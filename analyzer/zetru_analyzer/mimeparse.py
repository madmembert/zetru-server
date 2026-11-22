"""MIME parsing with the standard-library `email` package (policy.default) and explicit limits.

Limits mirror ZetruKit's MIMEParser: nesting depth 24 and 1,000 parts. Part paths follow IMAP section
numbering (`1`, `2.1`, …) so evidence `part` values match what the app computes.
"""

from __future__ import annotations

import codecs
import email
import email.policy
import email.utils
from dataclasses import dataclass, field
from email.message import EmailMessage, Message

from . import rawmail
from .domains import normalize_domain

MAX_DEPTH = 24
MAX_PARTS = 1000
MAX_TEXT_CHARS_PER_PART = 2_000_000
MAX_TEXT_CHARS_TOTAL = 4_000_000


@dataclass
class Address:
    display: str
    local: str
    domain: str | None  # ASCII, lowercase; None if missing/invalid

    @property
    def addr(self) -> str:
        return f"{self.local}@{self.domain}" if self.domain else self.local


@dataclass
class Part:
    path: str
    content_type: str
    disposition: str | None
    filename: str | None
    payload: bytes
    in_attached_message: bool
    is_body_text: bool


@dataclass
class ParsedMail:
    raw: bytes                       # CRLF-normalised
    headers: list[rawmail.RawHeader]
    body_raw: bytes
    malformed_header_lines: int
    message: EmailMessage | None = None
    from_addrs: list[Address] = field(default_factory=list)
    from_header_count: int = 0
    reply_to: list[Address] = field(default_factory=list)
    to_cc: list[Address] = field(default_factory=list)
    delivered_to: str | None = None
    return_path: str | None = None   # address; "" for the null path; None if absent
    subject: str = ""
    plain_texts: list[str] = field(default_factory=list)
    html_texts: list[str] = field(default_factory=list)
    parts: list[Part] = field(default_factory=list)
    depth_exceeded: bool = False
    parts_exceeded: bool = False
    text_truncated: bool = False
    defects: int = 0

    @property
    def from_addr(self) -> Address | None:
        return self.from_addrs[0] if self.from_addrs else None

    @property
    def limits_exceeded(self) -> bool:
        return self.depth_exceeded or self.parts_exceeded

    def header_values(self, lname: str) -> list[str]:
        return [h.value() for h in rawmail.find_all(self.headers, lname)]

    def has_header(self, lname: str) -> bool:
        return rawmail.first(self.headers, lname) is not None


class ParseError(Exception):
    pass


def parse(raw_in: bytes) -> ParsedMail:
    raw = rawmail.normalize_newlines(raw_in)
    headers, body, malformed = rawmail.split_message(raw)
    mail = ParsedMail(raw=raw, headers=headers, body_raw=body, malformed_header_lines=malformed)
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:  # the stdlib parser is lenient; anything raised here is a hard failure
        raise ParseError(type(exc).__name__) from None
    mail.message = msg
    _addresses(mail, msg)
    mail.subject = _safe_header(msg, "subject")[:2000]
    state = {"parts": 0, "text_chars": 0}
    try:
        _walk(mail, msg, prefix="", depth=0, attached=False, state=state, top=True)
    except RecursionError:
        mail.depth_exceeded = True
    return mail


def _safe_header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
        return "" if value is None else str(value)
    except Exception:
        return ""


def _parse_addresses(msg: Message, name: str) -> list[Address]:
    out: list[Address] = []
    values = []
    try:
        values = msg.get_all(name) or []
    except Exception:
        values = []
    for value in values:
        try:
            addresses = getattr(value, "addresses", None)
            if addresses is not None:
                for a in addresses:
                    out.append(Address(str(a.display_name or ""), str(a.username or ""),
                                       normalize_domain(a.domain) if a.domain else None))
                continue
        except Exception:
            pass
        for display, addr in email.utils.getaddresses([str(value)]):
            local, _, domain = addr.rpartition("@")
            if not local:
                local, domain = addr, ""
            out.append(Address(display, local, normalize_domain(domain) if domain else None))
    return out


def _addresses(mail: ParsedMail, msg: Message) -> None:
    mail.from_header_count = len(rawmail.find_all(mail.headers, "from"))
    mail.from_addrs = _parse_addresses(msg, "from")
    mail.reply_to = _parse_addresses(msg, "reply-to")
    mail.to_cc = _parse_addresses(msg, "to") + _parse_addresses(msg, "cc")
    delivered = rawmail.first(mail.headers, "delivered-to")
    if delivered is not None:
        _, addr = email.utils.parseaddr(delivered.value())
        mail.delivered_to = addr.lower() or None
    rp = rawmail.first(mail.headers, "return-path")
    if rp is not None:
        value = rp.value().strip()
        if value in ("<>", ""):
            mail.return_path = ""
        else:
            _, addr = email.utils.parseaddr(value)
            mail.return_path = addr.lower()


def _charset_ok(name: str | None) -> str:
    if not name:
        return "utf-8"
    try:
        return codecs.lookup(name).name
    except LookupError:
        return "utf-8"


def decode_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
    charset = _charset_ok(part.get_content_charset())
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _filename(part: Message) -> str | None:
    try:
        name = part.get_filename()
    except Exception:
        name = None
    if not name:
        try:
            name = part.get_param("name")
            if isinstance(name, tuple):
                name = email.utils.collapse_rfc2231_value(name)
        except Exception:
            name = None
    return str(name)[:512] if name else None


def _disposition(part: Message) -> str | None:
    try:
        value = part.get_content_disposition()
    except Exception:
        return None
    return value.lower() if value else None


def _walk(mail: ParsedMail, part: Message, prefix: str, depth: int, attached: bool, state: dict, top: bool) -> None:
    if depth > MAX_DEPTH:
        mail.depth_exceeded = True
        return
    try:
        mail.defects += len(part.defects)
    except Exception:
        pass
    ctype = part.get_content_type()
    if ctype == "message/rfc822" or (part.is_multipart() and ctype.startswith("message/")):
        try:
            inner = part.get_payload(0)
        except Exception:
            inner = None
        if isinstance(inner, Message):
            # The embedded message's own body starts at <path>.1 (IMAP numbering).
            if inner.is_multipart():
                _children(mail, inner, prefix, depth + 1, True, state)
            else:
                _leaf(mail, inner, f"{prefix}.1" if prefix else "1", True, state)
        return
    if part.is_multipart():
        _children(mail, part, prefix, depth + 1, attached, state)
        return
    path = prefix if prefix else "1"
    _leaf(mail, part, path, attached, state)


def _children(mail: ParsedMail, part: Message, prefix: str, depth: int, attached: bool, state: dict) -> None:
    if depth > MAX_DEPTH:
        mail.depth_exceeded = True
        return
    try:
        children = part.get_payload()
    except Exception:
        return
    if not isinstance(children, list):
        return
    for index, child in enumerate(children, start=1):
        if state["parts"] >= MAX_PARTS:
            mail.parts_exceeded = True
            return
        if not isinstance(child, Message):
            continue
        path = f"{prefix}.{index}" if prefix else str(index)
        _walk(mail, child, path, depth, attached, state, top=False)


def _leaf(mail: ParsedMail, part: Message, path: str, attached: bool, state: dict) -> None:
    state["parts"] += 1
    if state["parts"] > MAX_PARTS:
        mail.parts_exceeded = True
        return
    ctype = part.get_content_type()
    disposition = _disposition(part)
    filename = _filename(part)
    is_text = ctype in ("text/plain", "text/html")
    body_text = is_text and not attached and disposition != "attachment" and not filename
    if body_text:
        text = decode_text(part)
        remaining = MAX_TEXT_CHARS_TOTAL - state["text_chars"]
        limit = min(MAX_TEXT_CHARS_PER_PART, max(0, remaining))
        if len(text) > limit:
            text = text[:limit]
            mail.text_truncated = True
        state["text_chars"] += len(text)
        (mail.html_texts if ctype == "text/html" else mail.plain_texts).append(text)
        payload = b""
    else:
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
    mail.parts.append(Part(path=path, content_type=ctype, disposition=disposition, filename=filename,
                           payload=payload, in_attached_message=attached, is_body_text=body_text))
