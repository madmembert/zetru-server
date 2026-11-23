"""Byte-exact header access for the raw message (needed for DKIM and header-position rules)."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_HEADERS = 2000
_BARE_LF = re.compile(rb"(?<!\r)\n")
_HEADER_NAME = re.compile(rb"[\x21-\x39\x3b-\x7e]+")


@dataclass(frozen=True)
class RawHeader:
    name: str          # as written
    lname: str         # lowercase
    raw: bytes         # complete field including continuation lines and the final CRLF

    @property
    def value_bytes(self) -> bytes:
        """Unfolded value without the field name, leading whitespace and trailing CRLF."""
        value = self.raw.split(b":", 1)[1]
        value = value.replace(b"\r\n", b"")
        return value.strip(b" \t")

    def value(self) -> str:
        return self.value_bytes.decode("utf-8", errors="replace")


def normalize_newlines(raw: bytes) -> bytes:
    """Wire format uses CRLF; mails stored with bare LF are converted (as DKIM verifiers commonly do)."""
    if b"\n" not in raw:
        return raw
    return _BARE_LF.sub(b"\r\n", raw)


def split_message(raw: bytes) -> tuple[list[RawHeader], bytes, int]:
    """Returns (headers in order, body bytes, malformed header line count). Input must use CRLF."""
    headers: list[RawHeader] = []
    malformed = 0
    pos = 0
    if raw.startswith(b"From "):  # mbox separator line
        nl = raw.find(b"\r\n")
        pos = len(raw) if nl < 0 else nl + 2
    current_name: bytes | None = None
    current: list[bytes] = []
    length = len(raw)
    body_start = length
    while pos < length:
        nl = raw.find(b"\r\n", pos)
        line_end = length if nl < 0 else nl + 2
        line = raw[pos:line_end]
        if line in (b"\r\n", b""):
            body_start = line_end
            break
        if line[:1] in (b" ", b"\t"):
            if current_name is not None:
                current.append(line)
            else:
                malformed += 1
        else:
            if current_name is not None:
                _append(headers, current_name, current)
            colon = line.find(b":")
            name = line[:colon] if colon > 0 else b""
            if colon > 0 and _HEADER_NAME.fullmatch(name.rstrip(b" \t")):
                current_name = name.rstrip(b" \t")
                current = [line]
            else:
                malformed += 1
                current_name = None
                current = []
        pos = line_end
        if len(headers) >= MAX_HEADERS:
            malformed += 1
            body_start = length
            break
    else:
        body_start = length
    if current_name is not None and len(headers) < MAX_HEADERS:
        _append(headers, current_name, current)
    return headers, raw[body_start:], malformed


def _append(headers: list[RawHeader], name: bytes, lines: list[bytes]) -> None:
    raw = b"".join(lines)
    if not raw.endswith(b"\r\n"):
        raw += b"\r\n"
    text = name.decode("ascii", errors="replace")
    headers.append(RawHeader(text, text.lower(), raw))


def find_all(headers: list[RawHeader], lname: str) -> list[RawHeader]:
    return [h for h in headers if h.lname == lname]


def first(headers: list[RawHeader], lname: str) -> RawHeader | None:
    for h in headers:
        if h.lname == lname:
            return h
    return None
