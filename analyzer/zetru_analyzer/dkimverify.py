"""DKIM re-verification (RFC 6376, RFC 8301, RFC 8463) for detection only (concept §6.3).

Results: `pass`, `fail` (cryptographic or body-hash mismatch) or `unverifiable` (no key, DNS error,
revoked/rotated key, expired signature, rsa-sha1, RSA keys under 1024 bits, unsupported parameters).
Keys are fetched by the caller (the supervisor brokers DNS); this module is pure.

A signature covers the bottom-most instances of the header fields it lists (RFC 6376 §5.4.2). When the
message has more instances of a signed field that the reader is shown (From, Sender, Reply-To, Subject, To,
Cc) than `h=` lists, the top-most, displayed instance is unsigned; a passing signature is then reported as
`unverifiable` (reason `unsigned_instances`, RFC 6376 §8.15; security review PY-13).
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from . import rawmail
from .domains import normalize_domain

MAX_SIGNATURES_PARSED = 10
DISPLAYED_FIELDS = ("from", "sender", "reply-to", "subject", "to", "cc")
_WSP_RUN = re.compile(rb"[ \t]+")
_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


@dataclass
class Signature:
    index: int                    # position among DKIM-Signature headers (0 = topmost)
    header: rawmail.RawHeader
    tags: dict[str, str]
    d: str
    s: str
    a: str
    header_canon: str
    body_canon: str
    h: list[str]
    bh: bytes
    b: bytes
    l: int | None
    t: int | None
    x: int | None
    i: str | None

    @property
    def key_name(self) -> str:
        return f"{self.s}._domainkey.{self.d}"


@dataclass
class SigResult:
    d: str
    s: str
    result: str                   # pass | fail | unverifiable
    reason: str
    body_hash_ok: bool | None = None
    l_partial: bool = False
    t: int | None = None
    signed_headers: list[str] = field(default_factory=list)


def parse_tag_list(value: str) -> dict[str, str] | None:
    tags: dict[str, str] = {}
    for item in value.split(";"):
        if not item.strip():
            continue
        if "=" not in item:
            return None
        name, val = item.split("=", 1)
        name = name.strip()
        if not _TAG_NAME.fullmatch(name) or name in tags:
            return None
        tags[name] = val.strip()
    return tags


def _b64(value: str) -> bytes:
    cleaned = re.sub(r"\s+", "", value)
    return base64.b64decode(cleaned, validate=True)


def parse_signatures(headers: list[rawmail.RawHeader]) -> list[Signature]:
    out: list[Signature] = []
    for index, header in enumerate(rawmail.find_all(headers, "dkim-signature")[:MAX_SIGNATURES_PARSED]):
        tags = parse_tag_list(header.value())
        if not tags or tags.get("v") != "1":
            continue
        try:
            d = normalize_domain(tags["d"])
            s = re.sub(r"\s+", "", tags["s"]).lower()
            if not d or not s or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", s) or len(s) > 63:
                continue
            canon = tags.get("c", "simple/simple").lower().replace(" ", "")
            header_canon, _, body_canon = canon.partition("/")
            body_canon = body_canon or "simple"
            if header_canon not in ("simple", "relaxed") or body_canon not in ("simple", "relaxed"):
                continue
            h = [x.strip().lower() for x in re.sub(r"\s+", "", tags["h"]).split(":") if x.strip()]
            if "from" not in h:
                continue
            l_tag = int(tags["l"]) if "l" in tags else None
            t_tag = int(tags["t"]) if "t" in tags else None
            x_tag = int(tags["x"]) if "x" in tags else None
            out.append(Signature(index=index, header=header, tags=tags, d=d, s=s, a=tags["a"].strip().lower(),
                                 header_canon=header_canon, body_canon=body_canon, h=h, bh=_b64(tags["bh"]),
                                 b=_b64(tags["b"]), l=l_tag, t=t_tag, x=x_tag, i=tags.get("i")))
        except (KeyError, ValueError, TypeError):
            continue
    return out


# Canonicalisation -----------------------------------------------------------------------------------

def canonical_body(body: bytes, method: str) -> bytes:
    if method == "relaxed":
        lines = body.split(b"\r\n")
        lines = [_WSP_RUN.sub(b" ", line).rstrip(b" \t") for line in lines]
        while lines and lines[-1] == b"":
            lines.pop()
        return b"" if not lines else b"\r\n".join(lines) + b"\r\n"
    # simple
    if not body:
        return b"\r\n"
    if not body.endswith(b"\r\n"):
        body += b"\r\n"
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]
    return body


def canonical_header(raw: bytes, method: str) -> bytes:
    if method == "simple":
        return raw
    name, _, value = raw.partition(b":")
    value = value.replace(b"\r\n", b"")
    value = _WSP_RUN.sub(b" ", value).strip(b" ")
    return name.strip(b" \t").lower() + b":" + value + b"\r\n"


def _strip_b_value(raw: bytes) -> bytes:
    """The DKIM-Signature field with the b= tag value removed (RFC 6376 §3.7)."""
    name, colon, value = raw.partition(b":")
    out = bytearray()
    pos = 0
    for m in re.finditer(rb"(^|;)([ \t\r\n]*b[ \t\r\n]*=)([^;]*)", value):
        out += value[pos:m.end(2)]
        pos = m.end(3)
    out += value[pos:]
    return name + colon + bytes(out)


def unsigned_instances(headers: list[rawmail.RawHeader], signed: list[str]) -> bool:
    """True when a displayed field that `h=` lists occurs more often in the message than `h=` lists it."""
    for name in DISPLAYED_FIELDS:
        listed = signed.count(name)
        if listed and sum(1 for h in headers if h.lname == name) > listed:
            return True
    return False


def _select_headers(headers: list[rawmail.RawHeader], names: list[str], exclude: rawmail.RawHeader) -> list[bytes]:
    used: set[int] = set()
    selected: list[bytes] = []
    for name in names:
        for idx in range(len(headers) - 1, -1, -1):
            hdr = headers[idx]
            if idx in used or hdr is exclude or hdr.lname != name:
                continue
            used.add(idx)
            selected.append(hdr.raw)
            break
    return selected


# Keys ------------------------------------------------------------------------------------------------

@dataclass
class KeyRecord:
    k: str
    p: bytes
    hashes: list[str] | None
    services: list[str] | None
    flags: list[str]


def parse_key_record(txt: str) -> KeyRecord | None:
    tags = parse_tag_list(txt)
    if tags is None:
        return None
    if "v" in tags and tags["v"] != "DKIM1":
        return None
    if "p" not in tags:
        return None
    try:
        p = _b64(tags["p"]) if tags["p"].strip() else b""
    except ValueError:
        return None
    hashes_tag = tags.get("h")
    services = tags.get("s")
    return KeyRecord(
        k=tags.get("k", "rsa").strip().lower(), p=p,
        hashes=[x.strip().lower() for x in hashes_tag.split(":")] if hashes_tag else None,
        services=[x.strip().lower() for x in services.split(":")] if services else None,
        flags=[x.strip().lower() for x in tags.get("t", "").split(":") if x.strip()],
    )


def verify(sig: Signature, headers: list[rawmail.RawHeader], body: bytes, txt_records: list[str] | None,
           dns_status: str, now: int | None = None) -> SigResult:
    """`txt_records`/`dns_status` come from the brokered TXT lookup of `sig.key_name`."""
    res = SigResult(d=sig.d, s=sig.s, result="unverifiable", reason="", t=sig.t, signed_headers=list(sig.h))
    now = int(time.time()) if now is None else now
    if sig.a not in ("rsa-sha256", "ed25519-sha256"):
        res.reason = "algorithm"
        return res
    if sig.x is not None and sig.x < now:
        res.reason = "expired"
        return res
    if sig.i is not None:
        i_domain = normalize_domain(sig.i.rpartition("@")[2])
        if not i_domain or not (i_domain == sig.d or i_domain.endswith("." + sig.d)):
            res.result, res.reason = "fail", "identity"
            return res
    # Body hash first: it does not need the key.
    canon = canonical_body(body, sig.body_canon)
    if sig.l is not None:
        if sig.l > len(canon):
            res.result, res.reason, res.body_hash_ok = "fail", "length", False
            return res
        res.l_partial = sig.l < len(canon)
        canon = canon[: sig.l]
    res.body_hash_ok = hashlib.sha256(canon).digest() == sig.bh
    if dns_status != "ok" or not txt_records:
        res.reason = "no_key" if dns_status in ("nxdomain", "nodata") else "dns"
        return res
    key = None
    for txt in txt_records:
        key = parse_key_record(txt)
        if key is not None:
            break
    if key is None or not key.p:
        res.reason = "no_key"
        return res
    if key.hashes is not None and "sha256" not in key.hashes:
        res.reason = "key_hash"
        return res
    if key.services is not None and not ({"*", "email"} & set(key.services)):
        res.reason = "key_service"
        return res
    if "s" in key.flags and sig.i is not None and normalize_domain(sig.i.rpartition("@")[2]) != sig.d:
        res.result, res.reason = "fail", "strict"
        return res
    if not res.body_hash_ok:
        res.result, res.reason = "fail", "body_hash"
        return res
    data = b"".join(canonical_header(raw, sig.header_canon) for raw in _select_headers(headers, sig.h, sig.header))
    sig_field = canonical_header(_strip_b_value(sig.header.raw), sig.header_canon)
    if sig_field.endswith(b"\r\n"):
        sig_field = sig_field[:-2]
    data += sig_field
    try:
        if sig.a == "rsa-sha256":
            if key.k != "rsa":
                res.reason = "key_type"
                return res
            public = serialization.load_der_public_key(key.p)
            if not isinstance(public, rsa.RSAPublicKey):
                res.reason = "key_type"
                return res
            if public.key_size < 1024:
                res.reason = "weak_key"
                return res
            public.verify(sig.b, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            if key.k != "ed25519" or len(key.p) != 32:
                res.reason = "key_type"
                return res
            ed25519.Ed25519PublicKey.from_public_bytes(key.p).verify(sig.b, hashlib.sha256(data).digest())
    except InvalidSignature:
        res.result, res.reason = "fail", "signature"
        return res
    except (ValueError, TypeError):
        res.reason = "key_format"
        return res
    if unsigned_instances(headers, sig.h):
        res.reason = "unsigned_instances"
        return res
    res.result, res.reason = "pass", ""
    return res
