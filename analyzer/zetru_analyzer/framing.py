"""Request framing and validation for the internal endpoints (concept §11.2, server-internal-api.md)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct

DEFAULT_MAX_MAIL = 20_971_520
HARD_MAX_MAIL = 64 * 1024 * 1024
MAX_META = 65_536
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
KNOWN_BACKENDS = ("rules", "encoder", "llm", "openjev", "jev")


class BadRequest(Exception):
    pass


def parse_policy(header: str | None) -> dict:
    if not header:
        return {"backends": ["rules"], "max_mail_bytes": DEFAULT_MAX_MAIL}
    try:
        padded = header + "=" * (-len(header) % 4)
        doc = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        raise BadRequest("policy") from None
    if not isinstance(doc, dict):
        raise BadRequest("policy")
    backends = doc.get("backends", ["rules"])
    if not isinstance(backends, list) or not all(isinstance(b, str) and b in KNOWN_BACKENDS for b in backends):
        raise BadRequest("policy backends")
    max_mail = doc.get("max_mail_bytes", DEFAULT_MAX_MAIL)
    if isinstance(max_mail, bool) or not isinstance(max_mail, int) or not 1 <= max_mail <= HARD_MAX_MAIL:
        raise BadRequest("policy max_mail_bytes")
    return {"backends": list(dict.fromkeys(backends)), "max_mail_bytes": max_mail}


def valid_tenant(value: str | None) -> bool:
    return bool(value) and bool(_UUID.match(value))


def parse_analyze(body: bytes, max_mail: int) -> tuple[dict, bytes]:
    if len(body) < 6:
        raise BadRequest("framing")
    (n,) = struct.unpack(">I", body[:4])
    if not 1 <= n <= MAX_META or len(body) < 4 + n + 1:
        raise BadRequest("framing")
    try:
        meta = json.loads(body[4:4 + n].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BadRequest("meta json") from None
    raw = body[4 + n:]
    if not 1 <= len(raw) <= max_mail:
        raise BadRequest("mail size")
    meta = validate_meta(meta)
    if hashlib.sha256(raw).hexdigest() != meta["mail_sha256"]:
        raise BadRequest("mail hash")
    return meta, raw


def validate_meta(meta) -> dict:
    if not isinstance(meta, dict):
        raise BadRequest("meta")
    if meta.get("schema") != 1:
        raise BadRequest("schema")
    sha = meta.get("mail_sha256")
    if not isinstance(sha, str) or not _HEX64.match(sha):
        raise BadRequest("mail_sha256")
    ref = meta.get("account_ref")
    if not isinstance(ref, str) or not _HEX32.match(ref):
        raise BadRequest("account_ref")
    if meta.get("mode") not in ("auto", "confirm", "manual"):
        raise BadRequest("mode")
    if meta.get("locale") not in ("de", "en"):
        raise BadRequest("locale")
    catalog = meta.get("catalog_version")
    if isinstance(catalog, bool) or not isinstance(catalog, int) or catalog < 0:
        raise BadRequest("catalog_version")
    out = {"schema": 1, "mail_sha256": sha, "account_ref": ref, "mode": meta["mode"], "locale": meta["locale"],
           "catalog_version": catalog}
    received = meta.get("received_at")
    if received is not None:
        if isinstance(received, bool) or not isinstance(received, int) or not 0 < received < 2**40:
            raise BadRequest("received_at")
        out["received_at"] = received
    qr = meta.get("qr_payloads")
    if qr is not None:
        if not isinstance(qr, list) or len(qr) > 5 or not all(isinstance(x, str) and len(x) <= 2048 for x in qr):
            raise BadRequest("qr_payloads")
        out["qr_payloads"] = qr
    ocr = meta.get("ocr_text")
    if ocr is not None:
        if not isinstance(ocr, str) or len(ocr) > 4000:
            raise BadRequest("ocr_text")
        out["ocr_text"] = ocr
    return out


def parse_url_check(body: bytes) -> list[dict]:
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BadRequest("json") from None
    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not 1 <= len(items) <= 10:
        raise BadRequest("items")
    out = []
    for item in items:
        if not isinstance(item, dict):
            raise BadRequest("item")
        host, sha = item.get("host"), item.get("url_sha256")
        if not isinstance(host, str) or not 1 <= len(host) <= 253:
            raise BadRequest("host")
        if not isinstance(sha, str) or not _HEX64.match(sha):
            raise BadRequest("url_sha256")
        out.append({"host": host, "url_sha256": sha})
    return out
