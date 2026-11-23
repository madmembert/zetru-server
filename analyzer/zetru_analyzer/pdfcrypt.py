"""PDF standard security handler: does the document open without a user password?

Many legitimate PDFs (statements, invoices) are encrypted with an empty user password only to restrict
printing or copying; they open without a prompt and must not count as "password-protected" (concept
`ATT_ENCRYPTED`). Implements ISO 32000 algorithms 2/4/5 (R2–R4, RC4/MD5) and 2.A/2.B (R5/R6, SHA-2/AES).

Parsing is bounded (security review PY-05, PY-09): integers have at most 10 digits, the encryption dictionary is
looked for only in the first 8 definitions of the referenced object and within 16 KB after each, and at most 16
`/Encrypt` entries are examined. Every parsing step runs inside the error handler.
"""

from __future__ import annotations

import hashlib
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _compute_key(password: bytes, o: bytes, p: int, id0: bytes, r: int, length_bytes: int, encrypt_metadata: bool) -> bytes:
    h = hashlib.md5()
    h.update((password + PAD)[:32])
    h.update(o[:32])
    h.update((p & 0xFFFFFFFF).to_bytes(4, "little"))
    h.update(id0)
    if r >= 4 and not encrypt_metadata:
        h.update(b"\xff\xff\xff\xff")
    digest = h.digest()
    n = 5 if r == 2 else length_bytes
    if r >= 3:
        for _ in range(50):
            digest = hashlib.md5(digest[:n]).digest()
    return digest[:n]


def _user_password_ok_r2_r4(password: bytes, o: bytes, u: bytes, p: int, id0: bytes, r: int, length_bits: int,
                            encrypt_metadata: bool) -> bool:
    key = _compute_key(password, o, p, id0, r, max(5, min(16, length_bits // 8)), encrypt_metadata)
    if r == 2:
        return rc4(key, PAD) == u[:32]
    value = rc4(key, hashlib.md5(PAD + id0).digest())
    for i in range(1, 20):
        value = rc4(bytes(b ^ i for b in key), value)
    return value[:16] == u[:16]


def _hash_2b(password: bytes, salt: bytes, udata: bytes) -> bytes:
    k = hashlib.sha256(password + salt + udata).digest()
    i = 0
    e = b""
    while i < 64 or e[-1] > i - 32:
        k1 = (password + k + udata) * 64
        encryptor = Cipher(algorithms.AES(k[:16]), modes.CBC(k[16:32])).encryptor()
        e = encryptor.update(k1) + encryptor.finalize()
        remainder = int.from_bytes(e[:16], "big") % 3
        k = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[remainder](e).digest()
        i += 1
    return k[:32]


def _user_password_ok_r5_r6(password: bytes, u: bytes, r: int) -> bool:
    if len(u) < 48:
        return False
    validation_salt = u[32:40]
    if r == 5:
        return hashlib.sha256(password + validation_salt).digest() == u[:32]
    return _hash_2b(password, validation_salt, b"") == u[:32]


# Minimal object parsing -------------------------------------------------------------------------------

MAX_STRING_BYTES = 4096   # /O, /U and /ID strings are at most 48 bytes


def _parse_literal(data: bytes, start: int) -> tuple[bytes, int]:
    out = bytearray()
    depth = 1
    i = start + 1
    n = min(len(data), start + 1 + 4 * MAX_STRING_BYTES)
    while i < n and depth:
        c = data[i]
        if c == 0x5C and i + 1 < n:  # backslash
            nxt = data[i + 1]
            mapping = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12,
                       ord("("): 40, ord(")"): 41, ord("\\"): 92}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if 0x30 <= nxt <= 0x37:
                j = i + 1
                digits = b""
                while j < n and len(digits) < 3 and 0x30 <= data[j] <= 0x37:
                    digits += data[j:j + 1]
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            if nxt in (10, 13):
                i += 2
                if nxt == 13 and i < n and data[i] == 10:
                    i += 1
                continue
            out.append(nxt)
            i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
        out.append(c)
        i += 1
    return bytes(out), i + 1


def _parse_string_at(data: bytes, i: int) -> tuple[bytes | None, int]:
    while i < len(data) and data[i] in b" \t\r\n\x0c\x00":
        i += 1
    if i >= len(data):
        return None, i
    if data[i:i + 1] == b"(":
        return _parse_literal(data, i)
    if data[i:i + 1] == b"<" and data[i + 1:i + 2] != b"<":
        end = data.find(b">", i, i + 4 * MAX_STRING_BYTES)
        if end < 0:
            return None, i
        hexdigits = re.sub(rb"\s+", b"", data[i + 1:end])
        if len(hexdigits) % 2:
            hexdigits += b"0"
        try:
            return bytes.fromhex(hexdigits.decode("ascii")), end + 1
        except ValueError:
            return None, end + 1
    return None, i


def _dict_value(d: bytes, key: bytes) -> tuple[bytes | None, int]:
    m = re.search(rb"/" + key + rb"(?![A-Za-z0-9])", d)
    return (None, -1) if not m else (d, m.end())


MAX_ENCRYPT_REFS = 16
MAX_OBJECT_DEFS = 8
MAX_DICT_BYTES = 16 * 1024


def _get_int(d: bytes, key: bytes) -> int | None:
    m = re.search(rb"/" + key + rb"\s+(-?\d{1,10})(?!\d)", d)
    return int(m.group(1)) if m else None


def _get_string(d: bytes, key: bytes) -> bytes | None:
    _, pos = _dict_value(d, key)
    if pos < 0:
        return None
    value, _ = _parse_string_at(d, pos)
    return value


_DICT_END = re.compile(rb">>\s*endobj")


def _object_dict(data: bytes, num: bytes, gen: bytes) -> bytes | None:
    """Body of `<<…>>` of the first of at most 8 definitions of object `num gen` whose dictionary is followed by
    `endobj` within 16 KB (the former lazy regex rescanned the rest of the file for every candidate)."""
    header = re.compile(rb"(?<![0-9])" + num + rb"\s+" + gen + rb"\s+obj\s*<<")
    for count, m in enumerate(header.finditer(data)):
        if count >= MAX_OBJECT_DEFS:
            break
        end = _DICT_END.search(data, m.end(), m.end() + MAX_DICT_BYTES)
        if end:
            return data[m.end():end.start()]
    return None


def _encrypt_dict(data: bytes) -> bytes | None:
    tried: set[tuple[bytes, bytes]] = set()
    for count, m in enumerate(re.finditer(rb"/Encrypt\s*(?:(\d{1,10})\s+(\d{1,5})\s+R|<<)", data)):
        if count >= MAX_ENCRYPT_REFS:
            break
        if m.group(1) is not None:
            key = (m.group(1), m.group(2))
            if key in tried:
                continue
            tried.add(key)
            body = _object_dict(data, *key)
            if body is not None:
                return body
        else:
            end = data.find(b">>", m.end(), m.end() + MAX_DICT_BYTES)
            if end > 0:
                return data[m.end():end]
    return None


def _first_id(data: bytes) -> bytes | None:
    m = None
    for m in re.finditer(rb"/ID\s*\[", data):
        pass
    if m is None:
        return None
    value, _ = _parse_string_at(data, m.end())
    return value


def opens_without_password(data: bytes) -> bool | None:
    """True: opens without a user password; False: a user password (or certificate) is required;
    None: could not be determined."""
    try:
        enc = _encrypt_dict(data)
        if enc is None:
            return None
        if b"/Standard" not in enc:
            return False  # public-key (certificate) security: cannot be opened without the recipient's key
        r = _get_int(enc, b"R")
        p = _get_int(enc, b"P")
        o = _get_string(enc, b"O")
        u = _get_string(enc, b"U")
        if r is None or u is None:
            return None
        if r in (2, 3, 4):
            id0 = _first_id(data)
            if p is None or o is None or id0 is None:
                return None
            length = _get_int(enc, b"Length") or 40
            encrypt_metadata = not re.search(rb"/EncryptMetadata\s+false", enc)
            return _user_password_ok_r2_r4(b"", o, u, p, id0, r, length, encrypt_metadata)
        if r in (5, 6):
            return _user_password_ok_r5_r6(b"", u, r)
    except Exception:
        return None
    return None
