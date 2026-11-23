"""URL extraction, canonicalisation and offline unwrapping (concept §6.5, §11.3).

Canonical URL (input to `url_sha256`, must match the app):
  1. strip leading/trailing whitespace and C0 controls; remove TAB, CR and LF anywhere;
  2. scheme lowercased; only http and https are link URLs; a bare `www.` start gets `http://`;
  3. backslashes before the query become slashes; any run of slashes after `scheme:` starts the authority;
  4. userinfo kept verbatim; host percent-decoded, IDNA-encoded to lowercase A-labels; IPv4 in any
     numeric form rewritten as dotted decimal; IPv6 lowercased in brackets;
  5. default port (80 for http, 443 for https) removed, other ports kept; a port is valid only when it consists of
     ASCII digits 0-9 whose value (leading zeros ignored, at most 5 significant digits) is at most 65535;
  6. empty path becomes `/`; path and query kept byte-for-byte; the fragment is removed.
Input that is not valid Unicode text (a lone surrogate, which only Python strings can hold) is rejected.
URL hosts are never resolved and URLs are never fetched.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from .domains import PublicSuffixList, normalize_domain
from .packs import Packs

MAX_URL_LEN = 8192
_TEXT_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'\[\]{}|\\^`]+")
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_CONTROL = re.compile(r"[\t\r\n]")
_ASCII_DIGITS = re.compile(r"[0-9]+")


@dataclass
class Link:
    url: str
    host: str
    reg_domain: str | None
    url_sha256: str
    source: str            # html, text, qr, form, unwrapped
    anchor_text: str = ""
    hidden: bool = False
    is_ip: bool = False
    via: str | None = None  # redirector host for unwrapped links


def _parse_ipv4(host: str) -> str | None:
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4:
        return None
    numbers = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                numbers.append(int(p[2:] or "0", 16))
            elif len(p) > 1 and p.startswith("0"):
                numbers.append(int(p, 8))
            else:
                numbers.append(int(p, 10))
        except ValueError:
            return None
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    value = 0
    for n in numbers[:-1]:
        value = value * 256 + n
    value = value * 256 ** (5 - len(numbers)) + numbers[-1]
    return str(ipaddress.IPv4Address(value))


def format_ipv6(address: ipaddress.IPv6Address) -> str:
    """WHATWG/RFC 5952 serialisation, identical to the app's LinkCanonicalizer.formatIPv6: eight lowercase
    hex pieces, the first longest run of two or more zero pieces written as "::", never dotted IPv4.
    str(IPv6Address) is not used because it depends on the Python version (3.13+ prints IPv4-mapped
    addresses dotted), which would change url_sha256 between the test machine and the container."""
    pieces = [int.from_bytes(address.packed[i:i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len, i = -1, 0, 0
    while i < 8:
        if pieces[i] != 0:
            i += 1
            continue
        j = i
        while j < 8 and pieces[j] == 0:
            j += 1
        if j - i >= 2 and j - i > best_len:
            best_start, best_len = i, j - i
        i = j
    if best_start < 0:
        return ":".join(f"{p:x}" for p in pieces)
    head = ":".join(f"{p:x}" for p in pieces[:best_start])
    tail = ":".join(f"{p:x}" for p in pieces[best_start + best_len:])
    return f"{head}::{tail}"


def canonicalize(url: str) -> tuple[str, str, bool] | None:
    """Returns (canonical URL, host, host_is_ip) or None for non-http(s) or unparsable input."""
    if not url or len(url) > MAX_URL_LEN:
        return None
    try:
        url.encode("utf-8")
    except UnicodeEncodeError:   # lone surrogate (e.g. from a JSON QR payload): no canonical form exists
        return None
    s = _CONTROL.sub("", url.strip(" \x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13"
                                   "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f ​"))
    m = _SCHEME.match(s)
    if not m:
        if s.lower().startswith("www."):
            s = "http://" + s
            m = _SCHEME.match(s)
        else:
            return None
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        return None
    rest = s[m.end():]
    q = len(rest)
    for ch in "?#":
        i = rest.find(ch)
        if i >= 0:
            q = min(q, i)
    rest = rest[:q].replace("\\", "/") + rest[q:]
    rest = rest.lstrip("/")
    end = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i >= 0:
            end = min(end, i)
    authority, tail = rest[:end], rest[end:]
    userinfo = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        userinfo += "@"
    port = ""
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host_raw, after = authority[: close + 1], authority[close + 1:]
        if after.startswith(":"):
            port = after[1:]
        elif after:
            return None
    else:
        host_raw, _, port = authority.partition(":")
    if port:
        # Same rule as the app (LinkCanonicalizer.swift): ASCII digits only (str.isdigit also accepts "²" or
        # "٣", on which int() raises or which Swift rejects), leading zeros ignored, at most 5 significant
        # digits (int() refuses strings over 4,300 digits).
        if not _ASCII_DIGITS.fullmatch(port):
            return None
        significant = port.lstrip("0")
        if len(significant) > 5:
            return None
        value = int(significant or "0")
        if value > 65535:
            return None
        port = "" if (scheme == "http" and value == 80) or (scheme == "https" and value == 443) else str(value)
    host_raw = unquote(host_raw)
    is_ip = False
    if host_raw.startswith("["):
        inner = host_raw[1:-1]
        if "%" in inner:   # zone IDs are not valid in URLs (WHATWG); the app rejects them too
            return None
        try:
            host = "[" + format_ipv6(ipaddress.IPv6Address(inner)) + "]"
        except ValueError:
            return None
        is_ip = True
    else:
        ipv4 = _parse_ipv4(host_raw) if re.fullmatch(r"[0-9a-fA-Fx.]+", host_raw or "-") else None
        if ipv4:
            host, is_ip = ipv4, True
        else:
            host = normalize_domain(host_raw)
            if not host:
                return None
    fragment = tail.find("#")
    if fragment >= 0:
        tail = tail[:fragment]
    if not tail.startswith("/"):
        tail = "/" + tail
    canonical = f"{scheme}://{userinfo}{host}{':' + port if port else ''}{tail}"
    return canonical, host, is_ip


def url_sha256(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_from_text(text: str, limit: int = 500) -> list[str]:
    """At most `limit` URLs in text order (callers ask for one more to detect that the limit was hit)."""
    out = []
    for m in _TEXT_URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?'\"")
        while url.endswith(")") and url.count(")") > url.count("("):
            url = url[:-1]
        out.append(url)
        if len(out) >= limit:
            break
    return out


def _unwrap_once(canonical: str, host: str, packs: Packs) -> str | None:
    try:
        parts = urlsplit(canonical)
    except ValueError:
        return None
    for rule in packs.redirectors:
        rule_host = rule["host"]
        if rule_host.startswith("."):
            if not host.endswith(rule_host):
                continue
        elif host != rule_host:
            continue
        if not parts.path.startswith(rule.get("path", "/")):
            continue
        encoding = rule.get("encoding", "plain")
        if encoding == "urldefense-v3":
            # Same result as re.search(r"/v3/__(.+?)__;") but linear: the lazy group rescans the rest of the
            # URL from every "/v3/__" when no "__;" follows (PY-05).
            start = canonical.find("/v3/__")
            end = canonical.find("__;", start + 7) if start >= 0 else -1
            return canonical[start + 6:end] if end >= 0 else None
        if encoding == "query-is-url":
            return unquote(parts.query) if parts.query else None
        params = dict(parse_qsl(parts.query, keep_blank_values=False))
        for name in rule.get("params", []):
            value = params.get(name)
            if not value:
                continue
            if encoding == "proofpoint-v2":
                value = unquote(value.replace("-", "%").replace("_", "/"))
            return value
        return None
    return None


def unwrap(canonical: str, host: str, packs: Packs, depth: int = 3) -> tuple[str, str, bool] | None:
    """Follows known redirectors offline; returns the innermost canonical destination or None."""
    result = None
    current, current_host = canonical, host
    for _ in range(depth):
        target = _unwrap_once(current, current_host, packs)
        if not target:
            break
        parsed = canonicalize(target)
        if not parsed:
            break
        result = parsed
        current, current_host = parsed[0], parsed[1]
    return result


def make_link(raw_url: str, source: str, psl: PublicSuffixList, anchor_text: str = "", hidden: bool = False
              ) -> Link | None:
    parsed = canonicalize(raw_url)
    if not parsed:
        return None
    canonical, host, is_ip = parsed
    return Link(url=canonical, host=host, reg_domain=None if is_ip else psl.registrable_domain(host),
                url_sha256=url_sha256(canonical), source=source, anchor_text=anchor_text, hidden=hidden,
                is_ip=is_ip)


def domain_in_text(text: str) -> str | None:
    """A host name that link text displays (e.g. 'paypal.com/konto' or 'https://x.y'), if any."""
    m = re.search(r"(?i)(?:https?://)?((?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,63})(?=$|[/\s:?#])",
                  text.strip())
    if not m:
        return None
    return normalize_domain(m.group(1))
