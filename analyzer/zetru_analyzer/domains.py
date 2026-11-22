"""Domain names: normalisation (IDNA), Public Suffix List and registrable domains.

All domains inside the analyzer are handled in their ASCII (A-label, lowercase) form. The Unicode form is
derived only where look-alike checks need it.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
BUNDLED_PSL = os.path.join(os.path.dirname(__file__), "data", "public_suffix_list.dat")


def _label_to_ascii(label: str) -> str | None:
    if label.isascii():
        return label.lower()
    try:
        out = label.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        try:
            out = "xn--" + label.lower().encode("punycode").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    return out


def normalize_domain(value: str | None) -> str | None:
    """Returns the lowercase ASCII form of a host name, or None if it is not a plausible DNS name.

    IP literals are not domains (see `is_ip_literal`)."""
    if not value or not isinstance(value, str):
        return None
    host = value.strip().translate(_ZERO_WIDTH)
    host = host.replace("。", ".").replace("．", ".").replace("｡", ".")
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 * 4:
        return None
    labels = host.split(".")
    out = []
    for label in labels:
        if not label:
            return None
        ascii_label = _label_to_ascii(label)
        if ascii_label is None or not _LABEL_RE.match(ascii_label):
            return None
        out.append(ascii_label)
    result = ".".join(out)
    if len(result) > 253:
        return None
    return result


def to_unicode(domain: str) -> str:
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Integer, octal or hex dotted forms that browsers accept as IPv4 (e.g. 0x7f.1, 3232235777).
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", h.lower()))


@dataclass(frozen=True)
class PublicSuffixList:
    rules: frozenset
    wildcards: frozenset
    exceptions: frozenset
    version: str

    @classmethod
    def parse(cls, text: str, version: str = "bundled") -> "PublicSuffixList":
        rules, wildcards, exceptions = set(), set(), set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            line = line.split()[0]
            target = rules
            if line.startswith("!"):
                target, line = exceptions, line[1:]
            elif line.startswith("*."):
                target, line = wildcards, line[2:]
            ascii_rule = normalize_domain(line)
            if ascii_rule:
                target.add(ascii_rule)
        if len(rules) < 1000:
            raise ValueError("public suffix list too small")
        return cls(frozenset(rules), frozenset(wildcards), frozenset(exceptions), version)

    @classmethod
    def load(cls, path: str, version: str) -> "PublicSuffixList":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.parse(handle.read(), version)

    def public_suffix(self, domain: str) -> str:
        labels = domain.split(".")
        n = len(labels)
        # Exception rules win: the public suffix is the exception minus its leftmost label.
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                return ".".join(labels[i + 1:])
        # Otherwise the longest matching normal or wildcard rule; iterating from the left finds it first.
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self.rules:
                return candidate
            if i + 1 < n and ".".join(labels[i + 1:]) in self.wildcards:
                return candidate
        return labels[-1]  # implicit "*" rule

    def registrable_domain(self, domain: str | None) -> str | None:
        """Organisational (registrable) domain: public suffix plus one label; None for a bare suffix."""
        if not domain or is_ip_literal(domain):
            return None
        suffix = self.public_suffix(domain)
        if domain == suffix:
            return None
        rest = domain[: -(len(suffix) + 1)]
        return rest.split(".")[-1] + "." + suffix

    def registrable_label(self, domain: str) -> str | None:
        reg = self.registrable_domain(domain)
        if not reg:
            return None
        return reg.split(".")[0]

    def is_public_suffix(self, domain: str) -> bool:
        return self.public_suffix(domain) == domain


_DEFAULT: PublicSuffixList | None = None


def bundled_psl() -> PublicSuffixList:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = PublicSuffixList.load(BUNDLED_PSL, "bundled")
    return _DEFAULT


def load_psl(feeds_dir: str | None) -> PublicSuffixList:
    """PSL from the updater's feed volume if present and valid, else the copy shipped in the image."""
    from . import feedfiles

    if feeds_dir:
        info = feedfiles.read_current(feeds_dir, "psl")
        if info is not None:
            try:
                return PublicSuffixList.load(info.data_path, info.version)
            except (OSError, ValueError, UnicodeError):
                pass
    return bundled_psl()


def is_subdomain_or_equal(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)
