"""Campaign fingerprint: 64-bit SimHash over 3-word shingles of the normalised visible text plus the sorted
set of link registrable domains, split into four 16-bit bands (concept §6.5).

Normalisation: NFKC, case folding, word tokens (`\\w+`), digit runs replaced by `#`. Each shingle and each
link domain is one feature of weight 1, hashed with BLAKE2b-64. No text leaves the analyzer; the gateway
keys the bands with K_fp before storing anything.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

MIN_FEATURES = 3
MAX_TOKENS = 20_000
_WORD = re.compile(r"\w+")
_DIGITS = re.compile(r"\d+")


def tokens(text: str) -> list[str]:
    norm = unicodedata.normalize("NFKC", text).casefold()
    return [_DIGITS.sub("#", t) for t in _WORD.findall(norm)[:MAX_TOKENS]]


def features(text: str, link_domains: list[str]) -> list[str]:
    words = tokens(text)
    out = [" ".join(words[i:i + 3]) for i in range(len(words) - 2)]
    out.extend("@" + d for d in sorted(set(link_domains)))
    return out


def simhash64(feats: list[str]) -> int:
    weights = [0] * 64
    for feat in feats:
        h = int.from_bytes(hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if (h >> bit) & 1 else -1
    value = 0
    for bit in range(64):
        if weights[bit] > 0:
            value |= 1 << bit
    return value


def bands(text: str, link_domains: list[str]) -> list[str] | None:
    feats = features(text, link_domains)
    if len(feats) < MIN_FEATURES:
        return None
    value = simhash64(feats)
    return [f"{(value >> shift) & 0xFFFF:04x}" for shift in (48, 32, 16, 0)]
