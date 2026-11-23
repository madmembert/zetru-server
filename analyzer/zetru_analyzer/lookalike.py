"""Brand/authority look-alike detection (concept §6.4). The server has no contact data, so only the
brand reference set (b) is used; contact look-alikes are evaluated on the device."""

from __future__ import annotations

from dataclasses import dataclass

from .confusables import fold as skeleton
from .domains import PublicSuffixList, to_unicode
from .packs import Packs


@dataclass(frozen=True)
class LookalikeHit:
    brand: str
    ref_domain: str
    rule: int          # 1 skeleton, 2 edit distance, 3 same label other suffix, 4 brand token


def damerau_levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Optimal string alignment distance; returns `limit` + 1 once the distance exceeds `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            value = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                value = min(value, prev2[j - 2] + 1)
            cur[j] = value
            best = min(best, value)
        if best > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[len(b)]


def _contains_sequence(tokens: list[str], seq: tuple[str, ...]) -> bool:
    n = len(seq)
    return any(tuple(tokens[i:i + n]) == seq for i in range(len(tokens) - n + 1))


def brand_lookalike(host: str | None, psl: PublicSuffixList, packs: Packs) -> LookalikeHit | None:
    """`host` is a sender domain or link host (ASCII). Official, regional-member and bare-suffix hosts never
    match."""
    if not host:
        return None
    reg = psl.registrable_domain(host)
    if not reg:
        return None
    if packs.official_brand(host, reg) is not None:
        return None
    reg_u = to_unicode(reg)
    label_ascii = reg.split(".")[0]
    label_u = reg_u.split(".")[0]
    suffix = reg[len(label_ascii) + 1:]
    exempt = {b.key for b in packs.brands if b.is_regional_member(reg)}

    # Rule 1: same skeleton as an official domain.
    hit = packs.skeleton_index.get(skeleton(reg_u))
    if hit is not None and hit[0].key not in exempt and hit[1] != reg:
        return LookalikeHit(hit[0].key, hit[1], 1)

    # Rules 2-4 compare UTS #39 skeletons, so digit and homoglyph substitutions ("paypa1") do not evade them.
    host_part = host[: -(len(suffix) + 1)] if host.endswith("." + suffix) else host
    host_tokens = [skeleton(to_unicode(t)) for t in host_part.replace(".", "-").split("-") if t]
    label_skel = skeleton(label_u)
    for brand, label, brand_skel, token_skels in packs.label_index:
        if brand.key in exempt:
            continue
        ref = next((d for d in brand.official if d.split(".")[0] == label), brand.official[0] if brand.official else label)
        # Rule 3: same registrable label under a different public suffix.
        if label_ascii == label or label_skel == brand_skel:
            return LookalikeHit(brand.key, ref, 3)
        # Rule 4: brand label as a whole hyphen/dot token sequence of the host.
        if brand.token_rule and _contains_sequence(host_tokens, token_skels):
            return LookalikeHit(brand.key, ref, 4)
        # Rule 2: Damerau-Levenshtein distance between registrable labels.
        n = len(label)
        if n >= 5:
            allowed = 1 if n <= 11 else 2
            distance = damerau_levenshtein(label_skel, brand_skel, allowed)
            if 1 <= distance <= allowed:
                return LookalikeHit(brand.key, ref, 2)
    return None
