"""Curated rule packs shipped with the analyzer (brands/authorities, freemail, UGC hosting, shorteners,
redirectors, ESP click trackers, dangerous extensions)."""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass

from .confusables import fold as skeleton_fold
from .confusables import skeleton
from .domains import is_subdomain_or_equal, normalize_domain, to_unicode

PACK_DIR = os.path.join(os.path.dirname(__file__), "packs")


def fold_ci(text: str) -> str:
    """Case-insensitive comparison form: NFKC, case folding, UTS #39 skeleton."""
    return skeleton_fold(unicodedata.normalize("NFKC", text))


def fold_cs(text: str) -> str:
    return skeleton(unicodedata.normalize("NFKC", text))


def _token_regex(tokens: list[str], fold) -> re.Pattern | None:
    folded = sorted({fold(t) for t in tokens if t.strip()}, key=len, reverse=True)
    if not folded:
        return None
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t in folded) + r")(?!\w)")


@dataclass(frozen=True)
class Brand:
    key: str
    name: str
    authority: bool
    sending: tuple[str, ...]
    link: tuple[str, ...]
    labels: tuple[str, ...]
    token_rule: bool
    token_re: re.Pattern | None
    token_cs_re: re.Pattern | None
    prefix_tokens: tuple[str, ...]
    regional_re: re.Pattern | None
    regional_tlds: tuple[str, ...]
    authority_suffixes: tuple[str, ...]

    @property
    def official(self) -> tuple[str, ...]:
        return self.sending + self.link

    def is_regional_member(self, reg_domain: str | None) -> bool:
        if not reg_domain or self.regional_re is None:
            return False
        label, _, suffix = reg_domain.partition(".")
        return suffix in self.regional_tlds and bool(self.regional_re.match(label))

    def is_official_sender(self, domain: str | None, reg_domain: str | None) -> bool:
        if not domain:
            return False
        if any(is_subdomain_or_equal(domain, d) for d in self.sending):
            return True
        if self.authority and any(is_subdomain_or_equal(domain, s) for s in self.authority_suffixes):
            return True
        return self.is_regional_member(reg_domain)

    def is_official_any(self, host: str, reg_domain: str | None) -> bool:
        if any(is_subdomain_or_equal(host, d) for d in self.official):
            return True
        if self.authority and any(is_subdomain_or_equal(host, s) for s in self.authority_suffixes):
            return True
        return self.is_regional_member(reg_domain)

    def mentioned_in(self, folded_ci: str, folded_cs: str) -> bool:
        if self.token_re is not None and self.token_re.search(folded_ci):
            return True
        return self.token_cs_re is not None and bool(self.token_cs_re.search(folded_cs))


class Packs:
    def __init__(self, pack_dir: str = PACK_DIR):
        def load(name: str) -> dict:
            with open(os.path.join(pack_dir, name), "r", encoding="utf-8") as handle:
                return json.load(handle)

        brands_doc = load("brands-de-en.json")
        suffix_groups = brands_doc.get("authority_suffixes", {})
        self.brands: list[Brand] = []
        for entry in brands_doc["brands"]:
            groups = entry.get("authority_suffix_groups", [])
            suffixes = tuple(s for g in groups for s in suffix_groups.get(g, []))
            regional = entry.get("regional")
            tokens = list(entry.get("tokens", []))
            self.brands.append(Brand(
                key=entry["key"], name=entry["name"], authority=bool(entry.get("authority")),
                sending=tuple(self._domains(entry.get("sending_domains", []))),
                link=tuple(self._domains(entry.get("link_domains", []))),
                labels=tuple(entry.get("labels", [])),
                token_rule=bool(entry.get("token_rule")),
                token_re=_token_regex(tokens, fold_ci),
                token_cs_re=_token_regex(list(entry.get("tokens_cs", [])), fold_cs),
                prefix_tokens=tuple(fold_ci(t) for t in tokens if len(t) >= 5 and " " not in t and t.isalnum()),
                regional_re=re.compile(regional["pattern"]) if regional else None,
                regional_tlds=tuple(regional.get("tlds", [])) if regional else (),
                authority_suffixes=suffixes,
            ))
        self.freemail = frozenset(self._domains(load("freemail.json")["domains"]))
        self.ugc_hosts = tuple(self._domains(load("ugc-hosting.json")["hosts"]))
        self.shorteners = frozenset(self._domains(load("shorteners.json")["hosts"]))
        self.redirectors = load("redirectors.json")["rules"]
        self.esp_trackers = tuple(self._domains(load("esp-click-trackers.json")["hosts"]))
        ext = load("dangerous-extensions.json")
        self.ext_executable = frozenset(ext["executable"])
        self.ext_macro = frozenset(ext["macro_office"])
        self.ext_archive = frozenset(ext["archive"])
        self.ext_html = frozenset(ext["html"])
        self.ext_document = frozenset(ext["document"])
        # Look-alike indexes.
        self.skeleton_index: dict[str, tuple[Brand, str]] = {}
        # (brand, label, skeleton(label), skeletons of the label's hyphen tokens)
        self.label_index: list[tuple[Brand, str, str, tuple[str, ...]]] = []
        for brand in self.brands:
            for domain in brand.official:
                self.skeleton_index.setdefault(skeleton_fold(to_unicode(domain)), (brand, domain))
            for label in brand.labels:
                self.label_index.append((brand, label, skeleton_fold(label),
                                         tuple(skeleton_fold(t) for t in label.split("-"))))
        self.all_official = tuple(sorted({d for b in self.brands for d in b.official}))
        self._official_cache: dict[tuple[str, str | None], Brand | None] = {}

    @staticmethod
    def _domains(values) -> list[str]:
        out = []
        for value in values:
            d = normalize_domain(value)
            if d:
                out.append(d)
        return out

    # Lookups -------------------------------------------------------------------------------------------
    def brand(self, key: str) -> Brand | None:
        for b in self.brands:
            if b.key == key:
                return b
        return None

    def is_freemail(self, domain: str | None) -> bool:
        return bool(domain) and domain in self.freemail

    def is_ugc(self, host: str | None) -> bool:
        return bool(host) and any(is_subdomain_or_equal(host, h) for h in self.ugc_hosts)

    def is_shortener(self, host: str | None) -> bool:
        if not host:
            return False
        return host in self.shorteners or (host.startswith("www.") and host[4:] in self.shorteners)

    def is_esp_tracker(self, host: str | None) -> bool:
        return bool(host) and any(is_subdomain_or_equal(host, h) for h in self.esp_trackers)

    def official_brand(self, host: str, reg_domain: str | None) -> Brand | None:
        key = (host, reg_domain)
        if key in self._official_cache:
            return self._official_cache[key]
        found = next((brand for brand in self.brands if brand.is_official_any(host, reg_domain)), None)
        if len(self._official_cache) < 20_000:   # a mail has at most a few thousand hosts (pipeline limits)
            self._official_cache[key] = found
        return found

    def brands_mentioned(self, text: str, local_part: str = "") -> list[Brand]:
        """Brands whose display tokens appear in `text` (e.g. a display name) or in an address local part."""
        folded_ci = fold_ci(text)
        folded_cs = fold_cs(text)
        local_words = fold_ci(re.sub(r"[._+\-]+", " ", local_part)) if local_part else ""
        local_compact = fold_ci(re.sub(r"[^0-9A-Za-z]", "", local_part)) if local_part else ""
        out = []
        for brand in self.brands:
            if brand.mentioned_in(folded_ci, folded_cs):
                out.append(brand)
            elif local_part and brand.token_re is not None and brand.token_re.search(local_words):
                out.append(brand)
            elif local_compact and any(local_compact.startswith(t) for t in brand.prefix_tokens):
                out.append(brand)
        return out


_PACKS: Packs | None = None


def default_packs() -> Packs:
    global _PACKS
    if _PACKS is None:
        _PACKS = Packs()
    return _PACKS
