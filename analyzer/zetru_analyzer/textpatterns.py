"""Shared text patterns: phone numbers, amounts, IBANs, invisible characters, word obfuscation."""

from __future__ import annotations

import bisect
import re
import unicodedata

from .confusables import fold

INVISIBLE = re.compile("[​‌‍‎‏‪-‮⁠-⁤⁦-⁩﻿­͏᠎]")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
PHONE = re.compile(
    r"(?<![\w+])(?:"
    r"(?:\+|00)[1-9]\d{0,2}[\s./-]?(?:\(0\)[\s./-]?)?\(?\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}"
    r"|\(?0\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}"
    r"|(?:1[\s.-])?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}"
    r")(?![\w])")
_DATE = re.compile(r"\d{1,4}[./-]\d{1,2}[./-]\d{1,4}")
AMOUNT = re.compile(
    r"(?i)(?:(?:€|eur|usd|us\$|\$|£|gbp|chf)\s?\d{1,3}(?:[.,\s]\d{3})*(?:[.,]\d{2})?"
    r"|\b\d{1,3}(?:[.,\s]\d{3})*(?:[.,]\d{2})?\s?(?:€|eur\b|euro\b|usd\b|\$|£|gbp\b|chf\b|dollars?\b))")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
                       "|": "l", "!": "i"})
SENSITIVE_WORDS = frozenset({
    "konto", "account", "passwort", "password", "kennwort", "bank", "verify", "verifizieren", "login", "anmelden",
    "sicherheit", "security", "rechnung", "invoice", "bitcoin", "paket", "parcel", "zahlung", "payment",
    "kreditkarte", "creditcard", "update", "support", "kundenservice", "verification", "verifizierung",
})


def strip_invisible(text: str) -> str:
    return INVISIBLE.sub("", text)


def normalize_visible(text: str) -> str:
    return unicodedata.normalize("NFKC", strip_invisible(text))


MAX_PHONE_CANDIDATES = 2000


def _inside_any(pos: int, starts: list[int], spans: list[tuple[int, int]], end_inclusive: bool) -> bool:
    """Whether `pos` lies in one of the sorted, disjoint `spans` ([a, b) or, with end_inclusive, (a, b])."""
    k = (bisect.bisect_left(starts, pos) if end_inclusive else bisect.bisect_right(starts, pos)) - 1
    if k < 0:
        return False
    a, b = spans[k]
    return a < pos <= b if end_inclusive else a <= pos < b


def find_phones(text: str, limit: int = 20) -> list[str]:
    """Phone numbers outside IBANs. IBAN spans are checked with a binary search (a scan over all spans per
    candidate was quadratic, PY-05); at most 2,000 candidates are examined."""
    iban_spans = [m.span() for m in IBAN.finditer(text)]
    starts = [a for a, _ in iban_spans]
    out = []
    for count, m in enumerate(PHONE.finditer(text)):
        if count >= MAX_PHONE_CANDIDATES:
            break
        if _inside_any(m.start(), starts, iban_spans, False) or _inside_any(m.end(), starts, iban_spans, True):
            continue
        candidate = m.group(0).strip()
        digits = re.sub(r"\D", "", candidate)
        if not 7 <= len(digits) <= 15 or _DATE.fullmatch(candidate):
            continue
        out.append(candidate)
        if len(out) >= limit:
            break
    return out


def has_amount(text: str) -> bool:
    return AMOUNT.search(text) is not None


def _scripts(word: str) -> set[str]:
    scripts = set()
    for ch in word:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0] if name else "?")
    return scripts


def _fold_word(word: str) -> str:
    return fold(word).translate(_LEET)


def obfuscated_words(text: str, extra_terms: frozenset[str], limit: int = 50) -> list[str]:
    """Words that, after removing invisible characters and undoing digit/homoglyph substitutions, spell a
    brand name or a sensitive term while being written differently. Returns the matched terms."""
    terms = SENSITIVE_WORDS | extra_terms
    hits = []
    for word in re.findall(r"[^\s.,;:?()\[\]<>\"'/\\]{4,40}", text):
        if "@" in word[1:-1] and re.search(r"@[a-z]{2,}", word, re.I):
            continue  # an address, not a word
        core = word.strip("!-_*")
        if len(core) < 4:
            continue
        invisible = bool(INVISIBLE.search(core))
        plain = strip_invisible(core)
        lowered = plain.casefold()
        mixed_digits = bool(re.search(r"[^\W\d_]", plain)) and bool(re.search(r"[0-9@$|]", plain))
        mixed_script = len(_scripts(plain)) > 1
        if not (invisible or mixed_digits or mixed_script):
            continue
        if lowered in terms:
            if invisible:
                hits.append(lowered)
            continue
        folded = _fold_word(plain)
        if folded in terms and folded != lowered:
            hits.append(folded)
        if len(hits) >= limit:
            break
    return hits
