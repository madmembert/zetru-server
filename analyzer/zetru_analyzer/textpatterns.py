"""Shared text patterns: phone numbers, amounts, IBANs, invisible characters, word obfuscation."""

from __future__ import annotations

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
_DATE = re.compile(r"^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$")
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


def find_phones(text: str, limit: int = 20) -> list[str]:
    iban_spans = [m.span() for m in IBAN.finditer(text)]
    out = []
    for m in PHONE.finditer(text):
        if any(a <= m.start() < b or a < m.end() <= b for a, b in iban_spans):
            continue
        candidate = m.group(0).strip()
        digits = re.sub(r"\D", "", candidate)
        if not 7 <= len(digits) <= 15 or _DATE.match(candidate):
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
