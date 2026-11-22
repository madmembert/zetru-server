"""Text normalisation for the rule tier: NFKC, invisible characters removed, case folding, homoglyph folding
(Cyrillic/Greek letters that look like Latin ones) and German umlaut folding (ä→ae, ö→oe, ü→ue, ß→ss), so
patterns written in ASCII match both spellings."""

from __future__ import annotations

import re
import unicodedata

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­͏᠎]")
_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ӏ": "l",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "У": "y", "Ѕ": "s", "І": "i", "Ј": "j",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
})
_UMLAUTS = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"})


def fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    text = text.translate(_HOMOGLYPHS).casefold().translate(_UMLAUTS)
    return re.sub(r"[ \t]+", " ", text)
