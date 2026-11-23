"""UTS #39 skeletons from the bundled Unicode confusables data (Unicode License v3)."""

from __future__ import annotations

import os
import unicodedata

CONFUSABLES_PATH = os.path.join(os.path.dirname(__file__), "data", "confusables.txt")

# Default_Ignorable_Code_Point characters that matter in practice (zero-width, joiners, bidi controls,
# soft hyphen, variation selectors are handled by range below).
_IGNORABLE = set(map(ord, "­͏؜ᅟᅠ឴឵᠋᠌᠍᠎᠏"
                     "​‌‍‎‏‪‫‬‭‮⁠⁡⁢"
                     "⁣⁤⁦⁧⁨⁩⁪⁫⁬⁭⁮⁯ㅤ"
                     "﻿ﾠ"))
_IGNORABLE.update(range(0xFE00, 0xFE10))
_IGNORABLE.update(range(0xE0000, 0xE1000))

_TABLE: dict[str, str] | None = None


def _load() -> dict[str, str]:
    table: dict[str, str] = {}
    with open(CONFUSABLES_PATH, "r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = [f.strip() for f in line.split(";")]
            if len(fields) < 2:
                continue
            try:
                source = "".join(chr(int(cp, 16)) for cp in fields[0].split())
                target = "".join(chr(int(cp, 16)) for cp in fields[1].split())
            except ValueError:
                continue
            if len(source) == 1:
                table[source] = target
    return table


def table() -> dict[str, str]:
    global _TABLE
    if _TABLE is None:
        _TABLE = _load()
    return _TABLE


def is_ignorable(ch: str) -> bool:
    return ord(ch) in _IGNORABLE


def skeleton(text: str) -> str:
    """skeleton(X): NFD, drop default-ignorables, map each character to its prototype, NFD again."""
    mapping = table()
    decomposed = unicodedata.normalize("NFD", text)
    out = []
    for ch in decomposed:
        if ord(ch) in _IGNORABLE:
            continue
        out.append(mapping.get(ch, ch))
    return unicodedata.normalize("NFD", "".join(out))


def fold(text: str) -> str:
    """Case-insensitive skeleton: skeleton(casefold(skeleton(casefold(x)))). Prototypes may be upper case
    (digit zero maps to 'O'), so a second pass after case folding makes '0' and 'o' compare equal."""
    return skeleton(skeleton(text.casefold()).casefold())
