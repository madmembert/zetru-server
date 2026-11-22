"""Language identification for German and English by stop-word ratio (concept §9.4)."""

from __future__ import annotations

import re

from .normalize import fold

MIN_TOKENS = 20
MIN_RATIO = 0.08

DE = frozenset(fold(w) for w in """
der die das den dem des ein eine einer einen einem eines und oder aber auch als am an auf aus bei bis da damit
dann dass denn doch durch es für gegen hat haben hatte hier ich ihm ihn ihnen ihr ihre ihrem ihren ihrer im in
ist ja jetzt kann kein keine können mich mir mit muss müssen nach nicht noch nur ob ohne schon sehr sein seine
sich sie sind so soll sollen über um und uns unser unsere unter vom von vor war waren was weil wenn werden wie
wieder wir wird wurde wurden zu zum zur zwischen bitte danke vielen dank liebe lieber hallo geehrte geehrter
freundlichen grüßen gruß diese dieser dieses diesem diesen dich dir du euch heute morgen gibt alle allen etwas
""".split())

EN = frozenset("""
the be to of and a an in that have has had i it for not on with he as you do at this but his by from they we
her she or will my one all would there their what so up out if about who get which go me when make can like
time no just him know take into your yours good some could them see other than then now only come its over
also back after use how our work well way even new want because any these give day most us is are was were
been being dear please thanks thank regards hello hi kind best should must here there those am did does
""".split())

_TOKEN = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)?")


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(fold(text))


def detect(text: str) -> tuple[str | None, str | None, int]:
    """Returns (language, abstain reason, token count)."""
    toks = tokens(text)
    n = len(toks)
    if n < MIN_TOKENS:
        return None, "too_short", n
    de = sum(1 for t in toks if t in DE) / n
    en = sum(1 for t in toks if t in EN) / n
    if max(de, en) < MIN_RATIO:
        return None, "unsupported_language", n
    return ("de" if de >= en else "en"), None, n
