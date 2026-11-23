"""Day-one `rules` backend (concept §9.4): transparent German/English pattern tier, `calibrated: false`.

Evidence per question: none (no group), weak (one group), moderate (two groups), strong (two groups in the
same or adjacent sentence plus a call to action — link, attachment, phone number, reply or payment
instruction — in that sentence or the one before/after). Probabilities: 0.05 / 0.35 / 0.65 / 0.90.

Hardening (security review PY-04, PY-16; DECISIONS.md):
- every pattern of a rule pack is timed against adversarial inputs when the pack is loaded; a pattern that is
  super-linear makes loading fail (the service does not start with a pack an attacker could stall);
- tokens are clipped to 100 characters and a state contributes at most 800 sentences; evaluation stops at the
  router's deadline (`DeadlineExceeded`);
- a `suppress` pattern cancels only the group or call-to-action matches it overlaps, not its whole sentence,
  so words a sender adds next to a request ("(newsletter)") cannot switch the request off;
- text that is too diluted for language identification is still evaluated against the language of its
  longest German/English stretch; only strong findings are reported then, everything else abstains.
"""

from __future__ import annotations

import bisect
import os
import re
import time
from dataclasses import dataclass

import yaml

from .. import CATEGORY_LABELS, RISK_LEVELS
from ..language import detect, detect_window
from ..normalize import fold
from .base import Answer, Backend, DeadlineExceeded, abstain_answer

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
LEVEL_P = {"none": 0.05, "weak": 0.35, "moderate": 0.65, "strong": 0.90}
LEVEL_RANK = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
NOUL_QUESTIONS = ("asks_credentials", "asks_payment", "asks_bank_change", "urgency_pressure", "asks_secrecy",
                  "impersonates_brand_or_authority", "asks_callback", "asks_code_or_command", "extortion",
                  "shared_document_lure")
PSEUDO = ("scam", "spam")
MAX_SENTENCES = 800
MAX_TOKEN_CHARS = 100
MAX_PHONE_CANDIDATES = 200

PHONE = re.compile(
    r"(?<![\w+])(?:(?:\+|00)[1-9]\d{0,2}[\s./-]?(?:\(0\)[\s./-]?)?\(?\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}"
    r"|\(?0\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}|(?:1[\s.-])?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4})(?![\w])")
DATE = re.compile(r"\d{1,4}[./-]\d{1,2}[./-]\d{1,4}")
IBAN = re.compile(r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?\b")
CRYPTO = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")
SECTIONS = ("FROM", "AUTH", "SUBJECT", "BODY-HEAD", "LINKS", "ATTACH", "OCR", "BODY-TAIL")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\s+/\s+|\n+")
_SECTION_LINE = re.compile(r"\[(FROM|AUTH|SUBJECT|BODY-HEAD|LINKS|ATTACH|OCR|BODY-TAIL)\]\s?(.*)", re.S)

# Pattern lint (PY-04): every pattern is searched in these strings when a pack is loaded. A linear pattern
# needs well under a millisecond for 2,000 characters; the quadratic amount pattern of rules-1.0.0 needed
# about 75 ms on a laptop (several times that on a Raspberry Pi).
LINT_LENGTH = 2000
LINT_LIMIT_S = 0.02
LINT_UNITS = ("1", "a", " ", "a ", "1 ", "1.", "1,", ". ", "-", "/", "a1", "€1", "$1", "aa.", "\n", "1/", "a-")


@dataclass
class QuestionRules:
    groups: dict[str, list[re.Pattern]]
    suppress: list[re.Pattern]
    extra_cta: list[re.Pattern]


@dataclass
class LanguageRules:
    version: str
    questions: dict[str, QuestionRules]
    cta_link: list[re.Pattern]
    cta_reply: list[re.Pattern]
    cta_attachment: list[re.Pattern]

    def all_patterns(self) -> list[re.Pattern]:
        out = list(self.cta_link) + list(self.cta_reply) + list(self.cta_attachment)
        for spec in self.questions.values():
            for patterns in spec.groups.values():
                out.extend(patterns)
            out.extend(spec.suppress)
            out.extend(spec.extra_cta)
        return out


def _compile(patterns) -> list[re.Pattern]:
    return [re.compile(p) for p in (patterns or [])]


def slow_patterns(patterns: list[re.Pattern], limit_s: float = LINT_LIMIT_S) -> list[str]:
    """Patterns whose search time on adversarial strings suggests super-linear behaviour."""
    inputs = [(unit * (LINT_LENGTH // len(unit) + 1))[:LINT_LENGTH] for unit in LINT_UNITS]
    offenders = []
    for pattern in patterns:
        for text in inputs:
            elapsed = _time_search(pattern, text)
            if elapsed > limit_s and _time_search(pattern, text) > limit_s:   # re-check: one GC pause is no finding
                offenders.append(pattern.pattern)
                break
    return offenders


def _time_search(pattern: re.Pattern, text: str) -> float:
    started = time.perf_counter()
    pattern.search(text)
    return time.perf_counter() - started


_LINTED: dict[tuple[str, float], None] = {}


def load_rules(path: str, lint: bool = True) -> LanguageRules:
    with open(path, "r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    questions = {}
    for qid, spec in doc["questions"].items():
        questions[qid] = QuestionRules(
            groups={g: _compile(p) for g, p in spec["groups"].items()},
            suppress=_compile(spec.get("suppress")),
            extra_cta=_compile(spec.get("extra_cta")),
        )
    cta = doc["cta"]
    rules = LanguageRules(version=doc["version"], questions=questions, cta_link=_compile(cta["link"]),
                          cta_reply=_compile(cta["reply"]), cta_attachment=_compile(cta["attachment"]))
    if lint:
        key = (os.path.realpath(path), os.path.getmtime(path))
        if key not in _LINTED:
            offenders = slow_patterns(rules.all_patterns())
            if offenders:
                raise ValueError(f"rule pack {os.path.basename(path)}: super-linear patterns: {offenders}")
            _LINTED[key] = None
    return rules


@dataclass
class ParsedState:
    display: str
    flags: list[str]
    subject: str
    body_head: str
    ocr: str
    body_tail: str
    has_attachment: bool
    has_links: bool

    @property
    def text_for_language(self) -> str:
        return " ".join((self.subject, self.body_head, self.ocr, self.body_tail)).replace("[LINK]", " ")


def parse_state(state: str) -> ParsedState:
    sections: dict[str, str] = {}
    current = "BODY-HEAD"
    for line in state.splitlines():
        m = _SECTION_LINE.fullmatch(line)
        if m:
            current = m.group(1)
            sections[current] = m.group(2)
        else:
            sections[current] = sections.get(current, "") + "\n" + line
    def clean(name: str) -> str:
        value = sections.get(name, "").strip()
        return "" if value == "-" else value
    display, flags = "", []
    from_line = sections.get("FROM", "")
    if from_line:
        parts = [p.strip() for p in from_line.split("|")]
        display = "" if not parts or parts[0] == "-" else parts[0]
        for part in parts[1:]:
            if part.startswith("flags:"):
                flags = [f.strip() for f in part[6:].split(",") if f.strip() and f.strip() != "-"]
    return ParsedState(display=display, flags=flags, subject=clean("SUBJECT"), body_head=clean("BODY-HEAD"),
                       ocr=clean("OCR"), body_tail=clean("BODY-TAIL"), has_attachment=bool(clean("ATTACH")),
                       has_links=bool(clean("LINKS")))


def _phones(text: str) -> bool:
    iban_spans = [m.span() for m in IBAN.finditer(text)]
    starts = [a for a, _ in iban_spans]
    for count, m in enumerate(PHONE.finditer(text)):
        if count >= MAX_PHONE_CANDIDATES:
            break
        k = bisect.bisect_right(starts, m.start()) - 1      # IBAN spans are sorted and disjoint
        if k >= 0 and m.start() < iban_spans[k][1]:
            continue
        candidate = m.group(0).strip()
        digits = re.sub(r"\D", "", candidate)
        if 7 <= len(digits) <= 15 and not DATE.fullmatch(candidate):
            return True
    return False


def _clip_long_tokens(text: str) -> str:
    words = text.split()
    if all(len(w) <= MAX_TOKEN_CHARS for w in words):
        return text
    return " ".join(w[:MAX_TOKEN_CHARS] for w in words)


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    a, b = span
    return any(sa < b and a < sb for sa, sb in spans)


def _unsuppressed_match(patterns: list[re.Pattern], text: str, suppressed: list[tuple[int, int]]) -> bool:
    """True if some match of `patterns` in `text` lies outside every suppressed span."""
    for pattern in patterns:
        for m in pattern.finditer(text):
            if not suppressed or not _overlaps(m.span(), suppressed):
                return True
    return False


def _marker_free(spans: list[tuple[int, int]], suppressed: list[tuple[int, int]]) -> bool:
    """A phone number/IBAN/wallet counts unless every occurrence found in the folded sentence lies inside a
    suppressed span (no occurrence found there: it counts)."""
    return not suppressed or not spans or any(not _overlaps(s, suppressed) for s in spans)


class Evaluation:
    def __init__(self, rules: LanguageRules, parsed: ParsedState, deadline: float | None = None):
        self.rules = rules
        self.parsed = parsed
        self.deadline = deadline
        raw_sentences = [parsed.display, parsed.subject]
        for block in (parsed.body_head, parsed.ocr, parsed.body_tail):
            raw_sentences.extend(s for s in _SENTENCE_SPLIT.split(block) if s.strip())
        raw_sentences = [_clip_long_tokens(s) for s in raw_sentences[:MAX_SENTENCES]]
        self.raw = raw_sentences
        self.sentences = [fold(s) for s in raw_sentences]
        self._check()
        self.phone = [_phones(s) for s in raw_sentences]
        self.iban = [bool(IBAN.search(s)) for s in raw_sentences]
        self.crypto = [bool(CRYPTO.search(s)) for s in raw_sentences]
        self._check()
        self.cta_patterns = rules.cta_link + rules.cta_reply + (rules.cta_attachment if parsed.has_attachment else [])
        self.cta = [any(p.search(s) for p in self.cta_patterns) for s in self.sentences]
        self._marker_spans: dict[tuple[str, int], list[tuple[int, int]]] = {}

    def _check(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise DeadlineExceeded()

    def _spans(self, kind: str, j: int) -> list[tuple[int, int]]:
        key = (kind, j)
        if key not in self._marker_spans:
            regex = {"phone": PHONE, "iban": IBAN, "crypto": CRYPTO}[kind]
            self._marker_spans[key] = [m.span() for m in regex.finditer(self.sentences[j])]
        return self._marker_spans[key]

    def level(self, qid: str) -> str:
        self._check()
        spec = self.rules.questions[qid]
        n = len(self.sentences)
        suppressed = [[m.span() for p in spec.suppress for m in p.finditer(s)] if spec.suppress else []
                      for s in self.sentences]
        hits: dict[str, set[int]] = {}
        for group, patterns in spec.groups.items():
            if group == "phone":
                idx = {i for i in range(n) if self.phone[i] and _marker_free(self._spans("phone", i), suppressed[i])}
            else:
                idx = {i for i, s in enumerate(self.sentences) if _unsuppressed_match(patterns, s, suppressed[i])}
            if idx:
                hits[group] = idx
        self._check()
        if not hits:
            return "none"
        if len(hits) == 1:
            return "weak"
        cta_cache: dict[int, bool] = {}

        def call_to_action(j: int) -> bool:
            if j not in cta_cache:
                sup = suppressed[j]
                s = self.sentences[j]
                hit = (self.cta[j] and (not sup or _unsuppressed_match(self.cta_patterns, s, sup))) \
                    or _unsuppressed_match(spec.extra_cta, s, sup) \
                    or (self.phone[j] and _marker_free(self._spans("phone", j), sup)) \
                    or (self.iban[j] and qid in ("asks_payment", "asks_bank_change")
                        and _marker_free(self._spans("iban", j), sup)) \
                    or (self.crypto[j] and qid in ("extortion", "asks_payment", "scam")
                        and _marker_free(self._spans("crypto", j), sup))
                cta_cache[j] = bool(hit)
            return cta_cache[j]

        for i in range(n):
            window = {i, i + 1}
            if sum(1 for idx in hits.values() if idx & window) < 2:
                continue
            for j in range(max(0, i - 1), min(n, i + 3)):
                if call_to_action(j):
                    return "strong"
        return "moderate"


class RulesBackend(Backend):
    id = "rules"
    calibrated = False
    licence_notice = None

    def __init__(self, rules_dir: str = RULES_DIR):
        self.languages = {
            "de": load_rules(os.path.join(rules_dir, "de.yaml")),
            "en": load_rules(os.path.join(rules_dir, "en.yaml")),
        }
        self.version = self.languages["de"].version

    def enabled(self) -> bool:
        return True

    def evaluate(self, state: str, deadline: float | None = None
                 ) -> tuple[str | None, str | None, dict[str, str], ParsedState, bool]:
        """(language, abstain reason, levels, parsed state, window_only). `window_only`: the text as a whole is
        not German or English, but a stretch of it is; only strong findings may then be reported."""
        parsed = parse_state(state)
        text = parsed.text_for_language
        language, reason, _ = detect(text)
        window_only = False
        if language is None and reason == "unsupported_language":
            language = detect_window(text)
            window_only = language is not None
        if language is None:
            return None, reason, {}, parsed, False
        ev = Evaluation(self.languages[language], parsed, deadline)
        levels = {q: ev.level(q) for q in NOUL_QUESTIONS + PSEUDO}
        return language, None, levels, parsed, window_only

    def answer(self, state: str, questions: list[dict], language_hint: str | None) -> dict[str, Answer]:
        return self._answer(state, questions, None)

    def answer_until(self, state: str, questions: list[dict], language_hint: str | None,
                     deadline: float) -> dict[str, Answer]:
        return self._answer(state, questions, deadline)

    def _answer(self, state: str, questions: list[dict], deadline: float | None) -> dict[str, Answer]:
        language, reason, levels, parsed, window_only = self.evaluate(state, deadline)
        out: dict[str, Answer] = {}
        for q in questions:
            qid = q["id"]
            if qid not in NOUL_QUESTIONS and qid not in ("category", "risk_score"):
                out[qid] = abstain_answer(q, self.id, self.version, "unsupported_question")
                continue
            if language is None:
                out[qid] = abstain_answer(q, self.id, self.version, reason or "unsupported_language")
                continue
            if qid in NOUL_QUESTIONS:
                lvl = levels[qid]
                answer = Answer(id=qid, type="noul", backend=self.id, model_version=self.version, calibrated=False,
                                p_yes=LEVEL_P[lvl], evidence_level=lvl)
                strong = lvl == "strong"
            elif qid == "category":
                answer = self._category(q, levels, parsed)
                strong = answer.evidence_level in ("phishing", "scam_fraud", "spam") \
                    and max(answer.probabilities.values()) >= LEVEL_P["strong"]
            else:
                answer = self._risk(q, levels)
                strong = answer.evidence_level == RISK_LEVELS[-1]
            if window_only and not strong:
                answer = abstain_answer(q, self.id, self.version, "unsupported_language")
            out[qid] = answer
        return out

    def _category(self, q: dict, levels: dict[str, str], parsed: ParsedState) -> Answer:
        bulk = "bulk" in parsed.flags
        label, p = "legit", 0.60
        if levels["asks_credentials"] == "strong" and LEVEL_RANK[levels["impersonates_brand_or_authority"]] >= 2:
            label, p = "phishing", LEVEL_P["strong"]
        elif levels["extortion"] == "strong" or levels["scam"] == "strong":
            label, p = "scam_fraud", LEVEL_P["strong"]
        elif bulk:
            label, p = "newsletter_bulk", LEVEL_P["strong"]
        elif levels["spam"] == "strong":
            label, p = "spam", LEVEL_P["strong"]
        elif levels["asks_credentials"] == "strong":
            label, p = "phishing", LEVEL_P["moderate"]
        elif levels["scam"] == "moderate":
            label, p = "scam_fraud", LEVEL_P["moderate"]
        rest = (1.0 - p) / (len(CATEGORY_LABELS) - 1)
        probabilities = {c: (p if c == label else rest) for c in CATEGORY_LABELS}
        return Answer(id=q["id"], type="choice", backend=self.id, model_version=self.version, calibrated=False,
                      probabilities=probabilities, evidence_level=label)

    def _risk(self, q: dict, levels: dict[str, str]) -> Answer:
        core = ("asks_credentials", "asks_payment", "asks_bank_change", "asks_code_or_command", "extortion", "scam")
        top = max(LEVEL_RANK[levels[k]] for k in core)
        severe = any(levels[k] == "strong" for k in ("asks_code_or_command", "extortion", "asks_bank_change", "scam"))
        phishing = levels["asks_credentials"] == "strong" and LEVEL_RANK[levels["impersonates_brand_or_authority"]] >= 2
        if severe or phishing:
            index = 3
        elif top >= 2:
            index = 2
        elif top == 1 or LEVEL_RANK[levels["urgency_pressure"]] >= 2 or LEVEL_RANK[levels["asks_secrecy"]] >= 2:
            index = 1
        else:
            index = 0
        table = ([0.75, 0.17, 0.06, 0.02], [0.15, 0.65, 0.15, 0.05], [0.05, 0.15, 0.65, 0.15], [0.02, 0.08, 0.20, 0.70])
        dist = table[index]
        return Answer(id=q["id"], type="score", backend=self.id, model_version=self.version, calibrated=False,
                      distribution=list(dist), expected=sum(i * p for i, p in enumerate(dist)),
                      evidence_level=RISK_LEVELS[index])


__all__ = ["RulesBackend", "DeadlineExceeded", "slow_patterns", "load_rules"]
