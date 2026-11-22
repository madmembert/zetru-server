"""Day-one `rules` backend (concept §9.4): transparent German/English pattern tier, `calibrated: false`.

Evidence per question: none (no group), weak (one group), moderate (two groups), strong (two groups in the
same or adjacent sentence plus a call to action — link, attachment, phone number, reply or payment
instruction — in that sentence or the one before/after). Probabilities: 0.05 / 0.35 / 0.65 / 0.90.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import yaml

from .. import CATEGORY_LABELS, RISK_LEVELS
from ..language import detect
from ..normalize import fold
from .base import Answer, Backend, abstain_answer

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
LEVEL_P = {"none": 0.05, "weak": 0.35, "moderate": 0.65, "strong": 0.90}
LEVEL_RANK = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
NOUL_QUESTIONS = ("asks_credentials", "asks_payment", "asks_bank_change", "urgency_pressure", "asks_secrecy",
                  "impersonates_brand_or_authority", "asks_callback", "asks_code_or_command", "extortion",
                  "shared_document_lure")
PSEUDO = ("scam", "spam")

PHONE = re.compile(
    r"(?<![\w+])(?:(?:\+|00)[1-9]\d{0,2}[\s./-]?(?:\(0\)[\s./-]?)?\(?\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}"
    r"|\(?0\d{1,5}\)?(?:[\s./-]?\d{1,5}){1,5}|(?:1[\s.-])?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4})(?![\w])")
DATE = re.compile(r"^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$")
IBAN = re.compile(r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?\b")
CRYPTO = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")
SECTIONS = ("FROM", "AUTH", "SUBJECT", "BODY-HEAD", "LINKS", "ATTACH", "OCR", "BODY-TAIL")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\s+/\s+|\n+")


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


def _compile(patterns) -> list[re.Pattern]:
    return [re.compile(p) for p in (patterns or [])]


def load_rules(path: str) -> LanguageRules:
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
    return LanguageRules(version=doc["version"], questions=questions, cta_link=_compile(cta["link"]),
                         cta_reply=_compile(cta["reply"]), cta_attachment=_compile(cta["attachment"]))


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
        m = re.match(r"^\[(FROM|AUTH|SUBJECT|BODY-HEAD|LINKS|ATTACH|OCR|BODY-TAIL)\]\s?(.*)$", line)
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
    for m in PHONE.finditer(text):
        if any(a <= m.start() < b for a, b in iban_spans):
            continue
        candidate = m.group(0).strip()
        digits = re.sub(r"\D", "", candidate)
        if 7 <= len(digits) <= 15 and not DATE.match(candidate):
            return True
    return False


class Evaluation:
    def __init__(self, rules: LanguageRules, parsed: ParsedState):
        self.rules = rules
        self.parsed = parsed
        raw_sentences = [parsed.display, parsed.subject]
        for block in (parsed.body_head, parsed.ocr, parsed.body_tail):
            raw_sentences.extend(s for s in _SENTENCE_SPLIT.split(block) if s.strip())
        self.raw = raw_sentences
        self.sentences = [fold(s) for s in raw_sentences]
        self.phone = [_phones(s) for s in raw_sentences]
        self.iban = [bool(IBAN.search(s)) for s in raw_sentences]
        self.crypto = [bool(CRYPTO.search(s)) for s in raw_sentences]
        self.cta = []
        for i, s in enumerate(self.sentences):
            hit = any(p.search(s) for p in rules.cta_link) or any(p.search(s) for p in rules.cta_reply)
            hit = hit or (parsed.has_attachment and any(p.search(s) for p in rules.cta_attachment))
            self.cta.append(hit or self.phone[i])

    def level(self, qid: str) -> str:
        spec = self.rules.questions[qid]
        n = len(self.sentences)
        suppressed = {i for i, s in enumerate(self.sentences) if any(p.search(s) for p in spec.suppress)}
        hits: dict[str, set[int]] = {}
        for group, patterns in spec.groups.items():
            if group == "phone":
                idx = {i for i in range(n) if self.phone[i]}
            else:
                idx = {i for i, s in enumerate(self.sentences) if any(p.search(s) for p in patterns)}
            idx -= suppressed
            if idx:
                hits[group] = idx
        if not hits:
            return "none"
        if len(hits) == 1:
            return "weak"
        extra = [any(p.search(s) for p in spec.extra_cta) or self.iban[i] and qid in ("asks_payment", "asks_bank_change")
                 or self.crypto[i] and qid in ("extortion", "asks_payment", "scam") for i, s in enumerate(self.sentences)]
        for i in range(n):
            window = {i, i + 1}
            if sum(1 for idx in hits.values() if idx & window) < 2:
                continue
            for j in range(max(0, i - 1), min(n, i + 3)):
                if (self.cta[j] or extra[j]) and j not in suppressed:
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

    def evaluate(self, state: str) -> tuple[str | None, str | None, dict[str, str], ParsedState]:
        parsed = parse_state(state)
        language, reason, _ = detect(parsed.text_for_language)
        if language is None:
            return None, reason, {}, parsed
        ev = Evaluation(self.languages[language], parsed)
        levels = {q: ev.level(q) for q in NOUL_QUESTIONS + PSEUDO}
        return language, None, levels, parsed

    def answer(self, state: str, questions: list[dict], language_hint: str | None) -> dict[str, Answer]:
        language, reason, levels, parsed = self.evaluate(state)
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
                out[qid] = Answer(id=qid, type="noul", backend=self.id, model_version=self.version, calibrated=False,
                                  p_yes=LEVEL_P[lvl], evidence_level=lvl)
            elif qid == "category":
                out[qid] = self._category(q, levels, parsed)
            else:
                out[qid] = self._risk(q, levels)
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
