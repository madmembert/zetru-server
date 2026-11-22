"""Rule tier: ≥ 30 positive and ≥ 30 negative snippets per question and language (concept §15, M6)."""

import itertools

import pytest

import corpus_de
import corpus_en
from zetru_inference import CANONICAL_QUESTIONS
from zetru_inference.backends.rules import NOUL_QUESTIONS, RulesBackend

CORPORA = {"de": corpus_de, "en": corpus_en}
THRESHOLD = 0.80
BACKEND = RulesBackend()
QUESTIONS = [{"id": q, "type": "choice" if q == "category" else "score" if q == "risk_score" else "noul",
              "instructions": "", "criteria": None} for q in CANONICAL_QUESTIONS]


def make_state(subject: str, body: str, display: str = "", attach: bool = False, flags=()) -> str:
    links = "Konto → example.org" if "[LINK]" in body else "-"
    return "\n".join([
        f"[FROM] {display or '-'} | example.org | flags: {', '.join(flags) or '-'}",
        "[AUTH] none",
        f"[SUBJECT] {subject}",
        f"[BODY-HEAD] {body}",
        f"[LINKS] {links}",
        f"[ATTACH] {'pdf' if attach else '-'}",
        "[OCR] -",
        "[BODY-TAIL] -",
    ])


def generated(corpus, pools):
    out = []
    for qid, (cores, ctas) in pools.items():
        for n, (core, cta) in enumerate(itertools.product(cores, ctas)):
            opener = corpus.OPENERS[n % len(corpus.OPENERS)]
            out.append((qid, f"{opener} {core} {cta}"))
    return out


def answers(state: str) -> dict:
    return BACKEND.answer(state, QUESTIONS, None)


def positive_cases():
    for lang, corpus in CORPORA.items():
        for i, (qid, body) in enumerate(generated(corpus, corpus.POOLS)):
            yield pytest.param(lang, qid, body, id=f"{lang}-{qid}-{i}")


def legit_cases():
    for lang, corpus in CORPORA.items():
        for i, case in enumerate(corpus.LEGIT):
            yield pytest.param(lang, case, id=f"{lang}-legit-{i}")


@pytest.mark.parametrize("lang,qid,body", list(positive_cases()))
def test_positive_snippet_is_strong(lang, qid, body):
    result = answers(make_state("Wichtige Mitteilung" if lang == "de" else "Important notice", body))
    answer = result[qid]
    assert answer.abstain is None, f"abstained: {answer.abstain}"
    assert BACKEND.evaluate(make_state("x", body))[0] == lang
    assert answer.p_yes >= THRESHOLD, f"{qid} level {answer.evidence_level}: {body}"


@pytest.mark.parametrize("lang,case", list(legit_cases()))
def test_legit_mail_raises_no_signal(lang, case):
    state = make_state(case["subject"], case["body"], case.get("display", ""), case.get("attach", False),
                       case.get("flags", ()))
    result = answers(state)
    assert BACKEND.evaluate(state)[0] == lang, "language must be detected (no free pass via abstention)"
    dont_care = set(case.get("any", []))
    for qid in NOUL_QUESTIONS:
        if qid in dont_care:
            continue
        assert result[qid].p_yes < THRESHOLD, f"false {qid} ({result[qid].evidence_level}): {case['body']}"
    probs = result["category"].probabilities
    for label in ("phishing", "scam_fraud", "spam"):
        assert probs[label] < THRESHOLD, f"false category {label}"


def category_cases():
    for lang, corpus in CORPORA.items():
        for label, (cores, ctas) in corpus.CATEGORY_POOLS.items():
            for n, (core, cta) in enumerate(itertools.product(cores, ctas)):
                body = f"{corpus.OPENERS[n % len(corpus.OPENERS)]} {core} {cta}"
                yield pytest.param(lang, label, body, id=f"{lang}-{label}-{n}")


@pytest.mark.parametrize("lang,label,body", list(category_cases()))
def test_category_positive(lang, label, body):
    probs = answers(make_state("Mitteilung" if lang == "de" else "Notice", body))["category"].probabilities
    assert probs[label] >= THRESHOLD, f"{label}: {probs} :: {body}"


def test_counts_meet_minimum():
    """≥ 30 positives and ≥ 30 negatives per question and language (category included)."""
    for lang, corpus in CORPORA.items():
        positives = {}
        for qid, _ in generated(corpus, corpus.POOLS):
            positives[qid] = positives.get(qid, 0) + 1
        for qid in NOUL_QUESTIONS:
            negatives = sum(1 for c in corpus.LEGIT if qid not in c.get("any", []))
            assert positives.get(qid, 0) >= 30, (lang, qid, positives.get(qid, 0))
            assert negatives >= 30, (lang, qid, negatives)
        category_pos = sum(len(c) * len(t) for c, t in corpus.CATEGORY_POOLS.values())
        assert category_pos >= 30 and len(corpus.LEGIT) >= 30


def test_newsletter_bulk_flag_gives_newsletter_category():
    state = make_state("Neuigkeiten", corpus_de.LEGIT[2]["body"], flags=("bulk",))
    probs = answers(state)["category"].probabilities
    assert max(probs, key=probs.get) == "newsletter_bulk"


@pytest.mark.parametrize("text,reason", [
    ("Hallo, kurz und knapp: bis morgen!", "too_short"),
    ("Bonjour, nous vous informons que votre colis est arrivé au dépôt. Veuillez confirmer votre adresse de "
     "livraison et payer les frais de douane afin que nous puissions livrer votre colis rapidement.", "unsupported_language"),
    ("Hola, le informamos de que su cuenta ha sido bloqueada temporalmente por motivos de seguridad. Por favor "
     "confirme sus datos personales en el siguiente enlace para reactivar su cuenta lo antes posible.", "unsupported_language"),
])
def test_abstains_for_other_languages_and_short_text(text, reason):
    result = answers(make_state("-", text))
    for qid in CANONICAL_QUESTIONS:
        assert result[qid].abstain == reason
        assert result[qid].p_yes is None


def test_unknown_question_abstains():
    out = BACKEND.answer(make_state("x", corpus_de.LEGIT[0]["body"]), [{"id": "is_poem", "type": "noul"}], None)
    assert out["is_poem"].abstain == "unsupported_question"


def test_homoglyph_and_invisible_obfuscation_is_folded():
    body = ("Sehr geehrte Kundin, sehr geehrter Kunde, wir wenden uns heute an Sie. Aus Sicherheitsgründen wurde Ihr "
            "Konto vorübergehend eingeschränkt. Bitte bеstät​igen Sie Ihre Zugаngsdaten. Klicken Sie hier: [LINK]")
    assert answers(make_state("Konto", body))["asks_credentials"].p_yes >= THRESHOLD


def test_probabilities_are_the_fixed_level_values():
    body = corpus_de.LEGIT[0]["body"]
    for answer in answers(make_state("x", body)).values():
        if answer.type == "noul":
            assert answer.p_yes in (0.05, 0.35, 0.65, 0.90)
            assert answer.calibrated is False and answer.backend == "rules"
