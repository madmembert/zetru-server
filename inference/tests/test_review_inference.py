"""Regression tests for the security review of the inference service (findings PY-03, PY-04, PY-12, PY-16,
PY-24, PY-26)."""

import http.client
import re
import socket
import threading
import time

import pytest

from zetru_inference import CANONICAL_QUESTIONS
from zetru_inference.backends import encoder as encoder_mod
from zetru_inference.backends import rules as rules_mod
from zetru_inference.backends.base import Answer, Backend
from zetru_inference.backends.encoder import EncoderBackend
from zetru_inference.backends.remote import JevCompatibleBackend, LLMBackend, _valid_url
from zetru_inference.backends.rules import RulesBackend
from zetru_inference.router import Router
from zetru_inference.server import BoundedThreadingHTTPServer, make_handler

QUESTIONS = [{"id": q, "type": "choice" if q == "category" else "score" if q == "risk_score" else "noul",
              "instructions": "", "criteria": None} for q in CANONICAL_QUESTIONS]
RULES = RulesBackend()


def state(body: str, subject: str = "Account notice", display: str = "PayPal", tail: str = "-") -> str:
    return (f"[FROM] {display} | x.example | flags: -\n[AUTH] none\n[SUBJECT] {subject}\n[BODY-HEAD] {body}\n"
            f"[LINKS] Konto → y.example\n[ATTACH] -\n[OCR] -\n[BODY-TAIL] {tail}")


PHISH_EN = ("Dear customer, your PayPal account has been limited for security reasons. Please confirm your login "
            "details here [LINK] to restore access. Thank you for your cooperation, your PayPal team.")
PHISH_DE = ("Sehr geehrte Kundin, aus Sicherheitsgründen wurde Ihr Konto eingeschränkt. Bitte bestätigen Sie Ihre "
            "Zugangsdaten. Klicken Sie hier [LINK] und melden Sie sich wie gewohnt an, damit wir Ihr Konto wieder "
            "freischalten können.")


def by_id(answers):
    return {a.id: a for a in answers}


# PY-04: quadratic patterns, lint, time bounds ----------------------------------------------------------------

def test_lint_rejects_the_old_quadratic_amount_pattern_and_accepts_the_shipped_packs():
    old = re.compile(r"\d+(?:[.,]\d{2})?\s?(?:usd|gbp|eur|dollars?|pounds?|euros?)\b")
    assert rules_mod.slow_patterns([old]) == [old.pattern]
    for language in RULES.languages.values():
        assert rules_mod.slow_patterns(language.all_patterns()) == []


def test_load_rules_fails_on_a_super_linear_pack(tmp_path):
    pack = tmp_path / "xx.yaml"
    pack.write_text("version: t\ncta: {link: [], reply: [], attachment: []}\nquestions:\n  q:\n    groups:\n"
                    "      g: ['\\d+(?:[.,]\\d{2})?\\s?(?:usd|eur)\\b']\n", encoding="utf-8")
    with pytest.raises(ValueError, match="super-linear"):
        rules_mod.load_rules(str(pack))


@pytest.mark.parametrize("unit", ["1", "1 ", "a", " ", "€1", "1,"])
def test_rule_tier_is_fast_on_pathological_200kb_state(unit):
    junk = unit * (200_000 // len(unit))
    started = time.monotonic()
    answers = by_id(Router.from_env({}).decide(state(PHISH_EN + " " + junk[:60_000]), QUESTIONS, None, ["rules"]))
    assert time.monotonic() - started < 1.0
    assert answers["asks_credentials"].p_yes is not None or answers["asks_credentials"].abstain


def test_digit_run_amount_still_matches_normal_amounts():
    answers = RULES.answer(state("Dear customer, we have not received your money yet. Please pay the outstanding "
                                 "invoice of 450.00 EUR today via the link [LINK] to avoid the penalty fee. Thank you "
                                 "for your understanding.", subject="Invoice", display="Billing"),
                           [{"id": "asks_payment", "type": "noul"}], None)
    assert answers["asks_payment"].p_yes == 0.9


def test_rule_tier_stops_at_the_deadline():
    answers = by_id(Router.from_env({}).decide(state(PHISH_EN), QUESTIONS, None, ["rules"],
                                               deadline=time.monotonic() - 1))
    assert all(a.abstain == "backend_error" for a in answers.values())


def test_server_refuses_connections_beyond_its_thread_limit():
    httpd = BoundedThreadingHTTPServer(("127.0.0.1", 0), make_handler(Router.from_env({})), max_concurrent=1,
                                       bind_and_activate=False)
    assert httpd.slots.acquire(blocking=False)      # the only slot is taken by a running request
    ours, theirs = socket.socketpair()
    try:
        httpd.process_request(theirs, ("127.0.0.1", 1))
        reply = ours.recv(4096)
    finally:
        ours.close()
        httpd.slots.release()
        httpd.server_close()
    assert reply.startswith(b"HTTP/1.1 503") and b'"busy"' in reply


# PY-12: optional tiers cannot take the rule tier's answers with them --------------------------------------------

class Exploding(Backend):
    def __init__(self, backend_id, exc=None, sleep=0.0, result=None):
        self.id, self.exc, self.sleep, self.result = backend_id, exc, sleep, result
        self.calibrated = False

    def enabled(self):
        return True

    def answer(self, state, questions, hint):
        if self.sleep:
            time.sleep(self.sleep)
        if self.exc is not None:
            raise self.exc
        return self.result


def router_with(**extra):
    backends = {"rules": RULES, **extra}
    return Router(backends, set(backends))


@pytest.mark.parametrize("backend", [
    Exploding("jev", AttributeError("'list' object has no attribute 'get'")),
    Exploding("jev", http.client.IncompleteRead(b"")),
    Exploding("jev", result=["not", "a", "dict"]),
    Exploding("openjev", RuntimeError("boom")),
])
def test_failing_remote_keeps_rule_answers(backend):
    answers = by_id(router_with(**{backend.id: backend}).decide(state(PHISH_EN), QUESTIONS, None,
                                                                ["rules", backend.id]))
    assert answers["asks_credentials"].p_yes == 0.9 and answers["asks_credentials"].backend == "rules"


def test_remote_returning_a_json_array_or_truncated_body_abstains():
    for result in ([], "x", {"answers": "nope"}, {"answers": [1, 2]}):
        jev = JevCompatibleBackend("jev", "https://jev.example", "k", True, "n", post=lambda *a, r=result, **k: r)
        assert all(a.abstain == "backend_error" for a in jev.answer("s", [{"id": "x", "type": "noul"}], None).values())

    def truncated(*args, **kwargs):
        raise http.client.IncompleteRead(b"{")

    jev = JevCompatibleBackend("jev", "https://jev.example", "k", True, "n", post=truncated)
    assert jev.answer("s", [{"id": "x", "type": "noul"}], None)["x"].abstain == "backend_error"


def test_slow_remote_is_cut_at_the_deadline():
    slow = Exploding("jev", sleep=3.0, result={})
    started = time.monotonic()
    answers = by_id(router_with(jev=slow).decide(state(PHISH_EN), QUESTIONS, None, ["rules", "jev"],
                                                 deadline=time.monotonic() + 0.5))
    assert time.monotonic() - started < 1.5
    assert answers["asks_credentials"].p_yes == 0.9


def test_failing_encoder_falls_back_to_rules():
    encoder = Exploding("encoder", ValueError("onnx"))
    answers = by_id(router_with(encoder=encoder).decide(state(PHISH_EN), QUESTIONS, None, ["rules", "encoder"]))
    assert answers["asks_credentials"].backend == "rules" and answers["asks_credentials"].p_yes == 0.9


def test_llm_stops_issuing_calls_after_the_deadline():
    calls = []

    def post(url, body, timeout, headers=None):
        calls.append(timeout)
        return {"completion_probabilities": [{"top_logprobs": [{"token": "A", "logprob": -0.1}]}]}

    llm = LLMBackend("http://llm:8080", "m", post=post)
    out = llm.answer_until("s", [{"id": f"q{i}", "type": "noul", "instructions": ""} for i in range(5)], None,
                           time.monotonic() - 1)
    assert calls == [] and all(a.abstain == "backend_error" for a in out.values())


# PY-16: sender-controlled suppressors ---------------------------------------------------------------------------

@pytest.mark.parametrize("body,qid", [
    (PHISH_EN.replace("Please confirm", "(newsletter) Please confirm").replace("Dear customer,", "Dear customer, (newsletter)"),
     "asks_credentials"),
    (PHISH_DE.replace("Bitte bestätigen", "(Newsletter) Bitte bestätigen").replace("Klicken", "(Newsletter) Klicken"),
     "asks_credentials"),
    ("Dear customer, we have not received your money yet and your account will be suspended. Please pay the "
     "outstanding fee of 49.00 EUR now via [LINK] (no action required). Thank you for your understanding.",
     "asks_payment"),
])
def test_injected_suppressor_words_do_not_cancel_a_request(body, qid):
    assert RULES.answer(state(body), [{"id": qid, "type": "noul"}], None)[qid].p_yes == 0.9


def test_suppressor_still_neutralises_the_phrase_it_was_written_for():
    service = state("Your car insurance has been renewed from 1 January. You will receive the premium notice by "
                    "post in the next few days. If you have any questions, call us on 0161 496 0000 from Monday "
                    "to Friday.", subject="Your insurance renewal", display="Insurance")
    assert RULES.answer(service, [{"id": "asks_callback", "type": "noul"}], None)["asks_callback"].p_yes < 0.8


# PY-03 (rule tier part): dilution with foreign words --------------------------------------------------------------

def test_diluted_phishing_text_still_yields_strong_findings_and_abstains_otherwise():
    filler = " ".join(f"zqx{i}" for i in range(300))
    answers = RULES.answer(state(PHISH_EN, tail=filler), QUESTIONS, None)
    assert answers["asks_credentials"].p_yes == 0.9 and answers["asks_credentials"].abstain is None
    assert answers["category"].probabilities["phishing"] == 0.9
    assert answers["asks_payment"].abstain == "unsupported_language"
    french = state("Bonjour Paul, nous vous informons que la réunion de demain est annulée. " * 3 + filler)
    assert all(a.abstain == "unsupported_language" for a in RULES.answer(french, QUESTIONS, None).values())


# PY-24: encoder robustness ------------------------------------------------------------------------------------------

class FakeEncoding:
    def __init__(self, n, overflow):
        self.ids = [1] * n
        self.attention_mask = [1] * n
        self.overflowing = [FakeEncoding(n, 0) for _ in range(overflow)]


class FakeTokenizer:
    def __init__(self, overflow=0, fail=False):
        self.overflow, self.fail = overflow, fail

    def encode(self, text):
        if self.fail:
            raise RuntimeError("tokenizer")
        return FakeEncoding(512, self.overflow)


class FakeIO:
    def __init__(self, name):
        self.name = name


class FakeSession:
    def __init__(self, noul_logit):
        self.noul_logit = noul_logit

    def get_inputs(self):
        return [FakeIO("input_ids"), FakeIO("attention_mask")]

    def get_outputs(self):
        return [FakeIO("cat"), FakeIO("noul"), FakeIO("risk")]

    def run(self, _names, _feeds):
        return [[[1e9, -1e9, 0.0, 0.0, 0.0]], [[self.noul_logit] * 10], [[0.0, 0.0, 0.0, 0.0]]]


class FakeNumpy:
    int64 = "int64"

    @staticmethod
    def array(value, dtype=None):
        return value


def fake_encoder(noul_logit=-1e6, overflow=0, fail=False):
    enc = EncoderBackend(None)
    enc.session, enc.tokenizer, enc.np = FakeSession(noul_logit), FakeTokenizer(overflow, fail), FakeNumpy()
    enc.heads = {"category": "cat", "noul": "noul", "risk": "risk",
                 "noul_order": [q for q in CANONICAL_QUESTIONS if q not in ("category", "risk_score")]}
    enc.temperatures = {"asks_payment": 1e-300}
    enc.version = "encoder-test"
    return enc


def test_encoder_clamps_extreme_logits_and_flags_truncation():
    answers = fake_encoder(noul_logit=-1e6, overflow=2).answer("s", QUESTIONS, None)
    assert 0.0 <= answers["asks_payment"].p_yes < 0.01
    assert answers["asks_payment"].abstain == "state_truncated_over_50pct"
    assert abs(sum(answers["category"].probabilities.values()) - 1.0) < 1e-6
    assert fake_encoder(overflow=0).answer("s", QUESTIONS, None)["asks_payment"].abstain is None


def test_encoder_tokenizer_error_abstains_instead_of_raising():
    answers = fake_encoder(fail=True).answer("s", QUESTIONS, None)
    assert all(a.abstain == "backend_error" for a in answers.values())


def test_encoder_file_names_must_stay_in_the_release_directory(tmp_path):
    with pytest.raises(ValueError):
        encoder_mod._inside(str(tmp_path), "../../etc/passwd")
    assert encoder_mod._inside(str(tmp_path), "model.onnx").endswith("model.onnx")


# PY-26: remote backends need TLS --------------------------------------------------------------------------------------

def test_remote_backends_require_https_unless_loopback():
    for url, ok in (("http://jev.example", False), ("https://jev.example", True), ("http://127.0.0.1:9000", True),
                    ("http://[::1]:9000", True), ("http://localhost:9000", True), ("ftp://jev.example", False),
                    ("https://jev.example:99999", False)):
        assert _valid_url(url, require_tls=True) is ok, url
        assert JevCompatibleBackend("jev", url, "k", True, "n").enabled() is ok, url
    assert _valid_url("http://llm:8080")          # the local LLM tier keeps mail text on the operator's host


def test_rule_phone_check_is_linear_with_many_ibans():
    text = " ".join("DE89 3704 0044 0532 0130 00 0301234567 1.1.2026" for _ in range(3000))
    started = time.monotonic()
    rules_mod._phones(text)
    assert time.monotonic() - started < 1.0


def test_threads_from_the_optional_pool_are_bounded():
    from zetru_inference import router as router_mod
    assert router_mod._pool()._max_workers == router_mod.OPTIONAL_WORKERS
    assert threading.active_count() < 64


def test_answer_type_guard_ignores_foreign_objects():
    from zetru_inference.router import _valid
    good = Answer(id="x", type="noul", backend="b", model_version="v", calibrated=False, p_yes=0.5)
    assert _valid({"x": good, "y": good, "z": "junk"}, [{"id": "x"}, {"id": "z"}]) == {"x": good}
    assert _valid(["x"], [{"id": "x"}]) is None
