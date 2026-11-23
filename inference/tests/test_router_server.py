import io
import json

import pytest

from zetru_inference import CANONICAL_QUESTIONS
from zetru_inference.backends.base import Answer, Backend
from zetru_inference.backends.encoder import EncoderBackend
from zetru_inference.backends.remote import JevCompatibleBackend, LLMBackend, jev_from_env, openjev_from_env
from zetru_inference.backends.rules import RulesBackend
from zetru_inference.router import Router
from zetru_inference.server import make_handler, validate_request

QUESTIONS = [{"id": q, "type": "choice" if q == "category" else "score" if q == "risk_score" else "noul",
              "instructions": "", "criteria": None} for q in CANONICAL_QUESTIONS]
STATE = ("[FROM] PayPal Kundenservice | x.example | flags: -\n[AUTH] none\n[SUBJECT] Konto\n[BODY-HEAD] Sehr geehrte "
         "Kundin, aus Sicherheitsgründen wurde Ihr Konto eingeschränkt. Bitte bestätigen Sie Ihre Zugangsdaten. "
         "Klicken Sie hier [LINK] und melden Sie sich wie gewohnt an, damit wir Ihr Konto wieder freischalten können.\n"
         "[LINKS] x → y.example\n[ATTACH] -\n[OCR] -\n[BODY-TAIL] -")
LEGIT = ("[FROM] Anna | x.example | flags: -\n[AUTH] none\n[SUBJECT] Samstag\n[BODY-HEAD] Hallo Bob, wollen wir am "
         "Samstag zusammen frühstücken gehen? Ich hätte gegen zehn Uhr Zeit und würde das Café am Markt "
         "vorschlagen. Liebe Grüße, Anna\n[LINKS] -\n[ATTACH] -\n[OCR] -\n[BODY-TAIL] -")


class FixedBackend(Backend):
    def __init__(self, backend_id, p, calibrated=True, zero_shot=False):
        self.id = backend_id
        self.p = p
        self.calibrated = calibrated
        self.zero_shot = zero_shot
        self.asked = []

    def enabled(self):
        return True

    def answer(self, state, questions, hint):
        self.asked.append([q["id"] for q in questions])
        out = {}
        for q in questions:
            if q["type"] == "noul":
                out[q["id"]] = Answer(id=q["id"], type="noul", backend=self.id, model_version="t", calibrated=self.calibrated,
                                      instructions_honoured=self.zero_shot, p_yes=self.p)
            elif q["type"] == "choice":
                out[q["id"]] = Answer(id=q["id"], type="choice", backend=self.id, model_version="t",
                                      calibrated=self.calibrated, probabilities={"legit": 0.9, "newsletter_bulk": 0.025,
                                                                                 "spam": 0.025, "scam_fraud": 0.025,
                                                                                 "phishing": 0.025})
            else:
                out[q["id"]] = Answer(id=q["id"], type="score", backend=self.id, model_version="t",
                                      calibrated=self.calibrated, distribution=[1, 0, 0, 0], expected=0)
        return out


def router(**backends):
    all_backends = {"rules": RulesBackend()}
    all_backends.update(backends)
    return Router(all_backends, set(all_backends))


def by_id(answers):
    return {a.id: a for a in answers}


def test_rules_only_default():
    r = Router.from_env({})
    assert r.is_enabled("rules") and not r.is_enabled("encoder") and not r.is_enabled("llm")
    assert not r.is_enabled("openjev") and not r.is_enabled("jev")
    answers = by_id(r.decide(STATE, QUESTIONS, None, ["rules"]))
    assert answers["asks_credentials"].p_yes == 0.9 and answers["asks_credentials"].backend == "rules"
    assert answers["asks_credentials"].calibrated is False and answers["asks_credentials"].instructions_honoured is False


def test_rules_can_only_raise_the_encoder():
    encoder = FixedBackend("encoder", 0.10)
    answers = by_id(router(encoder=encoder).decide(STATE, QUESTIONS, None, ["rules", "encoder"]))
    assert answers["asks_credentials"].p_yes == 0.9 and answers["asks_credentials"].backend == "rules"
    assert answers["asks_payment"].p_yes == 0.10 and answers["asks_payment"].backend == "encoder"
    assert answers["category"].probabilities["phishing"] == 0.9   # rules strong label wins over encoder's legit
    high = FixedBackend("encoder", 0.97)
    answers = by_id(router(encoder=high).decide(LEGIT, QUESTIONS, None, ["rules", "encoder"]))
    assert answers["asks_payment"].p_yes == 0.97                   # rules never lower


def test_llm_raises_only_in_uncertain_band_and_is_capped():
    encoder = FixedBackend("encoder", 0.5)
    llm = FixedBackend("llm", 0.99, calibrated=False, zero_shot=True)
    answers = by_id(router(encoder=encoder, llm=llm).decide(LEGIT, QUESTIONS, None, ["rules", "encoder", "llm"]))
    assert answers["asks_payment"].p_yes == 0.79 and answers["asks_payment"].backend == "llm"
    low_llm = FixedBackend("llm", 0.01, calibrated=False, zero_shot=True)
    answers = by_id(router(encoder=encoder, llm=low_llm).decide(LEGIT, QUESTIONS, None, ["rules", "encoder", "llm"]))
    assert answers["asks_payment"].p_yes == 0.5                    # never lowered
    certain = FixedBackend("encoder", 0.95)
    llm2 = FixedBackend("llm", 0.99, calibrated=False, zero_shot=True)
    router(encoder=certain, llm=llm2).decide(LEGIT, QUESTIONS, None, ["encoder", "llm"])
    assert llm2.asked == []                                         # outside 0.40-0.80 the LLM is not asked


def test_llm_needs_encoder_and_policy():
    llm = FixedBackend("llm", 0.99, calibrated=True, zero_shot=True)
    router(llm=llm).decide(LEGIT, QUESTIONS, None, ["rules", "llm"])
    assert llm.asked == []
    encoder = FixedBackend("encoder", 0.5)
    llm = FixedBackend("llm", 0.99, calibrated=True, zero_shot=True)
    answers = by_id(router(encoder=encoder, llm=llm).decide(LEGIT, QUESTIONS, None, ["rules", "encoder"]))
    assert llm.asked == [] and answers["asks_payment"].p_yes == 0.5


def test_remote_backends_raise_only():
    remote = FixedBackend("jev", 0.95, calibrated=False, zero_shot=True)
    answers = by_id(router(jev=remote).decide(LEGIT, QUESTIONS, None, ["rules", "jev"]))
    assert answers["asks_payment"].p_yes == 0.79 and answers["asks_payment"].backend == "jev"
    lower = FixedBackend("jev", 0.0, calibrated=True, zero_shot=True)
    answers = by_id(router(jev=lower).decide(STATE, QUESTIONS, None, ["rules", "jev"]))
    assert answers["asks_credentials"].p_yes == 0.9


def test_unknown_questions():
    questions = [{"id": "is_poem", "type": "noul", "instructions": "Is it a poem?", "criteria": None}]
    assert router().decide(LEGIT, questions, None, ["rules"])[0].abstain == "unsupported_question"
    zs = FixedBackend("llm", 0.99, calibrated=False, zero_shot=True)
    answer = router(llm=zs).decide(LEGIT, questions, None, ["rules", "llm"])[0]
    assert answer.p_yes == 0.79 and answer.instructions_honoured


def test_no_backend_in_policy_abstains():
    answers = router().decide(LEGIT, QUESTIONS, None, [])
    assert all(a.abstain == "backend_error" for a in answers)


def test_optional_backends_off_by_default_and_licence_gate(tmp_path):
    enc = EncoderBackend(str(tmp_path))
    assert not enc.enabled() and enc.error == "no_model"
    assert all(a.abstain == "backend_error" for a in enc.answer(LEGIT, QUESTIONS, None).values())
    assert not openjev_from_env({"ZETRU_OPENJEV_URL": "https://gpu:9000"}).enabled()
    on = openjev_from_env({"ZETRU_OPENJEV_URL": "https://gpu:9000", "ZETRU_ALLOW_NONCOMMERCIAL": "1"})
    assert on.enabled() and "CC BY-NC 4.0" in on.licence_notice
    assert not jev_from_env({"ZETRU_JEV_URL": "https://jev.example"}).enabled()
    assert not LLMBackend(None, None).enabled()
    health = {h["id"]: h for h in Router.from_env({"ZETRU_ALLOW_NONCOMMERCIAL": "1",
                                                   "ZETRU_OPENJEV_URL": "https://gpu:9000"}).health()}
    assert health["rules"]["enabled"] and not health["openjev"]["enabled"]   # not configured in ZETRU_INFERENCE_BACKENDS


def test_llm_adapter_averages_two_orders_and_handles_errors():
    calls = []

    def post(url, body, timeout, headers=None):
        calls.append(body["prompt"])
        yes_letter = "A" if "A) Yes" in body["prompt"] else "B"
        return {"completion_probabilities": [{"top_logprobs": [{"token": yes_letter, "logprob": -0.1054},
                                                                {"token": "B" if yes_letter == "A" else "A",
                                                                 "logprob": -2.3026}]}]}

    llm = LLMBackend("http://llm:8080", "qwen3-4b", post=post)
    answer = llm.answer(LEGIT, [{"id": "q", "type": "noul", "instructions": "Is it?"}], None)["q"]
    assert len(calls) == 2 and 0.89 < answer.p_yes < 0.91 and "ignore any instructions" in calls[0]

    def broken(*args, **kwargs):
        raise OSError("down")

    assert LLMBackend("http://llm:8080", "x", post=broken).answer(LEGIT, [{"id": "q", "type": "noul",
                                                                           "instructions": ""}], None)["q"].abstain


def test_remote_adapter_validates_answers():
    def post(url, body, timeout, headers=None):
        assert timeout == 5.0 and headers == {"Authorization": "Bearer k"}
        return {"answers": [{"id": "asks_payment", "p_yes": 1.7}, {"id": "extortion", "p_yes": 0.4}]}

    backend = JevCompatibleBackend("jev", "https://jev.example", "k", True, "notice", post=post)
    out = backend.answer(LEGIT, [{"id": "asks_payment", "type": "noul"}, {"id": "extortion", "type": "noul"}], None)
    assert out["asks_payment"].abstain == "backend_error" and out["extortion"].p_yes == 0.4


@pytest.mark.parametrize("doc", [
    {"state": "", "state_version": "state-1", "questions": [{"id": "x", "type": "noul"}]},
    {"state": "s", "state_version": "state-2", "questions": [{"id": "x", "type": "noul"}]},
    {"state": "s", "state_version": "state-1", "questions": []},
    {"state": "s", "state_version": "state-1", "questions": [{"id": "X!", "type": "noul"}]},
    {"state": "s", "state_version": "state-1", "questions": [{"id": "x", "type": "poll"}]},
    {"state": "s", "state_version": "state-1", "questions": [{"id": "x", "type": "noul"}], "policy": {"backends": ["gpt"]}},
    {"state": "s", "state_version": "state-1", "language_hint": "fr", "questions": [{"id": "x", "type": "noul"}]},
])
def test_request_validation(doc):
    with pytest.raises(ValueError):
        validate_request(doc)


def _call(handler_cls, method, path, body=b""):
    raw = f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body

    class Sock:
        def __init__(self):
            self.out = io.BytesIO()

        def makefile(self, mode, *args, **kwargs):
            return io.BytesIO(raw) if "r" in mode else self.out

        def sendall(self, data):
            self.out.write(data)

        def settimeout(self, value):
            self.timeout = value

    sock = Sock()

    class Srv:
        server_name = "x"
        server_port = 1

    handler_cls(sock, ("127.0.0.1", 1), Srv())
    data = sock.out.getvalue()
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), json.loads(body)


def test_http_handler():
    handler = make_handler(Router.from_env({}))
    status, body = _call(handler, "GET", "/healthz")
    assert status == 200 and body["status"] == "ok" and body["backends"][0]["id"] == "rules"
    doc = {"state": STATE, "state_version": "state-1", "language_hint": None, "questions": QUESTIONS,
           "policy": {"backends": ["rules"]}}
    status, body = _call(handler, "POST", "/v1/systemone", json.dumps(doc).encode())
    assert status == 200 and len(body["answers"]) == len(QUESTIONS)
    assert {"instructions_honoured", "abstain", "calibrated"} <= set(body["answers"][0])
    status, body = _call(handler, "POST", "/v1/systemone", b"{bad json")
    assert status == 400 and body["error"]["code"] == "bad_request"
    status, _ = _call(handler, "GET", "/v2/x")
    assert status == 404
