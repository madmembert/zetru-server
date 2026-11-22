"""Backend router (concept §9.3 router rules).

1. Known question IDs go to `encoder` if available, else `rules`.
2. With both available, the reported probability is max(p_encoder, p_rules if strong): the rule tier can
   only raise risk.
3. `llm` is asked only when the encoder probability lies in 0.40–0.80 and may only raise it; uncalibrated
   it can raise to at most 0.79, so it never creates a signal by itself.
4. Remote backends (`openjev`, `jev`) follow the same raise-only rule with a 5 s timeout.
5. Unknown question IDs are answered only by an enabled zero-shot backend, else abstain
   `unsupported_question`.
"""

from __future__ import annotations

import copy
import os

from . import CANONICAL_QUESTIONS
from .backends.base import Answer, Backend, abstain_answer
from .backends.encoder import EncoderBackend
from .backends.remote import LLMBackend, jev_from_env, openjev_from_env
from .backends.rules import RulesBackend

UNCERTAIN_LOW, UNCERTAIN_HIGH = 0.40, 0.80
UNCALIBRATED_CAP = 0.79
STRONG = 0.80
ORDER = ("rules", "encoder", "llm", "openjev", "jev")


class Router:
    def __init__(self, backends: dict[str, Backend], configured: set[str]):
        self.backends = backends
        self.configured = configured

    @classmethod
    def from_env(cls, env=os.environ) -> "Router":
        configured = {b.strip() for b in env.get("ZETRU_INFERENCE_BACKENDS", "rules").split(",") if b.strip()}
        backends: dict[str, Backend] = {"rules": RulesBackend()}
        backends["encoder"] = EncoderBackend(env.get("ZETRU_MODELS_DIR", "/models") if "encoder" in configured else None)
        backends["llm"] = LLMBackend(env.get("ZETRU_LLM_URL") if "llm" in configured else None,
                                     env.get("ZETRU_LLM_MODEL_VERSION"), env.get("ZETRU_LLM_CALIBRATED") == "1")
        backends["openjev"] = openjev_from_env(env)
        backends["jev"] = jev_from_env(env)
        return cls(backends, configured)

    def is_enabled(self, backend_id: str) -> bool:
        backend = self.backends.get(backend_id)
        return backend is not None and backend_id in self.configured and backend.enabled()

    def health(self) -> list[dict]:
        out = []
        for backend_id in ORDER:
            backend = self.backends.get(backend_id)
            if backend is None:
                continue
            entry = backend.health()
            entry["enabled"] = self.is_enabled(backend_id)
            out.append(entry)
        return out

    def decide(self, state: str, questions: list[dict], language_hint: str | None, policy_backends: list[str]) -> list[Answer]:
        active = [b for b in ORDER if b in policy_backends and self.is_enabled(b)]
        known = [q for q in questions if q["id"] in CANONICAL_QUESTIONS]
        unknown = [q for q in questions if q["id"] not in CANONICAL_QUESTIONS]
        results: dict[str, Answer] = {}

        primary_id = "encoder" if "encoder" in active else ("rules" if "rules" in active else None)
        if known:
            if primary_id is None:
                for q in known:
                    results[q["id"]] = abstain_answer(q, "rules", "none", "backend_error")
            else:
                primary = self.backends[primary_id].answer(state, known, language_hint)
                secondary = None
                if primary_id == "encoder" and "rules" in active:
                    secondary = self.backends["rules"].answer(state, known, language_hint)
                for q in known:
                    base = primary.get(q["id"]) or abstain_answer(q, primary_id, "?", "backend_error")
                    if secondary is not None:
                        base = _combine_rules(base, secondary.get(q["id"]))
                    results[q["id"]] = base
                if primary_id == "encoder" and "llm" in active:
                    uncertain = [q for q in known if q["type"] == "noul" and results[q["id"]].p_yes is not None
                                 and UNCERTAIN_LOW <= results[q["id"]].p_yes <= UNCERTAIN_HIGH]
                    if uncertain:
                        llm = self.backends["llm"]
                        for qid, answer in llm.answer(state, uncertain, language_hint).items():
                            results[qid] = _raise_only(results[qid], answer, llm.calibrated)
                for remote_id in ("openjev", "jev"):
                    if remote_id not in active:
                        continue
                    remote = self.backends[remote_id]
                    noul = [q for q in known if q["type"] == "noul"]
                    for qid, answer in remote.answer(state, noul, language_hint).items():
                        results[qid] = _raise_only(results[qid], answer, remote.calibrated)
        for q in unknown:
            zero_shot = next((b for b in ("llm", "openjev", "jev") if b in active), None)
            if zero_shot is None or q.get("type") != "noul":
                results[q["id"]] = abstain_answer(q, primary_id or "rules", "none", "unsupported_question")
                continue
            backend = self.backends[zero_shot]
            answer = backend.answer(state, [q], language_hint)[q["id"]]
            if answer.p_yes is not None and not backend.calibrated:
                answer.p_yes = min(answer.p_yes, UNCALIBRATED_CAP)
            results[q["id"]] = answer
        return [results[q["id"]] for q in questions]


def _combine_rules(encoder: Answer, rules: Answer | None) -> Answer:
    """max(p_encoder, p_rules if strong); rules only ever raise."""
    if rules is None or rules.abstain:
        return encoder
    if encoder.abstain:
        return rules
    if encoder.type == "noul" and rules.p_yes is not None and rules.p_yes >= STRONG and rules.p_yes > (encoder.p_yes or 0):
        return rules
    if encoder.type == "choice" and rules.probabilities and encoder.probabilities:
        label = max(rules.probabilities, key=rules.probabilities.get)
        if label != "legit" and rules.probabilities[label] >= STRONG and rules.probabilities[label] > encoder.probabilities.get(label, 0):
            return rules
    return encoder


def _raise_only(current: Answer, candidate: Answer, calibrated: bool) -> Answer:
    if candidate.abstain or candidate.p_yes is None or current.p_yes is None:
        return current
    p = candidate.p_yes if calibrated else min(candidate.p_yes, UNCALIBRATED_CAP)
    if p <= current.p_yes:
        return current
    raised = copy.copy(current)
    raised.p_yes = p
    raised.backend = candidate.backend
    raised.model_version = candidate.model_version
    raised.calibrated = calibrated
    raised.instructions_honoured = candidate.instructions_honoured
    return raised
