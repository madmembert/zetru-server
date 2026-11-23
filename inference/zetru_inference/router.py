"""Backend router (concept §9.3 router rules).

1. Known question IDs go to `encoder` if available, else `rules`.
2. With both available, the reported probability is max(p_encoder, p_rules if strong): the rule tier can
   only raise risk.
3. `llm` is asked only when the encoder probability lies in 0.40–0.80 and may only raise it; uncalibrated
   it can raise to at most 0.79, so it never creates a signal by itself.
4. Remote backends (`openjev`, `jev`) follow the same raise-only rule with a 5 s timeout.
5. Unknown question IDs are answered only by an enabled zero-shot backend, else abstain
   `unsupported_question`.

Failure and time rules (security review PY-04, PY-12):
- one deadline per request (`DECIDE_BUDGET_S` = 6 s, below the analyzer's 8 s timeout); the rule tier stops
  at it and then abstains with `backend_error`;
- an optional tier (encoder, llm, remotes) that raises, returns something that is not an answer map, or misses
  the deadline is ignored: the answers already computed are returned. A failing encoder falls back to rules;
- `llm`, `openjev` and `jev` run in parallel on a small shared thread pool, each bounded by the deadline.
"""

from __future__ import annotations

import copy
import os
import threading
import time
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait

from . import CANONICAL_QUESTIONS
from .backends.base import Answer, Backend, abstain_answer
from .backends.encoder import EncoderBackend
from .backends.remote import LLMBackend, jev_from_env, openjev_from_env
from .backends.rules import RulesBackend

UNCERTAIN_LOW, UNCERTAIN_HIGH = 0.40, 0.80
UNCALIBRATED_CAP = 0.79
STRONG = 0.80
ORDER = ("rules", "encoder", "llm", "openjev", "jev")
DECIDE_BUDGET_S = 6.0
OPTIONAL_WORKERS = 4

_POOL: ThreadPoolExecutor | None = None
_POOL_LOCK = threading.Lock()


def _pool() -> ThreadPoolExecutor:
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = ThreadPoolExecutor(max_workers=OPTIONAL_WORKERS, thread_name_prefix="tier")
        return _POOL


def _valid(result, questions: list[dict]) -> dict[str, Answer] | None:
    """The answer map of a tier, or None when it is not one (a misbehaving backend is ignored)."""
    if not isinstance(result, dict):
        return None
    wanted = {q["id"] for q in questions}
    return {k: v for k, v in result.items() if k in wanted and isinstance(v, Answer) and v.id == k}


def _call(backend: Backend, state: str, questions: list[dict], hint: str | None,
          deadline: float) -> dict[str, Answer] | None:
    if time.monotonic() >= deadline:
        return None
    try:
        return _valid(backend.answer_until(state, questions, hint, deadline), questions)
    except Exception:  # noqa: BLE001 - an optional tier must never take the rule tier's answers with it
        return None


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

    def decide(self, state: str, questions: list[dict], language_hint: str | None, policy_backends: list[str],
               deadline: float | None = None) -> list[Answer]:
        deadline = time.monotonic() + DECIDE_BUDGET_S if deadline is None else deadline
        active = [b for b in ORDER if b in policy_backends and self.is_enabled(b)]
        known = [q for q in questions if q["id"] in CANONICAL_QUESTIONS]
        unknown = [q for q in questions if q["id"] not in CANONICAL_QUESTIONS]
        results: dict[str, Answer] = {}

        if known:
            primary_id, primary, secondary = None, None, None
            if "encoder" in active:
                primary = _call(self.backends["encoder"], state, known, language_hint, deadline)
                primary_id = "encoder" if primary is not None else None
            if "rules" in active:
                rules = _call(self.backends["rules"], state, known, language_hint, deadline)
                if primary_id is None:
                    primary_id, primary = "rules", rules
                else:
                    secondary = rules
            if primary is None:
                version = getattr(self.backends.get(primary_id), "version", "none") if primary_id else "none"
                for q in known:
                    results[q["id"]] = abstain_answer(q, primary_id or "rules", version, "backend_error")
            else:
                for q in known:
                    base = primary.get(q["id"]) or abstain_answer(q, primary_id, "?", "backend_error")
                    if secondary is not None:
                        base = _combine_rules(base, secondary.get(q["id"]))
                    results[q["id"]] = base
                self._raise_with_optional_tiers(state, known, language_hint, active, primary_id, results, deadline)
        for q in unknown:
            zero_shot = next((b for b in ("llm", "openjev", "jev") if b in active), None)
            if zero_shot is None or q.get("type") != "noul":
                results[q["id"]] = abstain_answer(q, "rules", "none", "unsupported_question")
                continue
            backend = self.backends[zero_shot]
            answer = (_call(backend, state, [q], language_hint, deadline) or {}).get(q["id"])
            if answer is None:
                answer = abstain_answer(q, zero_shot, "?", "backend_error")
            elif answer.p_yes is not None and not backend.calibrated:
                answer.p_yes = min(answer.p_yes, UNCALIBRATED_CAP)
            results[q["id"]] = answer
        return [results[q["id"]] for q in questions]

    def _raise_with_optional_tiers(self, state: str, known: list[dict], hint: str | None, active: list[str],
                                   primary_id: str, results: dict[str, Answer], deadline: float) -> None:
        jobs: list[tuple[str, list[dict]]] = []
        if primary_id == "encoder" and "llm" in active:
            uncertain = [q for q in known if q["type"] == "noul" and results[q["id"]].p_yes is not None
                         and UNCERTAIN_LOW <= results[q["id"]].p_yes <= UNCERTAIN_HIGH]
            if uncertain:
                jobs.append(("llm", uncertain))
        noul = [q for q in known if q["type"] == "noul"]
        for remote_id in ("openjev", "jev"):
            if remote_id in active and noul:
                jobs.append((remote_id, noul))
        if not jobs:
            return
        futures = {}
        pool = _pool()
        for backend_id, qs in jobs:
            futures[pool.submit(_call, self.backends[backend_id], state, qs, hint, deadline)] = backend_id
        wait(futures, timeout=max(0.0, deadline - time.monotonic()), return_when=ALL_COMPLETED)
        outcomes = {}
        for future, backend_id in futures.items():
            if future.done() and not future.cancelled() and future.exception() is None:
                outcomes[backend_id] = future.result()
            else:
                future.cancel()   # not started yet: skip it; running: its own timeouts end it
        for backend_id, _qs in jobs:          # fixed order: the result does not depend on timing
            answers = outcomes.get(backend_id)
            if not answers:
                continue
            backend = self.backends[backend_id]
            for qid, answer in answers.items():
                if qid in results:
                    results[qid] = _raise_only(results[qid], answer, backend.calibrated)


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
