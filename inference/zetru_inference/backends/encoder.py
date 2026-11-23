"""Optional `encoder` backend: fine-tuned multilingual encoder (mmBERT-small/base) in ONNX int8 run with ONNX
Runtime (concept §9.3). Off by default. It becomes available only when

- the optional packages `onnxruntime`, `tokenizers` and `numpy` are installed (requirements-encoder.txt), and
- `/models/encoder/current.json` points to a release that passed the gates of §9.6:
  {"version": "...", "path": "<version>", "model": "model.onnx", "tokenizer": "tokenizer.json",
   "heads": "heads.json", "calibration": "calibration.json", "calibrated": true|false, "languages": ["de","en"]}

heads.json maps ONNX output names to heads: {"category": "<output>", "noul": "<output>", "noul_order": [...ids],
"risk": "<output>"}; calibration.json holds one temperature per head (and optionally per language).

Robustness (security review PY-24): every file named in current.json must resolve inside the release
directory; logits are clamped before exp(); a tokenizer or ONNX error makes the whole request abstain with
`backend_error` (the router then answers from `rules`); when more than half of the state's tokens fall
behind the 512-token window, answers carry `abstain: "state_truncated_over_50pct"` (still answered, §9.5).
"""

from __future__ import annotations

import json
import math
import os

from .. import CATEGORY_LABELS, RISK_LEVELS
from .base import Answer, Backend, abstain_answer

MAX_TOKENS = 512
MAX_LOGIT = 50.0
TRUNCATED = "state_truncated_over_50pct"


def _inside(root: str, name) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("file name")
    path = os.path.join(root, name)
    if not os.path.realpath(path).startswith(os.path.realpath(root) + os.sep):
        raise ValueError("path")
    return path


def _clamp(value: float) -> float:
    if value != value:   # NaN
        raise ValueError("nan")
    return max(-MAX_LOGIT, min(MAX_LOGIT, value))


class EncoderBackend(Backend):
    id = "encoder"
    licence_notice = None

    def __init__(self, models_dir: str | None):
        self.models_dir = models_dir
        self.session = None
        self.tokenizer = None
        self.np = None
        self.heads: dict = {}
        self.temperatures: dict = {}
        self.version = "encoder-unavailable"
        self.calibrated = False
        self.languages: list[str] = []
        self.error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.models_dir:
            self.error = "no_models_dir"
            return
        base = os.path.join(self.models_dir, "encoder")
        try:
            with open(os.path.join(base, "current.json"), "r", encoding="utf-8") as handle:
                current = json.load(handle)
        except (OSError, ValueError):
            self.error = "no_model"
            return
        try:
            import numpy  # noqa: F401  (optional dependency)
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError:
            self.error = "runtime_missing"
            return
        try:
            root = _inside(base, current["path"])
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = max(1, (os.cpu_count() or 2) - 1)
            self.session = onnxruntime.InferenceSession(_inside(root, current["model"]), options,
                                                        providers=["CPUExecutionProvider"])
            self.tokenizer = Tokenizer.from_file(_inside(root, current["tokenizer"]))
            self.tokenizer.enable_truncation(MAX_TOKENS)
            with open(_inside(root, current["heads"]), "r", encoding="utf-8") as handle:
                self.heads = json.load(handle)
            with open(_inside(root, current["calibration"]), "r", encoding="utf-8") as handle:
                self.temperatures = json.load(handle)
            if not isinstance(self.heads, dict) or not isinstance(self.temperatures, dict):
                raise ValueError("heads/calibration")
            import numpy as np

            self.np = np
            self.version = f"encoder-{current['version']}"
            self.calibrated = bool(current.get("calibrated", False))
            self.languages = list(current.get("languages", ["de", "en"]))
            self.error = None
        except Exception as exc:  # a broken model must not take the service down
            self.session = None
            self.error = type(exc).__name__

    def enabled(self) -> bool:
        return self.session is not None

    def _temperature(self, head: str, language: str | None) -> float:
        value = self.temperatures.get(f"{head}:{language}", self.temperatures.get(head, 1.0))
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 1.0
        return min(100.0, max(0.05, value)) if value > 0 else 1.0

    def answer(self, state: str, questions: list[dict], language_hint: str | None) -> dict[str, Answer]:
        if self.session is None:
            return {q["id"]: abstain_answer(q, self.id, self.version, "backend_error") for q in questions}
        try:
            by_name, truncated = self._run(state)
        except Exception:  # noqa: BLE001 - tokenizer/ONNX failure: abstain, the router falls back to rules
            return {q["id"]: abstain_answer(q, self.id, self.version, "backend_error", self.calibrated)
                    for q in questions}
        out: dict[str, Answer] = {}
        noul_order = list(self.heads.get("noul_order", []))
        for q in questions:
            qid = q["id"]
            try:
                if qid == "category":
                    temperature = self._temperature("category", language_hint)
                    probs = _softmax([_clamp(float(x)) / temperature for x in by_name[self.heads["category"]][0]])
                    answer = Answer(id=qid, type="choice", backend=self.id, model_version=self.version,
                                    calibrated=self.calibrated, probabilities=dict(zip(CATEGORY_LABELS, probs)))
                elif qid == "risk_score":
                    temperature = self._temperature("risk", language_hint)
                    dist = _softmax([_clamp(float(x)) / temperature for x in by_name[self.heads["risk"]][0]])
                    answer = Answer(id=qid, type="score", backend=self.id, model_version=self.version,
                                    calibrated=self.calibrated, distribution=dist,
                                    expected=sum(i * p for i, p in enumerate(dist)))
                elif qid in noul_order:
                    logit = _clamp(float(by_name[self.heads["noul"]][0][noul_order.index(qid)]))
                    p = _sigmoid(logit / self._temperature(qid, language_hint))
                    answer = Answer(id=qid, type="noul", backend=self.id, model_version=self.version,
                                    calibrated=self.calibrated, p_yes=p)
                else:
                    out[qid] = abstain_answer(q, self.id, self.version, "unsupported_question", self.calibrated)
                    continue
                if truncated:
                    answer.abstain = TRUNCATED
                out[qid] = answer
            except (KeyError, IndexError, ValueError, TypeError, OverflowError, ZeroDivisionError):
                out[qid] = abstain_answer(q, self.id, self.version, "backend_error", self.calibrated)
        return out

    def _run(self, state: str) -> tuple[dict, bool]:
        np = self.np
        enc = self.tokenizer.encode(state)
        kept = len(enc.ids)
        dropped = sum(len(o.ids) for o in (getattr(enc, "overflowing", None) or []))
        feeds = {"input_ids": np.array([enc.ids], dtype=np.int64),
                 "attention_mask": np.array([enc.attention_mask], dtype=np.int64)}
        names = [i.name for i in self.session.get_inputs()]
        outputs = self.session.run(None, {k: v for k, v in feeds.items() if k in names})
        return dict(zip([o.name for o in self.session.get_outputs()], outputs)), dropped > kept


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _softmax(values: list[float]) -> list[float]:
    m = max(values)
    exps = [math.exp(v - m) for v in values]
    total = sum(exps)
    return [e / total for e in exps]


__all__ = ["EncoderBackend", "RISK_LEVELS"]
