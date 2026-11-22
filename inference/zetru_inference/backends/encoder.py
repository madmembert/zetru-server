"""Optional `encoder` backend: fine-tuned multilingual encoder (mmBERT-small/base) in ONNX int8 run with ONNX
Runtime (concept §9.3). Off by default. It becomes available only when

- the optional packages `onnxruntime`, `tokenizers` and `numpy` are installed (requirements-encoder.txt), and
- `/models/encoder/current.json` points to a release that passed the gates of §9.6:
  {"version": "...", "path": "<version>", "model": "model.onnx", "tokenizer": "tokenizer.json",
   "heads": "heads.json", "calibration": "calibration.json", "calibrated": true|false, "languages": ["de","en"]}

heads.json maps ONNX output names to heads: {"category": "<output>", "noul": "<output>", "noul_order": [...ids],
"risk": "<output>"}; calibration.json holds one temperature per head (and optionally per language).
"""

from __future__ import annotations

import json
import math
import os

from .. import CATEGORY_LABELS, RISK_LEVELS
from .base import Answer, Backend, abstain_answer

MAX_TOKENS = 512


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
            root = os.path.join(base, current["path"])
            if not os.path.realpath(root).startswith(os.path.realpath(base) + os.sep):
                raise ValueError("path")
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = max(1, (os.cpu_count() or 2) - 1)
            self.session = onnxruntime.InferenceSession(os.path.join(root, current["model"]), options,
                                                        providers=["CPUExecutionProvider"])
            self.tokenizer = Tokenizer.from_file(os.path.join(root, current["tokenizer"]))
            self.tokenizer.enable_truncation(MAX_TOKENS)
            with open(os.path.join(root, current["heads"]), "r", encoding="utf-8") as handle:
                self.heads = json.load(handle)
            with open(os.path.join(root, current["calibration"]), "r", encoding="utf-8") as handle:
                self.temperatures = json.load(handle)
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
        return value if value > 0 else 1.0

    def answer(self, state: str, questions: list[dict], language_hint: str | None) -> dict[str, Answer]:
        if self.session is None:
            return {q["id"]: abstain_answer(q, self.id, self.version, "backend_error") for q in questions}
        np = self.np
        enc = self.tokenizer.encode(state)
        feeds = {"input_ids": np.array([enc.ids], dtype=np.int64),
                 "attention_mask": np.array([enc.attention_mask], dtype=np.int64)}
        names = [i.name for i in self.session.get_inputs()]
        outputs = self.session.run(None, {k: v for k, v in feeds.items() if k in names})
        by_name = dict(zip([o.name for o in self.session.get_outputs()], outputs))
        out: dict[str, Answer] = {}
        noul_order = list(self.heads.get("noul_order", []))
        for q in questions:
            qid = q["id"]
            try:
                if qid == "category":
                    logits = by_name[self.heads["category"]][0] / self._temperature("category", language_hint)
                    probs = _softmax([float(x) for x in logits])
                    out[qid] = Answer(id=qid, type="choice", backend=self.id, model_version=self.version,
                                      calibrated=self.calibrated, probabilities=dict(zip(CATEGORY_LABELS, probs)))
                elif qid == "risk_score":
                    logits = by_name[self.heads["risk"]][0] / self._temperature("risk", language_hint)
                    dist = _softmax([float(x) for x in logits])
                    out[qid] = Answer(id=qid, type="score", backend=self.id, model_version=self.version,
                                      calibrated=self.calibrated, distribution=dist,
                                      expected=sum(i * p for i, p in enumerate(dist)))
                elif qid in noul_order:
                    logit = float(by_name[self.heads["noul"]][0][noul_order.index(qid)])
                    p = 1.0 / (1.0 + math.exp(-logit / self._temperature(qid, language_hint)))
                    out[qid] = Answer(id=qid, type="noul", backend=self.id, model_version=self.version,
                                      calibrated=self.calibrated, p_yes=p)
                else:
                    out[qid] = abstain_answer(q, self.id, self.version, "unsupported_question", self.calibrated)
            except (KeyError, IndexError, ValueError):
                out[qid] = abstain_answer(q, self.id, self.version, "backend_error", self.calibrated)
        return out


def _softmax(values: list[float]) -> list[float]:
    m = max(values)
    exps = [math.exp(v - m) for v in values]
    total = sum(exps)
    return [e / total for e in exps]


__all__ = ["EncoderBackend", "RISK_LEVELS"]
