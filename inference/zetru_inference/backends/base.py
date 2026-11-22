"""Backend interface and answer type shared by all typed-decision backends (concept §9.3)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Answer:
    id: str
    type: str
    backend: str
    model_version: str
    calibrated: bool
    instructions_honoured: bool = False
    abstain: str | None = None
    p_yes: float | None = None
    probabilities: dict[str, float] | None = None
    distribution: list[float] | None = None
    expected: float | None = None
    evidence_level: str | None = field(default=None, repr=False)   # rules tier only, not serialised

    def to_json(self) -> dict:
        return {
            "id": self.id, "type": self.type,
            "p_yes": None if self.p_yes is None else round(self.p_yes, 4),
            "probabilities": None if self.probabilities is None else {k: round(v, 4) for k, v in self.probabilities.items()},
            "distribution": None if self.distribution is None else [round(v, 4) for v in self.distribution],
            "expected": None if self.expected is None else round(self.expected, 4),
            "backend": self.backend, "model_version": self.model_version, "calibrated": self.calibrated,
            "abstain": self.abstain, "instructions_honoured": self.instructions_honoured,
        }


class Backend:
    id = "base"
    calibrated = False
    licence_notice: str | None = None
    zero_shot = False          # may answer questions it was not trained for
    remote = False             # mail-derived text leaves this container

    def enabled(self) -> bool:
        return False

    def answer(self, state: str, questions: list[dict], language_hint: str | None) -> dict[str, Answer]:
        raise NotImplementedError

    def health(self) -> dict:
        return {"id": self.id, "enabled": self.enabled(), "calibrated": self.calibrated,
                "licence_notice": self.licence_notice}


def abstain_answer(question: dict, backend: str, version: str, reason: str, calibrated: bool = False) -> Answer:
    return Answer(id=question["id"], type=question["type"], backend=backend, model_version=version,
                  calibrated=calibrated, abstain=reason)
