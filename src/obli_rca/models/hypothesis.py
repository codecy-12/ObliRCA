"""Root-cause hypotheses, verification results, and rankings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .code import CodeLocation
from .evidence import Evidence


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    NEEDS_REVISION = "needs_revision"
    VERIFIED = "verified"
    REFUTED = "refuted"
    RANKED = "ranked"
    UNRESOLVED = "unresolved"


class GapType(str, Enum):
    INSUFFICIENT_EXISTING = "insufficient_existing"
    MISSING_NECESSARY = "missing_necessary"


@dataclass
class Hypothesis:
    obligation_id: str
    location: CodeLocation
    mechanism: str
    gap_type: GapType
    id: str = ""
    investigation_id: str = ""
    bindings: dict[str, str] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.0
    revision_round: int = 0
    source_app: str = ""
    missing_region: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.obligation_id}|{self.location.key}|{self.mechanism}".encode("utf-8")
            self.id = "hyp-" + hashlib.sha256(raw).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "obligation_id": self.obligation_id,
            "location": self.location.to_dict(),
            "mechanism": self.mechanism,
            "gap_type": self.gap_type.value,
            "bindings": self.bindings,
            "evidence": [e.to_dict() for e in self.evidence],
            "status": self.status.value,
            "confidence": self.confidence,
            "revision_round": self.revision_round,
            "source_app": self.source_app,
            "missing_region": self.missing_region,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Hypothesis":
        return cls(
            obligation_id=data["obligation_id"],
            location=CodeLocation(**data["location"]),
            mechanism=data["mechanism"],
            gap_type=GapType(data["gap_type"]),
            id=data.get("id", ""),
            investigation_id=data.get("investigation_id", ""),
            bindings=data.get("bindings", {}),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", [])],
            status=HypothesisStatus(data.get("status", "proposed")),
            confidence=float(data.get("confidence", 0.0)),
            revision_round=int(data.get("revision_round", 0)),
            source_app=data.get("source_app", ""),
            missing_region=data.get("missing_region", ""),
        )


@dataclass
class VerificationResult:
    hypothesis_id: str
    status: HypothesisStatus
    gap_type: GapType
    constraints: list[str] = field(default_factory=list)
    counterexample: dict[str, Any] = field(default_factory=dict)
    tool: str = "local-symbolic"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "status": self.status.value,
            "gap_type": self.gap_type.value,
            "constraints": self.constraints,
            "counterexample": self.counterexample,
            "tool": self.tool,
            "notes": self.notes,
        }


@dataclass
class RankedHypothesis:
    rank: int
    hypothesis: Hypothesis
    score: float
    explanation: str
    fix_suggestion: str
    obligation_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "hypothesis": self.hypothesis.to_dict(),
            "score": self.score,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "obligation_name": self.obligation_name,
        }


@dataclass
class FeedbackRequest:
    hypothesis_id: str
    conditions_to_check: list[str]
    tool_evidence: list[str]
    questions: list[str]
    round: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "conditions_to_check": self.conditions_to_check,
            "tool_evidence": self.tool_evidence,
            "questions": self.questions,
            "round": self.round,
        }
