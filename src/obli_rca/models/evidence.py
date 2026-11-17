"""Evidence records shared by offline and online agents."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


class EvidenceKind(str, Enum):
    LOG = "log"
    SOURCE = "source"
    BINDING = "binding"
    STATIC = "static"
    SYMBOLIC = "symbolic"
    CROSS_APP = "cross_app"
    PATCH = "patch"
    ANNOTATION = "annotation"
    REVIEW = "review"


@dataclass
class Evidence:
    kind: EvidenceKind
    summary: str
    reference: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_by: str = ""
    id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.kind}|{self.reference}|{self.summary}".encode("utf-8")
            self.id = "ev-" + hashlib.sha256(raw).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "summary": self.summary,
            "reference": self.reference,
            "payload": self.payload,
            "confidence": self.confidence,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            kind=EvidenceKind(data["kind"]),
            summary=data["summary"],
            reference=data.get("reference", ""),
            payload=data.get("payload", {}),
            confidence=float(data.get("confidence", 1.0)),
            created_by=data.get("created_by", ""),
            id=data.get("id", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


class EvidenceBundle:
    """Ordered, de-duplicated evidence collection."""

    def __init__(self, items: Iterable[Evidence] | None = None):
        self._items: dict[str, Evidence] = {}
        for item in items or []:
            self.add(item)

    def add(self, evidence: Evidence) -> Evidence:
        if evidence.id not in self._items:
            self._items[evidence.id] = evidence
        return evidence

    def extend(self, evidence: Iterable[Evidence]) -> None:
        for item in evidence:
            self.add(item)

    def by_kind(self, kind: EvidenceKind) -> list[Evidence]:
        return [e for e in self._items.values() if e.kind == kind]

    def latest(self, n: int = 10) -> list[Evidence]:
        return sorted(self._items.values(), key=lambda e: e.created_at)[-n:]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items.values())

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._items.values()]

    @classmethod
    def from_list(cls, items: list[dict[str, Any]]) -> "EvidenceBundle":
        return cls(Evidence.from_dict(item) for item in items)
