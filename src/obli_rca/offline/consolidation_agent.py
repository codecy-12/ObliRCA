"""Consolidation Agent: top-K membership, entry verification, library update."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models.evidence import Evidence, EvidenceKind
from ..models.obligation import ObligationEntry
from ..storage.obligation_store import ObligationStore
from .assessment_agent import AssessmentResult
from .corpus import CorpusCase


@dataclass
class ConsolidationResult:
    status: str
    action: str = "noop"
    entry_id: str = ""
    reason: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "action": self.action,
            "entry_id": self.entry_id,
            "reason": self.reason,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class ConsolidationAgent:
    def __init__(self, config: Config, store: ObligationStore, *, human_queue: str | Path | None = None):
        self.config = config
        self.store = store
        self.human_queue = Path(human_queue or config.get("offline.human_queue", "data/human_review_queue.jsonl"))

    def consolidate(
        self,
        candidate: ObligationEntry,
        case: CorpusCase,
        assessment: AssessmentResult,
    ) -> ConsolidationResult:
        # 1. Abstractness and structure checks.
        try:
            candidate.validate(strict_abstractness=bool(self.config.get("offline.acceptance.forbid_concrete_identifiers", True)))
        except Exception as exc:  # noqa: BLE001
            return ConsolidationResult("rejected", reason=f"entry invalid: {exc}")
        # 2. Top-K membership.
        if assessment.status == "skipped":
            return ConsolidationResult(
                "skipped",
                reason="assessment was skipped; entry retained as candidate only",
                entry_id=candidate.id,
            )
        if not assessment.top_k_hit:
            return ConsolidationResult(
                "revision",
                reason=f"ground truth not in top-{assessment.top_k} (hit rank: {assessment.hit_rank})",
                entry_id=candidate.id,
            )
        # 3. Merge by semantic structure or create a new entry.
        existing = self.store.find_semantic(candidate.semantic_hash())
        if existing is None:
            existing = next(
                (e for e in self.store.find_by_category(candidate.category) if e.conditions.must == candidate.conditions.must),
                None,
            )
        if existing is not None:
            existing.provenance.source_cases += 1
            existing.provenance.graph_count = len(existing.graphs)
            existing.provenance.revision_count = candidate.provenance.revision_count
            self.store.save(existing)
            self.store.add_case(existing.id, case.case_id, "source", case.project)
            return ConsolidationResult(
                "accepted",
                action="enriched",
                entry_id=existing.id,
                reason="same obligation; added a new source case",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.REVIEW,
                        summary=f"enriched {existing.id} with {case.case_id}",
                        reference=case.case_id,
                        created_by="consolidation",
                    )
                ],
            )
        candidate.provenance.accepted_round = 1
        candidate.provenance.source_cases = max(1, candidate.provenance.source_cases)
        self.store.save(candidate)
        self.store.add_case(candidate.id, case.case_id, "source", case.project)
        return ConsolidationResult(
            "accepted",
            action="created",
            entry_id=candidate.id,
            reason="new obligation category entry",
        )

    def enqueue_human(self, candidate: ObligationEntry, reason: str) -> None:
        self.human_queue.parent.mkdir(parents=True, exist_ok=True)
        with self.human_queue.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {"entry": candidate.to_dict(), "reason": reason},
                    ensure_ascii=False,
                )
                + "\n"
            )
