"""Offline data flywheel orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..storage.obligation_store import ObligationStore
from .assessment_agent import AssessmentAgent
from .consolidation_agent import ConsolidationAgent
from .corpus import Corpus, CorpusCase
from .extraction_agent import ExtractionAgent


@dataclass
class FlywheelStats:
    cases: int = 0
    first_round: int = 0
    revised: int = 0
    manual: int = 0
    created: int = 0
    enriched: int = 0
    skipped: int = 0
    rejected: int = 0
    revisions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "first_round": self.first_round,
            "revised": self.revised,
            "manual": self.manual,
            "created": self.created,
            "enriched": self.enriched,
            "skipped": self.skipped,
            "rejected": self.rejected,
            "revisions": self.revisions,
        }


@dataclass
class FlywheelResult:
    stats: FlywheelStats
    records: list[dict[str, Any]] = field(default_factory=list)


class DataFlywheel:
    def __init__(
        self,
        config: Config,
        extraction: ExtractionAgent,
        assessment: AssessmentAgent,
        consolidation: ConsolidationAgent,
        store: ObligationStore,
    ):
        self.config = config
        self.extraction = extraction
        self.assessment = assessment
        self.consolidation = consolidation
        self.store = store
        self.max_revisions = int(config.get("offline.max_revisions", 3))

    def run(
        self,
        corpus: Corpus,
        *,
        dry_run: bool = True,
        log_paths: dict[str, str] | None = None,
        source_roots: dict[str, dict[str, str]] | None = None,
    ) -> FlywheelResult:
        stats = FlywheelStats()
        records: list[dict[str, Any]] = []
        for case in corpus:
            stats.cases += 1
            record = self._run_case(case, stats, dry_run, log_paths or {}, source_roots or {})
            records.append(record)
        return FlywheelResult(stats, records)

    def _run_case(
        self,
        case: CorpusCase,
        stats: FlywheelStats,
        dry_run: bool,
        log_paths: dict[str, str],
        source_roots: dict[str, dict[str, str]],
    ) -> dict[str, Any]:
        extraction = self.extraction.extract(case)
        if extraction.entry is None:
            stats.rejected += 1
            return {"case": case.case_id, "status": "rejected", "stage": "extraction"}
        candidate = extraction.entry
        assessment = self.assessment.assess(
            candidate,
            case,
            log_path=log_paths.get(case.case_id),
            source_roots=source_roots.get(case.case_id),
            source_versions={
                k: v for k, v in {
                    case.project: case.vulnerable_version,
                }.items() if k
            },
            top_k=int(self.config.get("offline.top_k.cross_program", 5)),
        )
        if assessment.status == "skipped":
            stats.skipped += 1
            return {
                "case": case.case_id,
                "status": "skipped",
                "reason": assessment.notes,
                "entry_id": candidate.id,
            }
        for round_index in range(1, self.max_revisions + 1):
            stats.revisions += 1
            result = self.consolidation.consolidate(candidate, case, assessment)
            if result.status == "accepted":
                if round_index == 1:
                    stats.first_round += 1
                else:
                    stats.revised += 1
                if result.action == "created":
                    stats.created += 1
                else:
                    stats.enriched += 1
                return {
                    "case": case.case_id,
                    "status": "accepted",
                    "round": round_index,
                    "action": result.action,
                    "entry_id": result.entry_id,
                }
            if result.status == "revision" and round_index < self.max_revisions:
                # A real system asks the Extraction Agent to revise the entry;
                # the reference implementation records the attempt and retries
                # the same structural candidate when no model revision is run.
                continue
            if result.status == "revision":
                stats.manual += 1
                self.consolidation.enqueue_human(candidate, result.reason)
                return {
                    "case": case.case_id,
                    "status": "manual",
                    "reason": result.reason,
                    "entry_id": candidate.id,
                }
            stats.rejected += 1
            return {"case": case.case_id, "status": "rejected", "reason": result.reason}
        stats.manual += 1
        return {"case": case.case_id, "status": "manual", "entry_id": candidate.id}
