"""Assessment Agent: fresh-session localization of a candidate entry."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models.code import CodeLocation
from ..models.obligation import ObligationEntry
from ..models.scenario import Scenario
from ..storage.investigation_store import InvestigationStore
from ..tools.base import ToolRegistry
from ..tools.log_query import LogIndex
from .corpus import CorpusCase


@dataclass
class AssessmentResult:
    status: str
    action: str = "noop"
    ranked: list[dict[str, Any]] = field(default_factory=list)
    top_k: int = 5
    top_k_hit: bool = False
    hit_rank: int | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "action": self.action,
            "ranked": self.ranked,
            "top_k": self.top_k,
            "top_k_hit": self.top_k_hit,
            "hit_rank": self.hit_rank,
            "notes": self.notes,
        }


class AssessmentAgent:
    def __init__(
        self,
        config: Config,
        tools: ToolRegistry,
        investigation_store: InvestigationStore,
        *,
        use_llm: bool = False,
    ):
        self.config = config
        self.tools = tools
        self.investigation_store = investigation_store
        self.use_llm = use_llm

    def assess(
        self,
        candidate: ObligationEntry,
        case: CorpusCase,
        *,
        log_path: str | Path | None = None,
        source_roots: dict[str, str] | None = None,
        source_versions: dict[str, str] | None = None,
        symptom_event_id: str | None = None,
        top_k: int | None = None,
    ) -> AssessmentResult:
        if not log_path or not source_roots:
            return AssessmentResult(
                "skipped",
                notes="assessment requires vulnerable-version logs and source roots",
                top_k=top_k or 5,
            )
        from ..online.localization_agent import LocalizationAgent
        from ..online.pipeline import OnlineScheduler
        from ..llm.client import LLMClient

        investigation_id = f"assess-{case.case_id}"
        localization = LocalizationAgent(
            self.config,
            self.tools,
            self.investigation_store,
            investigation_id,
            source_roots=source_roots,
            source_versions=source_versions or {},
            workspace=Path("data") / "assessments" / investigation_id,
        )
        index = localization.load_logs(log_path)
        event_id = symptom_event_id or (index.events[0].event_id if index.events else None)
        if event_id is None:
            return AssessmentResult("skipped", notes="no events in vulnerable log")
        app = case.metadata.get("symptom_app") or next(iter(source_roots))
        try:
            localization.initialize(
                app,
                event_id,
                source_root=source_roots.get(app),
                source_version=(source_versions or {}).get(app),
            )
        except Exception as exc:  # noqa: BLE001
            return AssessmentResult("failed", notes=f"localization failed: {exc}")
        scheduler = OnlineScheduler(
            self.config,
            self.tools,
            self.investigation_store,
            localization,
            [candidate],
            investigation_id,
            llm=LLMClient(self.config, mock=not self.use_llm),
            use_llm=self.use_llm,
            max_parallel=1,
        )
        result = scheduler.run()
        ranked = [item.to_dict() for item in result.rank_result.verified]
        top_k = top_k or int(self.config.get("offline.top_k.cross_program", 5))
        hit_rank = _hit_rank(ranked, case.ground_truth)
        return AssessmentResult(
            "ok",
            action="localized",
            ranked=ranked,
            top_k=top_k,
            top_k_hit=bool(hit_rank and hit_rank <= top_k),
            hit_rank=hit_rank,
            notes=f"{len(ranked)} verified candidates; top-{top_k} checked",
        )


def _hit_rank(ranked: list[dict[str, Any]], ground_truth: list[dict[str, Any]]) -> int | None:
    if not ground_truth:
        return None
    targets = []
    for item in ground_truth:
        for loc in item.get("locations", []) if isinstance(item, dict) else []:
            targets.append(str(loc))
        if isinstance(item, dict) and item.get("location"):
            targets.append(str(item["location"]))
    for index, candidate in enumerate(ranked, start=1):
        hypothesis = candidate.get("hypothesis", {})
        location = hypothesis.get("location", {})
        text = f"{location.get('file', '')}:{location.get('line', 0)}"
        if any(target in text or text in target for target in targets):
            return index
    return None
