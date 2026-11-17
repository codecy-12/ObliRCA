"""Parallel SOI scheduling and online orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Config
from ..llm.client import LLMClient
from ..models.code import CodeFramework
from ..models.hypothesis import FeedbackRequest, Hypothesis
from ..models.obligation import ObligationEntry
from ..models.report import AnalysisReport, CostSummary
from ..models.scenario import Scenario
from ..storage.investigation_store import InvestigationStore
from ..storage.obligation_store import ObligationStore
from ..tools.base import ToolRegistry
from ..tools.registry import build_registry
from .localization_agent import LocalizationAgent
from .rank_agent import RankAgent
from .soi import SecurityObligationInspector, SoiResult


@dataclass
class SchedulerResult:
    soi_results: list[SoiResult]
    hypotheses: list[Hypothesis]
    rank_result: Any


class OnlineScheduler:
    def __init__(
        self,
        config: Config,
        tools: ToolRegistry,
        store: InvestigationStore,
        localization: LocalizationAgent,
        entries: list[ObligationEntry],
        investigation_id: str,
        *,
        llm: LLMClient | None = None,
        use_llm: bool = False,
        max_parallel: int | None = None,
    ):
        self.config = config
        self.tools = tools
        self.store = store
        self.localization = localization
        self.entries = entries
        self.investigation_id = investigation_id
        self.llm = llm or LLMClient(config, mock=not use_llm)
        self.use_llm = use_llm
        self.max_parallel = max_parallel or int(config.get("online.soi.max_parallel", 10))
        self._soi_by_entry: dict[str, SecurityObligationInspector] = {}

    # ------------------------------------------------------------------
    def run(self) -> SchedulerResult:
        results: list[SoiResult] = []
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            futures = {
                pool.submit(self._run_one, entry): entry
                for entry in self.entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        SoiResult(False, entry.id, reason=f"SOI failed: {exc}")
                    )
        hypotheses = [h for result in results for h in result.hypotheses]
        obligations = {entry.id: entry for entry in self.entries}
        rank = RankAgent(
            self.config,
            self.tools,
            self.store,
            self.investigation_id,
            obligations,
            workspace=self.localization.workspace / "rank",
            llm=self.llm,
            use_llm=self.use_llm,
            feedback_handler=self._feedback,
        )
        rank_result = rank.run(hypotheses)
        return SchedulerResult(results, hypotheses, rank_result)

    def _run_one(self, entry: ObligationEntry) -> SoiResult:
        soi = SecurityObligationInspector(
            entry,
            self.localization.framework,
            self.tools,
            self.store,
            self.localization,
            config=self.config,
            llm=self.llm,
            investigation_id=self.investigation_id,
            workspace=str(self.localization.workspace / f"soi_{entry.id}"),
            budget=int(self.config.get("online.soi.tool_budget", 12)),
            use_llm=self.use_llm,
        )
        self._soi_by_entry[entry.id] = soi
        return soi.run()

    def _feedback(self, request: FeedbackRequest) -> Hypothesis | None:
        for soi in self._soi_by_entry.values():
            if any(h.id == request.hypothesis_id for h in soi.hypotheses):
                return soi.handle_feedback(request)
        return None


class OnlinePipeline:
    def __init__(
        self,
        config: Config | None = None,
        *,
        use_llm: bool = False,
        dry_run: bool = True,
    ):
        self.config = config or Config.load()
        self.use_llm = use_llm
        self.dry_run = dry_run
        self.tools = build_registry(self.config, dry_run=dry_run)
        from ..storage.database import Database

        self.db = Database(self.config.db_url)
        self.obligation_store = ObligationStore(self.db)
        self.investigation_store = InvestigationStore(self.db)
        self.llm = LLMClient(self.config, mock=not use_llm)

    def run_scenario(
        self,
        scenario: Scenario,
        *,
        log_path: str | Path,
        source_roots: dict[str, str],
        source_versions: dict[str, str] | None = None,
        binary: str | None = None,
        max_parallel: int | None = None,
    ) -> AnalysisReport:
        investigation_id = f"inv-{scenario.id}"
        entries = self.obligation_store.list(status="accepted")
        if not entries:
            raise RuntimeError("obligation library is empty; run init-db/import first")
        localization = LocalizationAgent(
            self.config,
            self.tools,
            self.investigation_store,
            investigation_id,
            source_roots=source_roots,
            source_versions=source_versions or scenario.versions,
            workspace=Path("data") / "investigations" / investigation_id,
        )
        localization.load_logs(log_path)
        symptom = scenario.symptom
        if symptom is None:
            raise ValueError(f"scenario {scenario.id} has no symptom")
        init = localization.initialize(
            symptom.application,
            symptom.event_id,
            source_root=source_roots.get(symptom.application),
            source_version=(source_versions or {}).get(symptom.application),
        )
        scheduler = OnlineScheduler(
            self.config,
            self.tools,
            self.investigation_store,
            localization,
            entries,
            investigation_id,
            llm=self.llm,
            use_llm=self.use_llm,
            max_parallel=max_parallel,
        )
        result = scheduler.run()
        report = AnalysisReport(
            investigation_id=investigation_id,
            scenario_id=scenario.id,
            ranked=result.rank_result.verified,
            unresolved=[h.mechanism for h in result.rank_result.unresolved],
            framework_nodes=localization.framework.size(),
            applications=localization.framework.applications(),
            evidence_count=len(localization.ctx.evidence),
            cost=CostSummary(
                llm_calls=self.llm.usage.calls,
                input_tokens=self.llm.usage.input_tokens,
                output_tokens=self.llm.usage.output_tokens,
                tool_calls=localization.ctx.calls,
            ),
            metadata={
                "initial": init,
                "active_sois": sum(1 for r in result.soi_results if r.active),
                "scenario_group": scenario.group.value,
            },
        )
        self.investigation_store.finish(investigation_id)
        return report
