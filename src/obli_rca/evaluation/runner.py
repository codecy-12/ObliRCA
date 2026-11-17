"""Benchmark runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models.report import AnalysisReport
from ..models.scenario import BenchmarkManifest, Scenario
from ..online.pipeline import OnlinePipeline
from .metrics import ScenarioPrediction, aggregate


@dataclass
class EvaluationResult:
    predictions: list[ScenarioPrediction] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    skipped: list[dict[str, str]] = field(default_factory=list)
    reports: list[AnalysisReport] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics,
            "predictions": [p.to_dict() for p in self.predictions],
            "skipped": self.skipped,
            "reports": [r.to_dict() for r in self.reports],
        }


class BenchmarkRunner:
    def __init__(self, config: Config, *, use_llm: bool = False, dry_run: bool = True):
        self.config = config
        self.use_llm = use_llm
        self.dry_run = dry_run
        self.pipeline = OnlinePipeline(config, use_llm=use_llm, dry_run=dry_run)

    def run(
        self,
        manifest: BenchmarkManifest,
        *,
        log_dir: str | Path = "data/logs",
        source_dir: str | Path = "data/sources",
        ground_truth: dict[str, dict[str, Any]] | None = None,
    ) -> EvaluationResult:
        result = EvaluationResult()
        ground_truth = ground_truth or {}
        for scenario in manifest.scenarios:
            log_path = Path(log_dir) / f"{scenario.id}.sysdig"
            sources = _source_roots(scenario, Path(source_dir))
            if not log_path.exists() or not sources:
                result.skipped.append(
                    {"scenario": scenario.id, "reason": "logs or source roots missing"}
                )
                continue
            try:
                report = self.pipeline.run_scenario(
                    scenario,
                    log_path=log_path,
                    source_roots=sources,
                    source_versions=scenario.versions,
                )
            except Exception as exc:  # noqa: BLE001
                result.skipped.append({"scenario": scenario.id, "reason": str(exc)})
                continue
            result.reports.append(report)
            result.predictions.append(_prediction(report))
        result.metrics = aggregate(result.predictions, ground_truth)
        return result


def _prediction(report: AnalysisReport) -> ScenarioPrediction:
    functions: list[str] = []
    locations: list[str] = []
    roots: list[list[str]] = []
    for item in report.ranked:
        location = item.hypothesis.location
        if location.function and location.function not in functions:
            functions.append(location.function)
        loc = f"{location.file}:{location.line}"
        if loc not in locations:
            locations.append(loc)
        roots.append([loc])
    return ScenarioPrediction(
        scenario_id=report.scenario_id,
        ranked_functions=functions,
        ranked_locations=locations,
        ranked_roots=roots,
        explanation=report.ranked[0].explanation if report.ranked else "",
    )


def _source_roots(scenario: Scenario, source_dir: Path) -> dict[str, str]:
    roots: dict[str, str] = {}
    base = source_dir / scenario.id
    applications = scenario.applications
    if not applications and base.exists():
        applications = [child.name for child in base.iterdir() if child.is_dir()]
    for app in applications:
        candidate = base / app
        if candidate.exists():
            roots[app] = str(candidate)
    return roots
