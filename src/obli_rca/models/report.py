"""Analysis reports and result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .hypothesis import RankedHypothesis


@dataclass
class CostSummary:
    elapsed_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    llm_calls: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": self.elapsed_seconds,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
        }


@dataclass
class AnalysisReport:
    investigation_id: str
    scenario_id: str
    ranked: list[RankedHypothesis] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    framework_nodes: int = 0
    applications: list[str] = field(default_factory=list)
    evidence_count: int = 0
    cost: CostSummary = field(default_factory=CostSummary)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "scenario_id": self.scenario_id,
            "ranked": [r.to_dict() for r in self.ranked],
            "unresolved": self.unresolved,
            "framework_nodes": self.framework_nodes,
            "applications": self.applications,
            "evidence_count": self.evidence_count,
            "cost": self.cost.to_dict(),
            "metadata": self.metadata,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# ObliRCA report: {self.scenario_id}",
            "",
            f"- investigation: `{self.investigation_id}`",
            f"- applications: {', '.join(self.applications) or '—'}",
            f"- framework nodes: {self.framework_nodes}",
            f"- evidence records: {self.evidence_count}",
            f"- elapsed: {self.cost.elapsed_seconds:.2f}s; tokens: {self.cost.total_tokens}",
            "",
            "## Ranked root causes",
            "",
        ]
        if not self.ranked:
            lines.append("No confirmed root cause. The investigation retained unresolved candidates.")
        for item in self.ranked:
            h = item.hypothesis
            lines.extend(
                [
                    f"### {item.rank}. {h.location.file}:{h.location.line} "
                    f"`{h.location.function}`",
                    "",
                    f"- obligation: `{h.obligation_id}` ({item.obligation_name})",
                    f"- gap type: `{h.gap_type.value}`",
                    f"- mechanism: {h.mechanism}",
                    f"- explanation: {item.explanation}",
                    f"- fix suggestion: {item.fix_suggestion}",
                    "",
                ]
            )
        if self.unresolved:
            lines.extend(["## Unresolved", ""])
            lines.extend(f"- {item}" for item in self.unresolved)
        return "\n".join(lines) + "\n"
