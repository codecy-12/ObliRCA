"""Tool protocol, context, and registry."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..errors import BudgetExceeded, ToolError
from ..models.code import CodeFramework
from ..models.evidence import Evidence, EvidenceBundle, EvidenceKind


@dataclass
class ToolContext:
    config: Config
    investigation_id: str
    workspace: Path
    framework: CodeFramework
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    budget: int = 12
    calls: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def consume(self, amount: int = 1) -> None:
        if self.calls + amount > self.budget:
            raise BudgetExceeded(
                f"tool budget exhausted: {self.calls}/{self.budget} in {self.investigation_id}"
            )
        self.calls += amount

    def record(self, evidence: Evidence) -> None:
        self.evidence.add(evidence)

    def log(self, message: str) -> None:
        log_path = self.workspace / "tool.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    evidence: list[Evidence] = field(default_factory=list)
    error: str = ""
    tool: str = ""
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "data": self.data,
            "evidence": [e.to_dict() for e in self.evidence],
            "error": self.error,
            "tool": self.tool,
            "elapsed": self.elapsed,
        }


class BaseTool:
    name: str = "base"
    description: str = ""
    input_schema: dict[str, Any] = {"type": "object", "properties": {}}
    output_schema: dict[str, Any] = {"type": "object"}

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        raise NotImplementedError

    def safe_run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        ctx.consume()
        started = time.time()
        try:
            result = self.run(ctx, **kwargs)
            result.tool = self.name
            result.elapsed = time.time() - started
            for evidence in result.evidence:
                ctx.record(evidence)
            ctx.log(f"{self.name} ok in {result.elapsed:.2f}s")
            return result
        except BudgetExceeded:
            raise
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"{self.name} failed: {exc}\n{traceback.format_exc()}")
            return ToolResult(
                ok=False,
                error=str(exc),
                tool=self.name,
                elapsed=time.time() - started,
            )


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if not tool.name or tool.name in self._tools:
            raise ToolError(f"tool name missing or duplicated: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, tool_name: str) -> BaseTool:
        if tool_name not in self._tools:
            raise ToolError(f"unknown tool: {tool_name}")
        return self._tools[tool_name]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            }
            for tool in self._tools.values()
        ]

    def run(self, tool_name: str, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        return self.get(tool_name).safe_run(ctx, **kwargs)


def evidence_for_tool(
    kind: EvidenceKind,
    tool: str,
    summary: str,
    reference: str,
    payload: dict[str, Any] | None = None,
    confidence: float = 1.0,
) -> Evidence:
    return Evidence(
        kind=kind,
        summary=summary,
        reference=reference,
        payload=payload or {},
        confidence=confidence,
        created_by=tool,
    )
