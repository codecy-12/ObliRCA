"""Local symbolic verification with angr when available.

The Rank Agent uses this adapter for two gap types:
- insufficient existing protection: find a path that passes the existing check
  and still violates the obligation at the use point;
- missing necessary protection: find a reachable violating state with no check.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models.hypothesis import GapType, HypothesisStatus, VerificationResult
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from ..models.evidence import EvidenceKind


@dataclass
class AngrConfig:
    enabled: bool = False
    timeout_seconds: int = 60
    find_symbol: str = ""
    avoid_symbol: str = ""


class AngrChecker:
    def __init__(self, config: AngrConfig | None = None):
        self.config = config or AngrConfig()

    def available(self) -> bool:
        if not self.config.enabled:
            return False
        try:
            import angr  # noqa: F401
        except ImportError:
            return False
        return True

    def check(
        self,
        binary: str | Path,
        gap_type: GapType,
        find_addr: int | None = None,
        avoid_addr: int | None = None,
        constraints: list[str] | None = None,
    ) -> VerificationResult:
        if not self.available():
            return VerificationResult(
                hypothesis_id="",
                status=HypothesisStatus.UNRESOLVED,
                gap_type=gap_type,
                tool="angr",
                notes="angr backend unavailable or disabled; hypothesis remains unverified",
            )
        import angr  # type: ignore

        project = angr.Project(str(binary), auto_load_libs=False)
        find = find_addr if find_addr is not None else project.entry
        state = project.factory.entry_state()
        simgr = project.factory.simulation_manager(state)
        try:
            simgr.explore(find=find, avoid=avoid_addr, timeout=self.config.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(
                hypothesis_id="",
                status=HypothesisStatus.UNRESOLVED,
                gap_type=gap_type,
                tool="angr",
                notes=f"symbolic execution error: {exc}",
            )
        if simgr.found:
            return VerificationResult(
                hypothesis_id="",
                status=HypothesisStatus.VERIFIED,
                gap_type=gap_type,
                constraints=constraints or [],
                counterexample={"address": hex(simgr.found[0].addr)},
                tool="angr",
            )
        return VerificationResult(
            hypothesis_id="",
            status=HypothesisStatus.REFUTED,
            gap_type=gap_type,
            tool="angr",
            notes="no reachable violating state under the modeled scope",
        )


class AngrTool(BaseTool):
    name = "angr"
    description = "Run a local symbolic check on a semantics-preserving analysis binary."
    input_schema = {
        "type": "object",
        "properties": {
            "binary": {"type": "string"},
            "gap_type": {"enum": ["insufficient_existing", "missing_necessary"]},
            "find_addr": {"type": "integer"},
            "avoid_addr": {"type": "integer"},
            "constraints": {"type": "array", "items": {"type": "string"}},
        },
    }

    def __init__(self, checker: AngrChecker | None = None):
        self.checker = checker or AngrChecker()

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        binary = Path(kwargs["binary"])
        if not binary.exists():
            return ToolResult(ok=False, error=f"binary not found: {binary}")
        result = self.checker.check(
            binary,
            GapType(kwargs.get("gap_type", "missing_necessary")),
            kwargs.get("find_addr"),
            kwargs.get("avoid_addr"),
            kwargs.get("constraints"),
        )
        return ToolResult(
            ok=True,
            data=result.to_dict(),
            evidence=[
                evidence_for_tool(
                    EvidenceKind.SYMBOLIC,
                    self.name,
                    f"symbolic verification: {result.status.value}",
                    str(binary),
                    result.to_dict(),
                )
            ],
        )
