"""Joern adapter with a deterministic source-index fallback."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models.evidence import EvidenceKind
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from .code_query import CodeIndex, CodeQueryTool


@dataclass
class JoernConfig:
    joern_bin: str = "joern"
    export_bin: str = "joern-export"
    timeout_seconds: int = 180
    enabled: bool = True


class JoernClient:
    def __init__(self, config: JoernConfig | None = None):
        self.config = config or JoernConfig()

    def available(self) -> bool:
        return self.config.enabled and bool(shutil.which(self.config.joern_bin))

    def export(self, source_root: str | Path, out_dir: str | Path) -> dict[str, Any]:
        if not self.available():
            return {"status": "unavailable", "reason": "joern binary not found"}
        root = Path(source_root)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        script = out / "export.sc"
        script.write_text(
            "\n".join(
                [
                    f'importCode("{root.as_posix()}")',
                    f'save("{out.as_posix()}/cpg.bin")',
                    "exit",
                ]
            ),
            encoding="utf-8",
        )
        try:
            proc = subprocess.run(
                [self.config.joern_bin, "--script", str(script)],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "error", "reason": str(exc)}
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "cpg": str(out / "cpg.bin"),
        }

    def query_methods(self, cpg_path: str | Path) -> list[dict[str, Any]]:
        """Read a method export if the CPG was exported to JSON/TSV."""
        path = Path(cpg_path)
        if path.suffix.lower() == ".json" and path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else data.get("methods", [])
        return []


class JoernTool(BaseTool):
    name = "joern"
    description = "Query Joern CPG for methods, call relations, data dependence, and slices."
    input_schema = {
        "type": "object",
        "properties": {
            "source_root": {"type": "string"},
            "application": {"type": "string"},
            "source_version": {"type": "string"},
            "action": {"enum": ["status", "export", "methods", "callgraph", "slice"]},
        },
    }

    def __init__(self, client: JoernClient | None = None, index: CodeIndex | None = None):
        self.client = client or JoernClient()
        self.index = index

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "status")
        if action == "status":
            return ToolResult(ok=True, data={"available": self.client.available()})
        if action == "export":
            result = self.client.export(kwargs["source_root"], ctx.workspace / "joern")
            return ToolResult(ok=result.get("status") == "ok", data=result)
        if self.index is None:
            if not kwargs.get("source_root"):
                return ToolResult(ok=False, error="source_root required")
            self.index = CodeIndex.build(
                kwargs["source_root"],
                kwargs.get("application", "unknown"),
                kwargs.get("source_version", "unknown"),
            )
        if action == "methods":
            data = [
                {
                    "name": f.name,
                    "file": f.file,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "calls": f.calls,
                }
                for f in self.index.functions.values()
            ]
            return ToolResult(
                ok=True,
                data={"methods": data},
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.SOURCE,
                        self.name,
                        f"method index: {len(data)} functions",
                        kwargs.get("application", "unknown"),
                    )
                ],
            )
        if action == "callgraph":
            return ToolResult(ok=True, data={"callgraph": {k: sorted(v) for k, v in self.index.call_graph.items()}})
        if action == "slice":
            funcs = self.index.find(kwargs.get("name", ""))
            if not funcs:
                return ToolResult(ok=False, error="function not found")
            func = funcs[0]
            return ToolResult(
                ok=True,
                data={
                    "slice": self.index.slice_for(func).to_dict(),
                    "callers": self.index.callers(func.name),
                    "callees": self.index.callees(func.name),
                },
            )
        return ToolResult(ok=False, error=f"unknown action: {action}")
