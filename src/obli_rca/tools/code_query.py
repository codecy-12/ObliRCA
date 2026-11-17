"""Source-code queries used by SOIs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models.code import CodeLocation, FunctionSlice
from ..models.evidence import EvidenceKind
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from .syscall_cfg import SourceFunction, extract_functions, iter_source_files


@dataclass
class CodeIndex:
    root: Path
    application: str
    source_version: str
    functions: dict[str, SourceFunction] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=dict)
    call_graph: dict[str, set[str]] = field(default_factory=dict)
    reverse_calls: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        root: str | Path,
        application: str,
        source_version: str,
        max_files: int = 500,
    ) -> "CodeIndex":
        root_path = Path(root)
        index = cls(root_path, application, source_version)
        for path in iter_source_files(root_path)[:max_files]:
            for func in extract_functions(path, root_path, application, source_version):
                key = f"{func.file}:{func.name}:{func.start_line}"
                index.functions[key] = func
                index.by_name.setdefault(func.name, []).append(key)
                index.call_graph.setdefault(func.name, set()).update(func.calls)
                for callee in func.calls:
                    index.reverse_calls.setdefault(callee, set()).add(func.name)
        return index

    def find(self, name: str) -> list[SourceFunction]:
        return [self.functions[k] for k in self.by_name.get(name, [])]

    def at(self, file: str, line: int) -> SourceFunction | None:
        for func in self.functions.values():
            if func.file == file and func.start_line <= line <= func.end_line:
                return func
        return None

    def callers(self, name: str) -> list[str]:
        return sorted(self.reverse_calls.get(name, set()))

    def callees(self, name: str) -> list[str]:
        return sorted(self.call_graph.get(name, set()))

    def snippet(self, func: SourceFunction, limit: int = 4000) -> str:
        return func.text[:limit]

    def search(self, pattern: str, limit: int = 50) -> list[dict[str, Any]]:
        regex = re.compile(pattern, re.I)
        results: list[dict[str, Any]] = []
        for key, func in self.functions.items():
            if regex.search(func.text) or regex.search(func.name):
                results.append(
                    {
                        "function": func.name,
                        "file": func.file,
                        "start_line": func.start_line,
                        "end_line": func.end_line,
                        "key": key,
                    }
                )
            if len(results) >= limit:
                break
        return results

    def slice_for(self, func: SourceFunction, event_ids: list[str] | None = None) -> FunctionSlice:
        return FunctionSlice(
            application=self.application,
            source_version=self.source_version,
            file=func.file,
            function=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            statements=func.text.splitlines(),
            callers=self.callers(func.name),
            callees=self.callees(func.name),
            event_ids=event_ids or [],
        )


class CodeQueryTool(BaseTool):
    name = "code_query"
    description = "Look up functions, callers/callees, snippets, and source slices."
    input_schema = {
        "type": "object",
        "properties": {
            "source_root": {"type": "string"},
            "application": {"type": "string"},
            "source_version": {"type": "string"},
            "action": {"enum": ["function", "callers", "callees", "snippet", "search", "slice"]},
            "name": {"type": "string"},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "pattern": {"type": "string"},
        },
    }

    def __init__(self, index: CodeIndex | None = None):
        self.index = index

    def ensure(self, kwargs: dict[str, Any]) -> CodeIndex:
        if self.index is None:
            if not kwargs.get("source_root"):
                raise ValueError("source_root required")
            self.index = CodeIndex.build(
                kwargs["source_root"],
                kwargs.get("application", "unknown"),
                kwargs.get("source_version", "unknown"),
            )
        return self.index

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        index = self.ensure(kwargs)
        action = kwargs.get("action", "function")
        if action == "function":
            funcs = index.find(kwargs["name"])
            return ToolResult(
                ok=True,
                data=[_func_dict(f) for f in funcs],
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.SOURCE,
                        self.name,
                        f"function lookup: {kwargs['name']} ({len(funcs)} hits)",
                        kwargs["name"],
                    )
                ],
            )
        if action == "callers":
            names = index.callers(kwargs["name"])
            return ToolResult(ok=True, data={"callers": names})
        if action == "callees":
            names = index.callees(kwargs["name"])
            return ToolResult(ok=True, data={"callees": names})
        if action == "snippet":
            func = index.at(kwargs.get("file", ""), int(kwargs.get("line", 0)))
            if func is None and kwargs.get("name"):
                funcs = index.find(kwargs["name"])
                func = funcs[0] if funcs else None
            if func is None:
                return ToolResult(ok=False, error="function not found")
            return ToolResult(
                ok=True,
                data={
                    "function": func.name,
                    "file": func.file,
                    "start_line": func.start_line,
                    "end_line": func.end_line,
                    "snippet": index.snippet(func),
                },
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.SOURCE,
                        self.name,
                        f"source snippet: {func.name}",
                        f"{func.file}:{func.start_line}",
                    )
                ],
            )
        if action == "search":
            results = index.search(kwargs["pattern"])
            return ToolResult(ok=True, data={"results": results})
        if action == "slice":
            func = index.at(kwargs.get("file", ""), int(kwargs.get("line", 0)))
            if func is None:
                return ToolResult(ok=False, error="function not found")
            slice_ = index.slice_for(func, kwargs.get("event_ids"))
            return ToolResult(
                ok=True,
                data={"slice": slice_.to_dict()},
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.SOURCE,
                        self.name,
                        f"function slice: {func.name}",
                        f"{func.file}:{func.start_line}",
                    )
                ],
            )
        return ToolResult(ok=False, error=f"unknown action: {action}")


def _func_dict(func: SourceFunction) -> dict[str, Any]:
    return {
        "name": func.name,
        "file": func.file,
        "start_line": func.start_line,
        "end_line": func.end_line,
        "sites": [{"syscall": s.syscall, "line": s.line} for s in func.sites],
    }
