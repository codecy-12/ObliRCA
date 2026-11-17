"""Lightweight inter-procedural taint paths for SOI queries.

This is not a full points-to analysis.  It connects source-like functions
(receive/read/open) to sink-like functions (copy/write/exec) through the call
graph and records sanitizer-like functions on the path.  The result is a
candidate set for the SOI to verify, not a root-cause claim.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from .code_query import CodeIndex
from ..models.evidence import EvidenceKind

SOURCE_PATTERNS = [
    r"\brecv(?:from|msg)?\s*\(",
    r"\bread\s*\(",
    r"\bopen(?:at)?\s*\(",
    r"\bscanf\s*\(",
    r"\bgetenv\s*\(",
]

SINK_PATTERNS = [
    r"\bmemcpy\s*\(",
    r"\bmemmove\s*\(",
    r"\bstrcpy\s*\(",
    r"\bstrcat\s*\(",
    r"\bwrite(?:v)?\s*\(",
    r"\bsend(?:to|msg|file)?\s*\(",
    r"\bsystem\s*\(",
    r"\bexec\w*\s*\(",
    r"\beval\s*\(",
]

SANITIZER_PATTERNS = [
    r"\b(check|validate|verify|sanitize|escape|bound|limit|canonical|normalize)\w*\s*\(",
    r"\bif\s*\([^)]*(?:len|size|offset|count|range|root|auth|policy)",
]


@dataclass
class TaintPath:
    source: str
    sink: str
    functions: list[str]
    sanitizers: list[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "functions": self.functions,
            "sanitizers": self.sanitizers,
            "score": self.score,
        }


class TaintAnalyzer:
    def __init__(self, index: CodeIndex, max_depth: int = 6):
        self.index = index
        self.max_depth = max_depth

    def sources(self) -> list[str]:
        return [
            name
            for name in self.index.by_name
            if any(_any_pattern(func.text, SOURCE_PATTERNS) for func in self.index.find(name))
        ]

    def sinks(self) -> list[str]:
        return [
            name
            for name in self.index.by_name
            if any(_any_pattern(func.text, SINK_PATTERNS) for func in self.index.find(name))
        ]

    def sanitizers(self, functions: Iterable[str]) -> list[str]:
        result = []
        for name in functions:
            funcs = self.index.find(name)
            if any(_any_pattern(func.text, SANITIZER_PATTERNS) for func in funcs):
                result.append(name)
        return result

    def paths(self, max_paths: int = 32) -> list[TaintPath]:
        sources = set(self.sources())
        sinks = set(self.sinks())
        results: list[TaintPath] = []
        for source in sources:
            queue = deque([(source, [source])])
            while queue and len(results) < max_paths:
                current, path = queue.popleft()
                if len(path) > self.max_depth:
                    continue
                if current in sinks and current != source:
                    sanitizers = self.sanitizers(path)
                    score = 1.0 - 0.1 * max(0, len(path) - 2) - 0.15 * len(sanitizers)
                    results.append(
                        TaintPath(source, current, path, sanitizers, round(max(0.05, score), 3))
                    )
                    continue
                for callee in sorted(self.index.callees(current)):
                    if callee in path:
                        continue
                    queue.append((callee, path + [callee]))
        results.sort(key=lambda item: item.score, reverse=True)
        return results[:max_paths]


class TaintTool(BaseTool):
    name = "taint"
    description = "Find source-to-sink call paths and sanitizer-like functions."
    input_schema = {
        "type": "object",
        "properties": {
            "source_root": {"type": "string"},
            "application": {"type": "string"},
            "source_version": {"type": "string"},
            "max_paths": {"type": "integer", "default": 32},
        },
    }

    def __init__(self, index: CodeIndex | None = None):
        self.index = index

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        if self.index is None:
            if not kwargs.get("source_root"):
                return ToolResult(ok=False, error="source_root required")
            self.index = CodeIndex.build(
                kwargs["source_root"],
                kwargs.get("application", "unknown"),
                kwargs.get("source_version", "unknown"),
            )
        analyzer = TaintAnalyzer(self.index)
        paths = analyzer.paths(int(kwargs.get("max_paths", 32)))
        return ToolResult(
            ok=True,
            data={
                "sources": analyzer.sources(),
                "sinks": analyzer.sinks(),
                "paths": [path.to_dict() for path in paths],
            },
            evidence=[
                evidence_for_tool(
                    EvidenceKind.SOURCE,
                    self.name,
                    f"taint paths: {len(paths)}",
                    kwargs.get("application", "unknown"),
                    {"paths": len(paths)},
                )
            ],
        )


def _any_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.I) for pattern in patterns)
