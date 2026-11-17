"""Source-code and shared-framework models."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class CodeLocation:
    file: str
    function: str = ""
    line: int = 0
    column: int = 0
    snippet: str = ""

    @property
    def key(self) -> str:
        return f"{self.file}:{self.function}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass
class SyscallSite:
    syscall: str
    line: int
    expression: str = ""
    aliases: list[str] = field(default_factory=list)

    def matches(self, syscall: str) -> bool:
        names = {self.syscall, *self.aliases}
        return syscall in names or self.syscall == syscall


@dataclass
class BasicBlock:
    id: str
    function: str
    file: str
    start_line: int
    end_line: int
    instructions: list[str] = field(default_factory=list)
    sites: list[SyscallSite] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "function": self.function,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "instructions": self.instructions,
            "sites": [
                {"syscall": s.syscall, "line": s.line, "expression": s.expression}
                for s in self.sites
            ],
            "successors": self.successors,
            "summary": self.summary,
        }


@dataclass
class CFGPath:
    blocks: list[BasicBlock]
    events: list[str]
    score: float = 0.0
    evidence: list[str] = field(default_factory=list)

    @property
    def functions(self) -> list[str]:
        return _dedupe([b.function for b in self.blocks])

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocks": [b.id for b in self.blocks],
            "functions": self.functions,
            "events": self.events,
            "score": self.score,
            "evidence": self.evidence,
        }


@dataclass
class FunctionSlice:
    application: str
    source_version: str
    file: str
    function: str
    start_line: int
    end_line: int
    statements: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    block_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "source_version": self.source_version,
            "file": self.file,
            "function": self.function,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "statements": self.statements,
            "callers": self.callers,
            "callees": self.callees,
            "event_ids": self.event_ids,
            "block_ids": self.block_ids,
        }


@dataclass
class FrameworkNode:
    id: str
    application: str
    source_version: str
    file: str
    function: str
    start_line: int
    end_line: int
    kind: str = "function"
    snippet: str = ""
    event_ids: list[str] = field(default_factory=list)
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def location(self) -> CodeLocation:
        return CodeLocation(self.file, self.function, self.start_line, snippet=self.snippet)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "application": self.application,
            "source_version": self.source_version,
            "file": self.file,
            "function": self.function,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "kind": self.kind,
            "snippet": self.snippet,
            "event_ids": self.event_ids,
            "parent_id": self.parent_id,
            "metadata": self.metadata,
        }


class CodeFramework:
    """Append-only shared code framework used by all SOIs."""

    def __init__(self, investigation_id: str):
        self.investigation_id = investigation_id
        self._nodes: dict[str, FrameworkNode] = {}
        self._event_index: dict[str, list[str]] = {}
        self._function_index: dict[tuple[str, str], list[str]] = {}

    # ---- mutation -------------------------------------------------------
    def add_node(self, node: FrameworkNode) -> FrameworkNode:
        if node.id in self._nodes:
            existing = self._nodes[node.id]
            # Keep the first version; the framework only grows.
            return existing
        self._nodes[node.id] = node
        for event_id in node.event_ids:
            self._event_index.setdefault(event_id, []).append(node.id)
        self._function_index.setdefault((node.application, node.function), []).append(node.id)
        return node

    def add_slice(self, slice_: FunctionSlice) -> FrameworkNode:
        node_id = _stable_id(
            "fn", slice_.application, slice_.source_version, slice_.file, slice_.function
        )
        node = FrameworkNode(
            id=node_id,
            application=slice_.application,
            source_version=slice_.source_version,
            file=slice_.file,
            function=slice_.function,
            start_line=slice_.start_line,
            end_line=slice_.end_line,
            kind="function_slice",
            snippet="\n".join(slice_.statements),
            event_ids=list(slice_.event_ids),
            metadata={
                "callers": slice_.callers,
                "callees": slice_.callees,
                "block_ids": slice_.block_ids,
            },
        )
        return self.add_node(node)

    # ---- queries --------------------------------------------------------
    def nodes(self) -> list[FrameworkNode]:
        return list(self._nodes.values())

    def get(self, node_id: str) -> FrameworkNode | None:
        return self._nodes.get(node_id)

    def by_event(self, event_id: str) -> list[FrameworkNode]:
        return [self._nodes[n] for n in self._event_index.get(event_id, [])]

    def by_function(self, application: str, function: str) -> list[FrameworkNode]:
        return [self._nodes[n] for n in self._function_index.get((application, function), [])]

    def applications(self) -> list[str]:
        return _dedupe([n.application for n in self._nodes.values()])

    def source_versions(self) -> dict[str, str]:
        return {n.application: n.source_version for n in self._nodes.values()}

    def contains(self, file: str, function: str) -> bool:
        return any(n.file == file and n.function == function for n in self._nodes.values())

    def size(self) -> int:
        return len(self._nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeFramework":
        framework = cls(data["investigation_id"])
        for item in data.get("nodes", []):
            framework.add_node(FrameworkNode(**item))
        return framework


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p) for p in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(raw).hexdigest()[:12]}"


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
