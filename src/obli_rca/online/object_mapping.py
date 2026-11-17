"""Role binding between obligation graphs and current source objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ..models.code import CodeFramework, FrameworkNode
from ..models.obligation import ObligationEntry


class BindingState(str, Enum):
    BOUND = "bound"
    PENDING = "pending"
    REFUTED = "refuted"


@dataclass
class RoleBinding:
    role: str
    state: BindingState
    node_id: str = ""
    symbol: str = ""
    line: int = 0
    evidence: str = ""
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "state": self.state.value,
            "node_id": self.node_id,
            "symbol": self.symbol,
            "line": self.line,
            "evidence": self.evidence,
            "score": self.score,
        }


@dataclass
class MappingResult:
    bindings: dict[str, RoleBinding] = field(default_factory=dict)
    unbound: list[str] = field(default_factory=list)
    graph_usable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "bindings": {k: v.to_dict() for k, v in self.bindings.items()},
            "unbound": self.unbound,
            "graph_usable": self.graph_usable,
        }


class ObjectMapper:
    """Bind abstract roles to source nodes using names, types, and context."""

    def __init__(self, entry: ObligationEntry):
        self.entry = entry

    def bind(self, framework: CodeFramework) -> MappingResult:
        result = MappingResult()
        for role_name, role in self.entry.roles.items():
            keywords = _keywords(role_name, role.description)
            best = self._best_node(framework.nodes(), keywords, role.kind)
            if best is None:
                result.bindings[role_name] = RoleBinding(role_name, BindingState.PENDING)
                result.unbound.append(role_name)
                continue
            node, score, evidence = best
            symbol, line = self._symbol_at(node, keywords)
            result.bindings[role_name] = RoleBinding(
                role=role_name,
                state=BindingState.BOUND,
                node_id=node.id,
                symbol=symbol,
                line=line,
                evidence=evidence,
                score=score,
            )
        result.graph_usable = all(
            binding.state == BindingState.BOUND
            for name, binding in result.bindings.items()
            if name in self._key_roles()
        )
        return result

    def rebind(
        self,
        framework: CodeFramework,
        previous: MappingResult,
        new_nodes: Iterable[FrameworkNode] | None = None,
    ) -> MappingResult:
        # The mapper is stateless; a rebind is a fresh pass over the enlarged
        # framework.  ``previous`` is retained so callers can diff bindings.
        refreshed = self.bind(framework)
        if previous is not None:
            for name, binding in previous.bindings.items():
                if binding.state == BindingState.REFUTED and name in refreshed.bindings:
                    refreshed.bindings[name].state = BindingState.REFUTED
        return refreshed

    def _key_roles(self) -> set[str]:
        if not self.entry.graphs:
            return set(self.entry.roles)
        return {node.role for node in self.entry.graphs[0].nodes}

    def _best_node(
        self,
        nodes: list[FrameworkNode],
        keywords: list[str],
        role_kind: str,
    ) -> tuple[FrameworkNode, float, str] | None:
        best: tuple[FrameworkNode, float, str] | None = None
        for node in nodes:
            haystack = f"{node.function} {node.file} {node.snippet[:4000]}".lower()
            hits = [keyword for keyword in keywords if keyword and keyword in haystack]
            if not hits:
                continue
            score = len(hits) / max(1, len(keywords))
            if role_kind == "value" and any(
                token in haystack for token in ("len", "length", "size", "offset", "count")
            ):
                score += 0.1
            if role_kind == "function" and node.kind in {"function", "function_slice"}:
                score += 0.1
            if best is None or score > best[1]:
                best = (node, round(score, 4), "hits: " + ", ".join(hits[:4]))
        return best

    def _symbol_at(self, node: FrameworkNode, keywords: list[str]) -> tuple[str, int]:
        for idx, line in enumerate(node.snippet.splitlines(), start=node.start_line):
            lowered = line.lower()
            for keyword in keywords:
                if keyword in lowered:
                    match = re.search(rf"\b{re.escape(keyword)}\w*\b", line)
                    if match:
                        return match.group(0), idx
        return "", node.start_line


def _keywords(name: str, description: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", f"{name} {description}".lower())
    stop = {"the", "and", "for", "with", "from", "into", "that", "this", "object", "value"}
    return [word for word in sorted(set(words), key=len, reverse=True) if word not in stop][:10]
