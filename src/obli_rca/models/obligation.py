"""Security-obligation entry model: o = <G, C, Q>."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..errors import ValidationError

FORBIDDEN_PATTERNS = [
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    re.compile(r"\bGHSA-[a-z0-9-]+\b", re.I),
    re.compile(r"\.(?:c|cc|cpp|h|py|go|java|rb):\d+", re.I),
    re.compile(r"\b(?:src|modules|lib|pkg)/[\w./-]+", re.I),
]


@dataclass
class Role:
    name: str
    description: str
    kind: str = "object"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "kind": self.kind}


@dataclass
class GraphNode:
    id: str
    role: str
    kind: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "role": self.role, "kind": self.kind, "description": self.description}


@dataclass
class GraphEdge:
    src: str
    dst: str
    relation: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "relation": self.relation,
            "description": self.description,
        }


@dataclass
class ObjectGraph:
    id: str
    description: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def validate(self) -> None:
        ids = {n.id for n in self.nodes}
        if not ids:
            raise ValidationError(f"graph {self.id} has no nodes")
        for edge in self.edges:
            if edge.src not in ids or edge.dst not in ids:
                raise ValidationError(f"graph {self.id} edge references unknown node: {edge}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class ConditionSet:
    pre: list[str] = field(default_factory=list)
    must: list[str] = field(default_factory=list)
    stage: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if not self.must:
            raise ValidationError("condition Must must not be empty")
        if not self.pre:
            raise ValidationError("condition Pre must not be empty")
        if not self.stage:
            raise ValidationError("condition Stage must not be empty")
        if not self.scope:
            raise ValidationError("condition Scope must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pre": self.pre,
            "must": self.must,
            "stage": self.stage,
            "scope": self.scope,
        }


@dataclass
class QueryItem:
    id: str
    what: str
    where: str
    interpret: str
    next: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "what": self.what,
            "where": self.where,
            "interpret": self.interpret,
            "next": self.next,
        }


@dataclass
class ObligationProvenance:
    category_id: int = 0
    graph_count: int = 0
    source_cases: int = 0
    accepted_round: int = 1
    revision_count: int = 0
    created_from: str = "offline-flywheel"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category_id": self.category_id,
            "graph_count": self.graph_count,
            "source_cases": self.source_cases,
            "accepted_round": self.accepted_round,
            "revision_count": self.revision_count,
            "created_from": self.created_from,
            "notes": self.notes,
        }


@dataclass
class ObligationEntry:
    id: str
    category: str
    category_id: int
    version: str
    summary: str
    roles: dict[str, Role]
    graphs: list[ObjectGraph]
    conditions: ConditionSet
    query_manual: list[QueryItem]
    provenance: ObligationProvenance = field(default_factory=ObligationProvenance)

    # ---- validation -----------------------------------------------------
    def validate(self, strict_abstractness: bool = False) -> None:
        if not self.id or not self.category:
            raise ValidationError("entry id and category are required")
        if not self.roles:
            raise ValidationError(f"{self.id}: roles must not be empty")
        if not self.graphs:
            raise ValidationError(f"{self.id}: at least one graph is required")
        for graph in self.graphs:
            graph.validate()
            for node in graph.nodes:
                if node.role not in self.roles:
                    raise ValidationError(
                        f"{self.id}/{graph.id}: node role {node.role!r} not declared in roles"
                    )
        self.conditions.validate()
        if not self.query_manual:
            raise ValidationError(f"{self.id}: query manual must not be empty")
        if strict_abstractness:
            self.assert_abstract()

    def assert_abstract(self) -> None:
        text = json.dumps(self.to_dict(), ensure_ascii=False)
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            if match:
                raise ValidationError(
                    f"{self.id}: concrete identifier in obligation entry: {match.group(0)!r}"
                )

    # ---- identity -------------------------------------------------------
    def semantic_hash(self) -> str:
        payload = {
            "category": self.category,
            "roles": sorted(self.roles),
            "graphs": [
                {
                    "nodes": sorted((n.role, n.kind) for n in g.nodes),
                    "edges": sorted((e.relation,) for e in g.edges),
                }
                for g in self.graphs
            ],
            "conditions": self.conditions.to_dict(),
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def graph_hashes(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for graph in self.graphs:
            raw = json.dumps(graph.to_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8")
            result[graph.id] = hashlib.sha256(raw).hexdigest()[:16]
        return result

    # ---- serialization --------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "category_id": self.category_id,
            "version": self.version,
            "summary": self.summary,
            "roles": {k: v.to_dict() for k, v in self.roles.items()},
            "graphs": [g.to_dict() for g in self.graphs],
            "conditions": self.conditions.to_dict(),
            "query_manual": [q.to_dict() for q in self.query_manual],
            "provenance": self.provenance.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ObligationEntry":
        roles = {
            name: Role(**{k: v for k, v in value.items() if k in {"name", "description", "kind"}})
            for name, value in (data.get("roles") or {}).items()
        }
        graphs = [
            ObjectGraph(
                id=g["id"],
                description=g.get("description", ""),
                nodes=[GraphNode(**n) for n in g.get("nodes", [])],
                edges=[GraphEdge(**e) for e in g.get("edges", [])],
            )
            for g in data.get("graphs", [])
        ]
        conditions = ConditionSet(**(data.get("conditions") or {}))
        queries = [QueryItem(**q) for q in data.get("query_manual", [])]
        provenance = ObligationProvenance(**(data.get("provenance") or {}))
        return cls(
            id=data["id"],
            category=data["category"],
            category_id=int(data.get("category_id", 0)),
            version=str(data.get("version", "1.0.0")),
            summary=data.get("summary", ""),
            roles=roles,
            graphs=graphs,
            conditions=conditions,
            query_manual=queries,
            provenance=provenance,
        )

    @classmethod
    def load(cls, path: str | Path) -> "ObligationEntry":
        with Path(path).open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        entry = cls.from_dict(data)
        entry.validate()
        return entry

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(self.to_dict(), fh, sort_keys=False, allow_unicode=True)

    # ---- helpers --------------------------------------------------------
    def condition_text(self) -> str:
        return " / ".join(self.conditions.must)

    def queries_for(self, keyword: str) -> list[QueryItem]:
        lowered = keyword.lower()
        return [
            q
            for q in self.query_manual
            if lowered in (q.what + q.where + q.interpret + q.next).lower()
        ]
