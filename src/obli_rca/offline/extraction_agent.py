"""Extraction Agent: patch + dual-version evidence -> candidate obligation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..llm.client import LLMClient
from ..llm.prompts import EXTRACTION_SCHEMA, load_prompt
from ..models.evidence import Evidence, EvidenceKind
from ..models.obligation import (
    ConditionSet,
    GraphEdge,
    GraphNode,
    ObjectGraph,
    ObligationEntry,
    ObligationProvenance,
    QueryItem,
    Role,
)
from ..utils.fs import read_text
from .category_assignment import CategoryAssigner
from .corpus import CorpusCase
from .patch_parser import parse_patch
from .reproduction import DualVersionReproducer


@dataclass
class ExtractionResult:
    status: str
    entry: ObligationEntry | None = None
    evidence: list[Evidence] = field(default_factory=list)
    notes: str = ""


class ExtractionAgent:
    def __init__(self, config: Config | None = None, llm: LLMClient | None = None, use_llm: bool = False):
        self.config = config or Config.load()
        self.llm = llm or LLMClient(self.config, mock=not use_llm)
        self.use_llm = use_llm
        self.reproducer = DualVersionReproducer(self.config, dry_run=True)
        self.category_assigner = CategoryAssigner()

    def extract(self, case: CorpusCase) -> ExtractionResult:
        patch = parse_patch(case.patch_path) if case.patch_path else None
        vuln_source = read_text(case.vulnerable_source, limit=12000) if case.vulnerable_source else ""
        evidence = [
            Evidence(
                kind=EvidenceKind.PATCH,
                summary=f"patch changes {len(patch.hunks) if patch else 0} hunks",
                reference=case.patch_path,
                payload={"changed": patch.changed_lines() if patch else []},
                created_by="extraction",
            ),
            Evidence(
                kind=EvidenceKind.SOURCE,
                summary="vulnerable source excerpt",
                reference=case.vulnerable_source,
                payload={"excerpt": vuln_source[:2000]},
                created_by="extraction",
            ),
        ]
        if patch and patch.guard_like_lines():
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PATCH,
                    summary="repair-like lines",
                    reference=case.patch_path,
                    payload={"lines": patch.guard_like_lines()},
                    created_by="extraction",
                )
            )
        if self.use_llm and self.llm.available():
            entry = self._llm_extract(case, evidence)
            if entry is not None:
                return ExtractionResult("ok", entry, evidence)
        entry = self._heuristic_entry(case, patch)
        return ExtractionResult("heuristic", entry, evidence, notes="LLM unavailable or declined")

    # ------------------------------------------------------------------
    def _llm_extract(self, case: CorpusCase, evidence: list[Evidence]) -> ObligationEntry | None:
        system = load_prompt("extraction.md")
        user = json.dumps(
            {
                "case": {
                    "category_hint": case.category,
                    "project": case.project,
                    "vulnerable_version": case.vulnerable_version,
                    "fixed_version": case.fixed_version,
                },
                "evidence": [e.to_dict() for e in evidence],
                "constraints": [
                    "retain protection semantics only",
                    "no program names, source paths, CVE ids, or payloads",
                    "G/C/Q must be reusable on a new application",
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        try:
            response = self.llm.chat(system, user, schema=EXTRACTION_SCHEMA)
        except Exception:  # noqa: BLE001
            return None
        payload = response.parsed or {}
        entry_data = payload.get("entry") if isinstance(payload, dict) else None
        if not entry_data:
            return None
        try:
            entry = ObligationEntry.from_dict(entry_data)
            entry.validate(strict_abstractness=True)
            return entry
        except Exception:  # noqa: BLE001
            return None

    def _heuristic_entry(self, case: CorpusCase, patch: Any) -> ObligationEntry:
        category = case.category or self.category_assigner.assign_case(case).category
        category_id = {
            "Path Constraints": 1,
            "Authorization Checks": 2,
            "Resource Bounds": 3,
            "Protocol State Constraints": 4,
            "Memory Bounds": 5,
            "Input Sanitization": 6,
            "Secure Defaults": 7,
            "Concurrency Ordering": 8,
            "Resource Lifecycles": 9,
            "Object Lifecycles": 10,
        }.get(category, 5)
        roles = {
            "source": Role("source", "untrusted input or state that reaches the operation"),
            "target": Role("target", "object or resource protected by the obligation"),
            "value": Role("value", "length, offset, path, credential, or state value"),
        }
        graph = ObjectGraph(
            id="G1",
            description="abstract source -> value -> target organization",
            nodes=[
                GraphNode("n1", "source", "object"),
                GraphNode("n2", "value", "value"),
                GraphNode("n3", "target", "object"),
            ],
            edges=[
                GraphEdge("n1", "n2", "provides"),
                GraphEdge("n2", "n3", "constrains"),
            ],
        )
        conditions = ConditionSet(
            pre=[f"the {category.lower()} operation is reachable from an untrusted source"],
            must=[f"the {category.lower()} condition holds before the protected operation"],
            stage=["before the protected operation"],
            scope=["until the operation completes and the state is no longer used"],
        )
        queries = [
            QueryItem(
                "Q1",
                "where is the protected value established?",
                "trace the value from its definition to the protected operation",
                "a dominating check that covers the operation answers the question",
                "continue to the sink if the check is established; otherwise record a gap",
            ),
            QueryItem(
                "Q2",
                "does the check survive later transformations?",
                "follow assignments, calls, and error paths after the check",
                "a later overwrite or bypass weakens the check",
                "retain the candidate if the check does not dominate the sink",
            ),
        ]
        return ObligationEntry(
            id=f"candidate-{case.case_id}",
            category=category,
            category_id=category_id,
            version="0.1.0",
            summary=f"{category} obligation abstracted from a historical repair",
            roles=roles,
            graphs=[graph],
            conditions=conditions,
            query_manual=queries,
            provenance=ObligationProvenance(
                category_id=category_id,
                graph_count=1,
                source_cases=1,
                accepted_round=0,
                created_from=case.case_id,
            ),
        )
