"""Security Obligation Inspector (SOI)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..errors import BudgetExceeded
from ..llm.client import LLMClient
from ..llm.prompts import SOI_SCHEMA, load_prompt
from ..models.code import CodeFramework, CodeLocation, FrameworkNode
from ..models.evidence import Evidence, EvidenceKind
from ..models.hypothesis import FeedbackRequest, GapType, Hypothesis, HypothesisStatus
from ..models.obligation import ObligationEntry, QueryItem
from ..storage.investigation_store import InvestigationStore
from ..tools.base import ToolContext, ToolRegistry
from ..tools.cross_app import BoundaryRequest
from .localization_agent import LocalizationAgent
from .object_mapping import ObjectMapper

CATEGORY_GUARDS: dict[str, list[str]] = {
    "Path Constraints": [
        r"realpath",
        r"canonical",
        r"normalize",
        r"\.\.",
        r"path_",
        r"is_safe",
        r"chroot",
        r"root",
        r"symlink",
        r"travers",
    ],
    "Authorization Checks": [
        r"auth",
        r"permission",
        r"allow",
        r"deny",
        r"check_",
        r"role",
        r"capab",
        r"policy",
        r"host",
        r"credential",
    ],
    "Resource Bounds": [
        r"limit",
        r"quota",
        r"max",
        r"size",
        r"count",
        r"rate",
        r"capacity",
        r"budget",
    ],
    "Protocol State Constraints": [
        r"state",
        r"phase",
        r"handshake",
        r"version",
        r"sequence",
        r"session",
        r"transition",
    ],
    "Memory Bounds": [
        r"\blen\b",
        r"length",
        r"size",
        r"offset",
        r"bound",
        r"capacity",
        r"avail",
        r"remaining",
        r"range",
    ],
    "Input Sanitization": [
        r"sanitize",
        r"validate",
        r"escape",
        r"encode",
        r"filter",
        r"parse",
        r"decode",
        r"canonical",
        r"quote",
    ],
    "Secure Defaults": [
        r"default",
        r"enable",
        r"disable",
        r"strict",
        r"secure",
        r"opt_",
        r"config",
    ],
    "Concurrency Ordering": [
        r"lock",
        r"mutex",
        r"atomic",
        r"barrier",
        r"order",
        r"race",
        r"refcount",
        r"seq",
    ],
    "Resource Lifecycles": [
        r"open",
        r"close",
        r"release",
        r"free",
        r"destroy",
        r"cleanup",
        r"acquire",
        r"put_",
    ],
    "Object Lifecycles": [
        r"init",
        r"destroy",
        r"free",
        r"ref",
        r"use",
        r"lifetime",
        r"valid",
        r"stale",
        r"release",
    ],
}

CATEGORY_OPERATIONS: dict[str, list[str]] = {
    "Path Constraints": [r"\bopen(?:at)?\s*\(", r"\brealpath", r"\bchdir", r"\bstat\b", r"\bsymlink"],
    "Authorization Checks": [r"\bauth", r"\bpolicy", r"\ballow", r"\bdeny", r"\bcredential", r"\bsudoers", r"\bpermission"],
    "Resource Bounds": [r"\balloc", r"\bmalloc", r"\bcalloc", r"\benqueue", r"\bquota", r"\brate", r"\blimit"],
    "Protocol State Constraints": [r"\bparse", r"\bmessage", r"\bframe", r"\bhandshake", r"\bsession", r"\bstate\b"],
    "Memory Bounds": [r"\bmemcpy", r"\bmemmove", r"\bstrcpy", r"\bread\s*\(", r"\bwrite", r"\bindex", r"\boffset"],
    "Input Sanitization": [r"\bparse", r"\bdecode", r"\bescape", r"\bsanitize", r"\bexec", r"\bsystem", r"\beval"],
    "Secure Defaults": [r"\bconfig", r"\boption", r"\bdefault", r"\benable", r"\bdisable", r"\bstrict"],
    "Concurrency Ordering": [r"\block", r"\bmutex", r"\batomic", r"\bthread", r"\brace", r"\brefcount"],
    "Resource Lifecycles": [r"\bopen", r"\bclose", r"\bfree", r"\brelease", r"\bdestroy", r"\bcleanup"],
    "Object Lifecycles": [r"\bfree", r"\bdestroy", r"\bref", r"\binit", r"\buse\b", r"\blifetime"],
}

SINK_HINTS = [
    r"\brecv(?:from|msg)?\s*\(",
    r"\bread\s*\(",
    r"\bopen(?:at)?\s*\(",
    r"\bwrite(?:v)?\s*\(",
    r"\bsend(?:to|msg|file)?\s*\(",
    r"\bmemcpy\s*\(",
    r"\bmemmove\s*\(",
    r"\bstrcpy\s*\(",
    r"\bmapset\s*\(",
    r"\bpivot_root\s*\(",
    r"\bchroot\s*\(",
]

BOUNDARY_FUNCS = ["recv", "read", "open", "write", "send", "sendfile"]


@dataclass
class SoiResult:
    active: bool
    entry_id: str
    bindings: dict[str, str] = field(default_factory=dict)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    queries: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""


class SecurityObligationInspector:
    def __init__(
        self,
        entry: ObligationEntry,
        framework: CodeFramework,
        tools: ToolRegistry,
        store: InvestigationStore,
        localization: LocalizationAgent,
        *,
        config: Config | None = None,
        llm: LLMClient | None = None,
        investigation_id: str = "",
        workspace: str | None = None,
        budget: int = 12,
        use_llm: bool = False,
    ):
        self.entry = entry
        self.framework = framework
        self.tools = tools
        self.store = store
        self.localization = localization
        self.config = config or Config.load()
        self.llm = llm or LLMClient(self.config, mock=not use_llm)
        self.investigation_id = investigation_id
        self.workspace = workspace or f"data/investigations/{investigation_id}/soi_{entry.id}"
        self.ctx = ToolContext(
            config=self.config,
            investigation_id=investigation_id,
            workspace=Path(self.workspace),
            framework=framework,
            budget=budget,
        )
        self.bindings: dict[str, str] = {}
        self.hypotheses: list[Hypothesis] = []
        self.unresolved: list[str] = []
        self.queries: list[dict[str, Any]] = []
        self.active = True
        self._peer_requested = False

    # ------------------------------------------------------------------
    def run(self) -> SoiResult:
        if not self._screen():
            self.active = False
            return SoiResult(False, self.entry.id, reason="precondition not present in shared framework")
        self._object_mapping()
        try:
            self._problem_driven_investigation()
        except BudgetExceeded as exc:
            self.unresolved.append(str(exc))
        self._check_conditions()
        for hypothesis in self.hypotheses:
            hypothesis.investigation_id = self.investigation_id
            self.store.save_hypothesis(self.investigation_id, hypothesis)
        return SoiResult(
            active=True,
            entry_id=self.entry.id,
            bindings=self.bindings,
            hypotheses=self.hypotheses,
            unresolved=self.unresolved,
            queries=self.queries,
        )

    # ------------------------------------------------------------------
    def _screen(self) -> bool:
        category = self.entry.category
        patterns = CATEGORY_GUARDS.get(category, [])
        operations = CATEGORY_OPERATIONS.get(category, [])
        text = "\n".join(
            f"{n.function}\n{n.file}\n{n.snippet[:2000]}" for n in self.framework.nodes()
        )
        has_category_term = any(re.search(p, text, re.I) for p in patterns)
        has_category_operation = any(re.search(p, text, re.I) for p in operations)
        # The obligation is applicable when the code contains either a term
        # associated with its condition or an operation of its category.  A
        # generic syscall alone is not enough: otherwise every SOI would claim
        # every function.
        return has_category_term or has_category_operation

    def _object_mapping(self) -> None:
        mapping = ObjectMapper(self.entry).bind(self.framework)
        self.mapping = mapping
        self.bindings = {
            role: binding.node_id
            for role, binding in mapping.bindings.items()
            if binding.node_id
        }
        for role in mapping.unbound:
            self.unresolved.append(f"unbound role: {role}")

    def _problem_driven_investigation(self) -> None:
        categories = self.entry.category.lower()
        for query in self.entry.query_manual:
            self.queries.append({"query": query.to_dict(), "status": "open"})
            # If the SOI has reached a boundary and the peer is absent, ask the
            # Localization Agent for one hop.
            if not self._peer_requested and self._needs_peer():
                self._peer_requested = True
                boundary = self._boundary_request()
                if boundary is not None:
                    try:
                        result = self.localization.expand(boundary)
                    except BudgetExceeded as exc:
                        self.unresolved.append(str(exc))
                        break
                    self.queries[-1]["localization"] = result
                    if result.get("status") != "expanded":
                        self.unresolved.append(
                            f"cannot expand {boundary.application}:{boundary.function}"
                        )
        # Use code query once per bound function to enrich call relations.
        seen_functions: set[str] = set()
        for role_name, node_id in list(self.bindings.items()):
            node = self.framework.get(node_id)
            if node is None or node.function in seen_functions:
                continue
            seen_functions.add(node.function)
            try:
                result = self.tools.run(
                    "code_query",
                    self.ctx,
                    action="callees",
                    name=node.function,
                )
            except BudgetExceeded as exc:
                self.unresolved.append(str(exc))
                break
            if result.ok:
                self.queries.append(
                    {"query": f"callees of {node.function}", "result": result.data}
                )

    def _needs_peer(self) -> bool:
        # A boundary is present when a framework node contains a recv/read/open
        # call and the entry's obligations involve cross-application input.
        boundary_terms = ["recv", "read", "open", "accept"]
        text = "\n".join(n.snippet[:2000] for n in self.framework.nodes())
        return any(term in text for term in boundary_terms) and len(self.framework.applications()) <= 1

    def _boundary_request(self) -> BoundaryRequest | None:
        for node in self.framework.nodes():
            for func in BOUNDARY_FUNCS:
                if re.search(rf"\b{func}\s*\(", node.snippet):
                    return BoundaryRequest(
                        investigation_id=self.investigation_id,
                        application=node.application,
                        function=func,
                        location=CodeLocation(node.file, node.function, node.start_line),
                        source_version=node.source_version,
                        question="peer that delivered the object to this boundary",
                    )
        return None

    # ------------------------------------------------------------------
    def _check_conditions(self) -> None:
        category = self.entry.category
        guard_patterns = CATEGORY_GUARDS.get(category, [])
        sinks = self._candidate_sinks()
        if not sinks:
            self.unresolved.append("no sink candidate in shared framework")
            return
        for node in sinks[:3]:
            guards = self._guards_before(node, guard_patterns)
            sink_line = self._operation_line(node, CATEGORY_OPERATIONS.get(category, SINK_HINTS))
            location = CodeLocation(node.file, node.function, sink_line, snippet=node.snippet[:800])
            if not guards:
                hypothesis = Hypothesis(
                    obligation_id=self.entry.id,
                    location=location,
                    mechanism=(
                        f"{self.entry.summary}: no guard for "
                        f"{'; '.join(self.entry.conditions.must[:2])} before the operation"
                    ),
                    gap_type=GapType.MISSING_NECESSARY,
                    investigation_id=self.investigation_id,
                    bindings=dict(self.bindings),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.SOURCE,
                            summary=f"no guard before {node.function}",
                            reference=f"{node.file}:{node.start_line}",
                            payload={"function": node.function, "category": category},
                            created_by="soi",
                        )
                    ],
                    confidence=0.55,
                    source_app=node.application,
                    missing_region=f"{node.file}:{node.function}",
                )
                self.hypotheses.append(hypothesis)
            else:
                # A guard exists but may not cover all Must clauses.
                covered = sum(
                    1
                    for must in self.entry.conditions.must
                    if any(term.lower() in " ".join(guards).lower() for term in _keywords(must))
                )
                if covered < max(1, len(self.entry.conditions.must)):
                    hypothesis = Hypothesis(
                        obligation_id=self.entry.id,
                        location=location,
                        mechanism=(
                            f"existing guard does not cover all required conditions: "
                            f"{'; '.join(self.entry.conditions.must)}"
                        ),
                        gap_type=GapType.INSUFFICIENT_EXISTING,
                        investigation_id=self.investigation_id,
                        bindings=dict(self.bindings),
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.SOURCE,
                                summary=f"guard found but incomplete: {guards[0]}",
                                reference=f"{node.file}:{node.start_line}",
                                payload={"guards": guards, "category": category},
                                created_by="soi",
                            )
                        ],
                        confidence=0.5,
                        source_app=node.application,
                    )
                    self.hypotheses.append(hypothesis)

    def _candidate_sinks(self) -> list[FrameworkNode]:
        sinks: list[FrameworkNode] = []
        operations = CATEGORY_OPERATIONS.get(self.entry.category, SINK_HINTS)
        for node in self.framework.nodes():
            if any(re.search(p, node.snippet, re.I) for p in operations):
                sinks.append(node)
        # Prefer nodes bound to a role and with a concrete file location.
        sinks.sort(key=lambda n: (n.function not in self.bindings.values(), n.start_line))
        return sinks

    def _operation_line(self, node: FrameworkNode, operations: list[str]) -> int:
        for idx, line in enumerate(node.snippet.splitlines(), start=node.start_line):
            if any(re.search(p, line, re.I) for p in operations):
                return idx
        return node.start_line

    def _guards_before(self, node: FrameworkNode, patterns: list[str]) -> list[str]:
        guards: list[str] = []
        sink_line = None
        for idx, line in enumerate(node.snippet.splitlines(), start=node.start_line):
            if any(re.search(p, line) for p in SINK_HINTS):
                sink_line = idx
                break
        if sink_line is None:
            return guards
        for line in node.snippet.splitlines()[: max(1, sink_line - node.start_line)]:
            if any(re.search(p, line, re.I) for p in patterns):
                if re.search(r"\b(if|while|return|assert|check|verify|validate|guard)\b", line, re.I):
                    guards.append(line.strip())
        return guards

    # ------------------------------------------------------------------
    def handle_feedback(self, request: FeedbackRequest) -> Hypothesis | None:
        target = next((h for h in self.hypotheses if h.id == request.hypothesis_id), None)
        if target is None:
            return None
        target.revision_round += 1
        # A targeted recheck: add evidence from the requested questions and
        # either strengthen or downgrade the hypothesis.
        target.evidence.append(
            Evidence(
                kind=EvidenceKind.REVIEW,
                summary="feedback recheck",
                reference=request.hypothesis_id,
                payload=request.to_dict(),
                created_by="soi",
            )
        )
        if target.revision_round >= int(self.config.get("online.rank.feedback_rounds", 2)):
            target.status = HypothesisStatus.UNRESOLVED
        return target


def _role_keywords(name: str, description: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", f"{name} {description}".lower())
    return sorted(set(words), key=len, reverse=True)[:8]


def _keywords(text: str) -> list[str]:
    return [w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text.lower()) if w not in {"must", "the", "and", "for", "with"}]
