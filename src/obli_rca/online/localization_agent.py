"""Localization Agent: shared code framework and on-demand expansion."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models.code import CodeFramework, FunctionSlice
from ..models.evidence import Evidence, EvidenceKind
from ..models.log import LogEvent, SyscallSequence
from ..storage.investigation_store import InvestigationStore
from ..tools.base import ToolContext, ToolRegistry
from ..tools.cross_app import BoundaryRequest, CrossAppSearchTool
from ..tools.log_query import LogIndex
from ..tools.syscall_cfg import ProgramCFG, SyscallCFGTool, build_program_cfg, function_slices, match_sequence


@dataclass
class LocalizationState:
    symptom_app: str
    symptom_event_id: str
    initial_functions: list[str] = field(default_factory=list)
    expanded_applications: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


class LocalizationAgent:
    def __init__(
        self,
        config: Config,
        tools: ToolRegistry,
        store: InvestigationStore,
        investigation_id: str,
        *,
        source_roots: dict[str, str] | None = None,
        source_versions: dict[str, str] | None = None,
        workspace: str | Path | None = None,
    ):
        self.config = config
        self.tools = tools
        self.store = store
        self.investigation_id = investigation_id
        self.source_roots = source_roots or {}
        self.source_versions = source_versions or {}
        self.workspace = Path(workspace or Path("data") / "investigations" / investigation_id)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.framework = CodeFramework(investigation_id)
        self.log_index: LogIndex | None = None
        self._cfgs: dict[str, ProgramCFG] = {}
        self.state: LocalizationState | None = None
        self.ctx = ToolContext(
            config=config,
            investigation_id=investigation_id,
            workspace=self.workspace,
            framework=self.framework,
            budget=int(config.get("online.localization.max_peer_queries", 12)),
        )

    # ------------------------------------------------------------------
    def load_logs(self, log_path: str | Path) -> LogIndex:
        self.log_index = LogIndex.from_file(log_path)
        self.ctx.metadata["log_path"] = str(log_path)
        return self.log_index

    def initialize(
        self,
        symptom_app: str,
        symptom_event_id: str,
        *,
        source_root: str | Path | None = None,
        source_version: str | None = None,
        window: int = 8,
    ) -> dict[str, Any]:
        if self.log_index is None:
            raise RuntimeError("load_logs() must be called before initialize()")
        symptom = self.log_index.get(symptom_event_id)
        if symptom is None:
            raise ValueError(f"symptom event not found: {symptom_event_id}")
        if source_root is not None:
            self.source_roots[symptom_app] = str(source_root)
        if source_version is not None:
            self.source_versions[symptom_app] = source_version
        events = self.log_index.window(symptom_event_id, before=window, after=window)
        sequence = SyscallSequence(symptom_app, symptom.thread_key, events)
        try:
            cfg = self._ensure_cfg(symptom_app)
        except (FileNotFoundError, ValueError) as exc:
            self.state = LocalizationState(
                symptom_app=symptom_app,
                symptom_event_id=symptom_event_id,
            )
            return {
                "status": "no_source",
                "reason": str(exc),
                "framework_nodes": 0,
                "functions": [],
                "paths": [],
                "events": [e.event_id for e in events],
            }
        paths = match_sequence(cfg, sequence)
        functions: list[str] = []
        for path in paths:
            for slice_ in function_slices(cfg, path):
                self._add_slice(slice_)
                functions.append(slice_.function)
        for event in events:
            self.store.add_log_ref(self.investigation_id, event)
        self.state = LocalizationState(
            symptom_app=symptom_app,
            symptom_event_id=symptom_event_id,
            initial_functions=_dedupe(functions),
        )
        self.store.create(self.investigation_id, symptom_app, source_version or "")
        for node in self.framework.nodes():
            self.store.add_framework_node(self.investigation_id, node)
        self.ctx.record(
            Evidence(
                kind=EvidenceKind.SOURCE,
                summary=f"initial framework: {len(self.framework.nodes())} functions",
                reference=symptom_event_id,
                payload={
                    "functions": self.state.initial_functions,
                    "paths": [p.to_dict() for p in paths],
                    "events": [e.event_id for e in events],
                },
                created_by="localization",
            )
        )
        return {
            "framework_nodes": self.framework.size(),
            "functions": self.state.initial_functions,
            "paths": [p.to_dict() for p in paths],
            "events": [e.event_id for e in events],
        }

    # ------------------------------------------------------------------
    def expand(self, request: BoundaryRequest) -> dict[str, Any]:
        if self.log_index is None:
            return {"status": "error", "reason": "logs not loaded"}
        result = self.tools.run(
            "cross_app_search",
            self.ctx,
            log_path=self.ctx.metadata.get("log_path"),
            application=request.application,
            function=request.function,
            file=request.location.file,
            line=request.location.line,
            tid=request.tid,
            fd=request.fd,
            connection=request.connection,
            object_key=request.object_key,
            source_version=request.source_version,
            question=request.question,
        )
        if not result.ok or not result.data:
            return {"status": "error", "reason": result.error or "no result"}
        data = result.data
        peer_app = data.get("peer_application") or ""
        if not peer_app:
            if self.state:
                self.state.unresolved.append(
                    f"no peer for {request.application}:{request.function}"
                )
            return {"status": "unresolved", "result": data}
        if peer_app == request.application:
            return {"status": "same_application", "result": data}
        if peer_app not in self.source_roots:
            return {
                "status": "unresolved",
                "reason": f"source root unknown for peer application {peer_app}",
                "result": data,
            }
        sequence_payload = data.get("peer_sequence") or {}
        events = [LogEvent(**item) for item in sequence_payload.get("events", [])]
        sequence = SyscallSequence(
            peer_app,
            tuple(sequence_payload.get("thread", (peer_app, 0, 0))),
            events,
        )
        try:
            cfg = self._ensure_cfg(peer_app)
        except (FileNotFoundError, ValueError) as exc:
            return {"status": "no_source", "reason": str(exc), "peer_application": peer_app}
        paths = match_sequence(cfg, sequence)
        functions: list[str] = []
        for path in paths:
            for slice_ in function_slices(cfg, path):
                self._add_slice(slice_)
                functions.append(slice_.function)
        for event in events:
            self.store.add_log_ref(self.investigation_id, event)
        for node in self.framework.nodes():
            self.store.add_framework_node(self.investigation_id, node)
        if self.state and peer_app not in self.state.expanded_applications:
            self.state.expanded_applications.append(peer_app)
        self.ctx.record(
            Evidence(
                kind=EvidenceKind.CROSS_APP,
                summary=f"expanded to {peer_app}: {len(functions)} functions",
                reference=f"{request.application}:{request.function}",
                payload={"request": request.to_dict(), "functions": functions},
                created_by="localization",
            )
        )
        return {
            "status": "expanded",
            "peer_application": peer_app,
            "functions": _dedupe(functions),
            "paths": [p.to_dict() for p in paths],
            "framework_nodes": self.framework.size(),
        }

    # ------------------------------------------------------------------
    def _ensure_cfg(self, application: str) -> ProgramCFG:
        if application in self._cfgs:
            return self._cfgs[application]
        root = self.source_roots.get(application)
        if not root:
            raise ValueError(f"no source root for application: {application}")
        cfg = build_program_cfg(
            application,
            self.source_versions.get(application, "unknown"),
            root,
        )
        self._cfgs[application] = cfg
        return cfg

    def _add_slice(self, slice_: FunctionSlice) -> None:
        node = self.framework.add_slice(slice_)
        self.store.add_framework_node(self.investigation_id, node)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
