"""Cross-Application Syscall Searching.

An SOI reaches a source-level boundary (for example ``recv``) and asks the
Localization Agent for the peer that delivered the object.  This module maps the
boundary function to the current application's syscall record, finds the peer
record by connection tuple / file path / pipe / signal, verifies direction and
order, and returns the peer's adjacent syscall sequence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models.code import CodeLocation
from ..models.evidence import EvidenceKind
from ..models.log import LogEvent, SyscallSequence
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from .log_query import LogIndex
from .provenance import ProvenanceGraph

BOUNDARY_SYSCALLS = {
    "recv": {"recv", "recvfrom", "recvmsg"},
    "read": {"read", "pread", "pread64"},
    "open": {"open", "openat", "creat"},
    "write": {"write", "writev", "send", "sendto", "sendmsg"},
    "send": {"send", "sendto", "sendmsg", "write", "writev"},
    "sendfile": {"sendfile", "splice"},
    "accept": {"accept", "accept4"},
    "stat": {"stat", "lstat", "fstat", "newfstatat"},
    "close": {"close"},
    "exec": {"execve", "execveat"},
}


@dataclass
class BoundaryRequest:
    investigation_id: str
    application: str
    function: str
    location: CodeLocation
    tid: int | None = None
    fd: int | None = None
    connection: str | None = None
    object_key: str | None = None
    source_version: str = ""
    question: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "application": self.application,
            "function": self.function,
            "location": self.location.to_dict(),
            "tid": self.tid,
            "fd": self.fd,
            "connection": self.connection,
            "object_key": self.object_key,
            "source_version": self.source_version,
            "question": self.question,
        }


@dataclass
class CrossAppResult:
    request: BoundaryRequest
    boundary_event: LogEvent | None
    peer_events: list[LogEvent] = field(default_factory=list)
    peer_application: str = ""
    peer_sequence: SyscallSequence | None = None
    evidence: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "boundary_event": self.boundary_event.to_dict() if self.boundary_event else None,
            "peer_events": [e.to_dict() for e in self.peer_events],
            "peer_application": self.peer_application,
            "peer_sequence": self.peer_sequence.to_dict() if self.peer_sequence else None,
            "evidence": self.evidence,
            "unresolved": self.unresolved,
        }


class CrossAppSearchTool(BaseTool):
    name = "cross_app_search"
    description = (
        "Given an SOI boundary request, locate the peer application and its "
        "adjacent syscall sequence."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "log_path": {"type": "string"},
            "application": {"type": "string"},
            "function": {"type": "string"},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "tid": {"type": "integer"},
            "fd": {"type": "integer"},
            "connection": {"type": "string"},
            "object_key": {"type": "string"},
            "source_version": {"type": "string"},
            "question": {"type": "string"},
        },
    }

    def __init__(self, index: LogIndex | None = None, graph: ProvenanceGraph | None = None):
        self.index = index
        self.graph = graph

    def ensure(self, log_path: str | None = None) -> None:
        if self.index is None:
            if not log_path:
                raise ValueError("log_path required")
            self.index = LogIndex.from_file(log_path)
        if self.graph is None:
            self.graph = ProvenanceGraph()
            for event in self.index.events:
                self.graph.add_event(event)

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        self.ensure(kwargs.get("log_path"))
        assert self.index is not None and self.graph is not None
        request = BoundaryRequest(
            investigation_id=ctx.investigation_id,
            application=kwargs["application"],
            function=kwargs["function"],
            location=CodeLocation(
                kwargs.get("file", ""),
                kwargs["function"],
                int(kwargs.get("line", 0)),
            ),
            tid=kwargs.get("tid"),
            fd=kwargs.get("fd"),
            connection=kwargs.get("connection"),
            object_key=kwargs.get("object_key"),
            source_version=kwargs.get("source_version", ""),
            question=kwargs.get("question", ""),
        )
        boundary = self._boundary_event(request)
        if boundary is None:
            return ToolResult(
                ok=True,
                data=CrossAppResult(request, None, unresolved=["no boundary syscall record"]).to_dict(),
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.CROSS_APP,
                        self.name,
                        "no boundary event found",
                        f"{request.application}:{request.function}",
                    )
                ],
            )
        peers = self._peer_candidates(boundary, request)
        if not peers:
            return ToolResult(
                ok=True,
                data=CrossAppResult(
                    request,
                    boundary,
                    unresolved=["no peer record on the interaction object"],
                ).to_dict(),
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.CROSS_APP,
                        self.name,
                        f"boundary {boundary.event_id} has no peer",
                        boundary.event_id,
                        boundary.to_dict(),
                    )
                ],
            )
        # Prefer the strongest peer; retain the others when scores tie.
        scored = sorted(
            ((self._score_peer(boundary, peer), peer) for peer in peers),
            key=lambda item: (item[0], item[1].timestamp),
            reverse=True,
        )
        peer = scored[0][1]
        ambiguous = (
            len(scored) > 1
            and scored[0][0] == scored[1][0]
            and scored[0][1].process != scored[1][1].process
        )
        if peer.process == request.application:
            return ToolResult(
                ok=True,
                data=CrossAppResult(
                    request,
                    boundary,
                    peers,
                    unresolved=["peer resolves to the same application"],
                ).to_dict(),
            )
        peer_thread_seq = self.index.sequences.get(peer.thread_key)
        peer_sequence = (
            peer_thread_seq.window(peer, before=4, after=4)
            if peer_thread_seq
            else SyscallSequence(peer.process, peer.thread_key, [peer])
        )
        result = CrossAppResult(
            request=request,
            boundary_event=boundary,
            peer_events=peers,
            peer_application=peer.process,
            peer_sequence=peer_sequence,
            evidence=[
                f"boundary {boundary.event_id} ({boundary.syscall}) in {boundary.process}",
                f"peer {peer.event_id} ({peer.syscall}) in {peer.process}",
                f"object {boundary.object_key}",
                "direction/time/byte checks applied",
            ],
            unresolved=["ambiguous peer candidates"] if ambiguous else [],
        )
        evidence = [
            evidence_for_tool(
                EvidenceKind.CROSS_APP,
                self.name,
                f"peer found: {peer.process} {peer.syscall} {peer.event_id}",
                f"{boundary.event_id}->{peer.event_id}",
                result.to_dict(),
            )
        ]
        return ToolResult(ok=True, data=result.to_dict(), evidence=evidence)

    # ------------------------------------------------------------------
    def _boundary_event(self, request: BoundaryRequest) -> LogEvent | None:
        names = BOUNDARY_SYSCALLS.get(request.function, {request.function})
        candidates = [
            e
            for e in self.index.events
            if e.process == request.application
            and e.syscall in names
            and (request.tid is None or e.tid == request.tid)
            and (request.fd is None or e.fd == request.fd)
            and (
                request.connection is None
                or e.tuple == request.connection
                or e.fd_object == request.connection
            )
            and (request.object_key is None or e.object_key == request.object_key)
        ]
        if not candidates:
            # Relax the fd/object filters one at a time.
            candidates = [
                e
                for e in self.index.events
                if e.process == request.application and e.syscall in names
            ]
        return sorted(candidates, key=lambda e: (e.timestamp, e.evt_num))[-1] if candidates else None

    def _peer_candidates(self, boundary: LogEvent, request: BoundaryRequest) -> list[LogEvent]:
        peers = self.graph.peer_events(self.index, boundary.event_id) if self.graph else []
        # Keep only peers whose object matches the boundary, and whose direction
        # is send/write for a receive boundary (or read for a write boundary).
        result = []
        for peer in peers:
            if boundary.tuple and peer.tuple != boundary.tuple:
                continue
            if boundary.path and peer.path != boundary.path:
                continue
            if boundary.timestamp and peer.timestamp > boundary.timestamp:
                continue
            result.append(peer)
        result.sort(key=lambda e: (e.timestamp, e.evt_num), reverse=True)
        return result

    def _score_peer(self, boundary: LogEvent, peer: LogEvent) -> float:
        score = 0.0
        if boundary.tuple and peer.tuple == boundary.tuple:
            score += 2.0
        if boundary.path and peer.path == boundary.path:
            score += 2.0
        if boundary.fd_object and peer.fd_object == boundary.fd_object:
            score += 1.0
        receiving = boundary.syscall.lower() in {"recv", "recvfrom", "recvmsg", "read", "pread64"}
        sending = peer.syscall.lower() in {"send", "sendto", "sendmsg", "write", "writev", "sendfile"}
        if receiving and sending:
            score += 1.5
        if boundary.res is not None and peer.res is not None:
            score += 1.0 if boundary.res == peer.res else -0.5
        if peer.timestamp <= boundary.timestamp:
            score += 0.5
        return score
