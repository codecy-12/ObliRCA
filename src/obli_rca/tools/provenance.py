"""Lightweight provenance graph built from syscall records.

The prototype intentionally keeps the graph representation small and
replaceable: the Localization Agent only needs process/object identity, event
order, and peer lookup.  A stronger provenance backend can implement the same
``peer_events`` and ``subgraph`` methods.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models.evidence import EvidenceKind
from ..models.log import LogEvent
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool
from .log_query import LogIndex


@dataclass
class ProvenanceNode:
    id: str
    kind: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    src: str
    dst: str
    relation: str
    event_id: str
    timestamp: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, ProvenanceNode] = {}
        self.edges: list[ProvenanceEdge] = []
        self.event_index: dict[str, ProvenanceEdge] = {}

    # ------------------------------------------------------------------
    def add_node(self, node: ProvenanceNode) -> None:
        self.nodes.setdefault(node.id, node)

    def add_event(self, event: LogEvent) -> None:
        process_id = f"proc:{event.process}:{event.tid}"
        self.add_node(
            ProvenanceNode(
                process_id,
                "process",
                f"{event.process}({event.tid})",
                {"process": event.process, "pid": event.pid, "tid": event.tid},
            )
        )
        object_id = None
        kind = None
        if event.tuple:
            object_id = f"sock:{event.tuple}"
            kind = "socket"
            self.add_node(ProvenanceNode(object_id, kind, event.tuple))
        elif event.path:
            object_id = f"file:{event.path}"
            kind = "file"
            self.add_node(ProvenanceNode(object_id, kind, event.path))
        elif event.fd_object:
            object_id = f"obj:{event.fd_object}"
            kind = "object"
            self.add_node(ProvenanceNode(object_id, kind, event.fd_object))

        if object_id is None:
            return
        relation = _relation_for(event)
        edge = ProvenanceEdge(
            src=process_id,
            dst=object_id,
            relation=relation,
            event_id=event.event_id,
            timestamp=event.timestamp,
            attrs={"syscall": event.syscall, "res": event.res, "direction": event.direction},
        )
        self.edges.append(edge)
        self.event_index[event.event_id] = edge

    # ------------------------------------------------------------------
    def incident_object(self, event_id: str) -> str | None:
        edge = self.event_index.get(event_id)
        return edge.dst if edge else None

    def peer_events(self, index: LogIndex, event_id: str) -> list[LogEvent]:
        """Return events from other process identities on the same object."""
        event = index.get(event_id)
        if event is None:
            return []
        object_key = event.tuple or event.path or event.fd_object
        if not object_key:
            return []
        candidates = index.by_object(object_key)
        result = []
        for candidate in candidates:
            if candidate.event_id == event.event_id:
                continue
            if candidate.thread_key == event.thread_key:
                continue
            # Direction check: for a connection, the peer should send when the
            # current event receives (and vice versa).
            if event.tuple and not _opposite_direction(event, candidate):
                continue
            if event.path and candidate.timestamp > event.timestamp:
                continue
            result.append(candidate)
        return sorted(result, key=lambda e: (e.timestamp, e.evt_num))

    def subgraph(self, index: LogIndex, event_id: str, hops: int = 2) -> dict[str, Any]:
        seed = index.get(event_id)
        if seed is None:
            return {"nodes": [], "edges": []}
        selected_events: dict[str, LogEvent] = {seed.event_id: seed}
        frontier = deque([(seed, 0)])
        while frontier:
            current, depth = frontier.popleft()
            if depth >= hops:
                continue
            for peer in self.peer_events(index, current.event_id):
                if peer.event_id in selected_events:
                    continue
                selected_events[peer.event_id] = peer
                frontier.append((peer, depth + 1))
        selected_edges = [
            self.event_index[eid] for eid in selected_events if eid in self.event_index
        ]
        node_ids = sorted({e.src for e in selected_edges} | {e.dst for e in selected_edges})
        return {
            "nodes": [
                {
                    "id": nid,
                    "kind": self.nodes[nid].kind,
                    "label": self.nodes[nid].label,
                    **self.nodes[nid].attrs,
                }
                for nid in node_ids
                if nid in self.nodes
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "relation": e.relation,
                    "event_id": e.event_id,
                    "timestamp": e.timestamp,
                }
                for e in selected_edges
            ],
            "events": [e.to_dict() for e in selected_events.values()],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.__dict__ for n in self.nodes.values()],
            "edges": [e.__dict__ for e in self.edges],
        }


def _relation_for(event: LogEvent) -> str:
    name = event.syscall.lower()
    if name in {"recv", "recvfrom", "recvmsg", "read", "pread64"}:
        return "reads"
    if name in {"send", "sendto", "sendmsg", "write", "writev"}:
        return "writes"
    if name in {"open", "openat", "creat"}:
        return "opens"
    if name in {"accept", "accept4", "connect"}:
        return "connects"
    if name in {"sendfile", "splice"}:
        return "transfers"
    if name in {"kill", "tgkill"}:
        return "signals"
    return "accesses"


def _opposite_direction(current: LogEvent, peer: LogEvent) -> bool:
    receiving = current.syscall.lower() in {"recv", "recvfrom", "recvmsg", "read", "pread64"}
    sending = peer.syscall.lower() in {"send", "sendto", "sendmsg", "write", "writev", "sendfile"}
    if receiving:
        return sending
    sending_current = current.syscall.lower() in {"send", "sendto", "sendmsg", "write", "writev", "sendfile"}
    receiving_peer = peer.syscall.lower() in {"recv", "recvfrom", "recvmsg", "read", "pread64"}
    if sending_current:
        return receiving_peer
    return True


class ProvenanceTool(BaseTool):
    name = "provenance"
    description = "Build a process/object provenance graph and query peer events."
    input_schema = {
        "type": "object",
        "properties": {
            "log_path": {"type": "string"},
            "event_id": {"type": "string"},
            "hops": {"type": "integer", "default": 2},
            "action": {"enum": ["build", "peer", "subgraph"]},
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
        action = kwargs.get("action", "build")
        if action == "peer":
            event_id = kwargs["event_id"]
            peers = self.graph.peer_events(self.index, event_id)
            return ToolResult(
                ok=True,
                data={"event_id": event_id, "peers": [p.to_dict() for p in peers]},
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.CROSS_APP,
                        self.name,
                        f"peer lookup for {event_id}: {len(peers)} candidates",
                        event_id,
                        {"peers": [p.event_id for p in peers]},
                    )
                ],
            )
        if action == "subgraph":
            data = self.graph.subgraph(self.index, kwargs["event_id"], int(kwargs.get("hops", 2)))
            return ToolResult(
                ok=True,
                data=data,
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.CROSS_APP,
                        self.name,
                        f"provenance subgraph around {kwargs['event_id']}",
                        kwargs["event_id"],
                        {"nodes": len(data["nodes"]), "edges": len(data["edges"])},
                    )
                ],
            )
        data = self.graph.to_dict()
        return ToolResult(
            ok=True,
            data={"nodes": len(data["nodes"]), "edges": len(data["edges"])},
            evidence=[
                evidence_for_tool(
                    EvidenceKind.LOG,
                    self.name,
                    "provenance graph built",
                    "log",
                    {"nodes": len(data["nodes"]), "edges": len(data["edges"])},
                )
            ],
        )
