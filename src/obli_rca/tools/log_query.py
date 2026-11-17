"""Audit-log indexing and queries."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..models.evidence import EvidenceKind
from ..models.log import LogEvent, SyscallSequence, group_by_thread, parse_sysdig_text
from ..utils.json import read_json
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool


@dataclass
class LogIndex:
    events: list[LogEvent]
    by_id: dict[str, LogEvent]
    sequences: dict[tuple[str, int, int], SyscallSequence]

    @classmethod
    def from_text(cls, text: str) -> "LogIndex":
        events = parse_sysdig_text(text)
        return cls.from_events(events)

    @classmethod
    def from_file(cls, path: str | Path) -> "LogIndex":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"log file not found: {p}")
        if p.is_dir():
            raise IsADirectoryError(f"log path is a directory: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix.lower() in {".json", ".jsonl"}:
            return cls.from_json(text)
        return cls.from_text(text)

    @classmethod
    def from_json(cls, text: str) -> "LogIndex":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            try:
                payload = [json.loads(line) for line in text.splitlines() if line.strip()]
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON/JSONL log: {exc}") from exc
        if isinstance(payload, dict):
            payload = payload.get("events", [])
        events = []
        for item in payload:
            if "raw" in item:
                from ..models.log import parse_sysdig_line

                event = parse_sysdig_line(item["raw"])
                if event:
                    events.append(event)
                    continue
            events.append(
                LogEvent(
                    event_id=item.get("event_id", f"e{item.get('evt_num', len(events))}"),
                    evt_num=int(item.get("evt_num", 0)),
                    timestamp=item.get("timestamp", ""),
                    cpu=int(item.get("cpu", 0)),
                    process=item.get("process", ""),
                    pid=int(item.get("pid", 0)),
                    tid=int(item.get("tid", item.get("pid", 0))),
                    direction=item.get("direction", "<"),
                    syscall=item.get("syscall", ""),
                    fd=item.get("fd"),
                    fd_kind=item.get("fd_kind"),
                    fd_object=item.get("fd_object"),
                    tuple=item.get("tuple"),
                    path=item.get("path"),
                    res=item.get("res"),
                    args=item.get("args", {}),
                    raw=item.get("raw", ""),
                )
            )
        return cls.from_events(events)

    @classmethod
    def from_events(cls, events: list[LogEvent]) -> "LogIndex":
        by_id = {event.event_id: event for event in events}
        return cls(events=events, by_id=by_id, sequences=group_by_thread(events))

    def get(self, event_id: str) -> LogEvent | None:
        return self.by_id.get(event_id)

    def by_thread(self, process: str, tid: int | None = None) -> list[LogEvent]:
        return [
            e
            for e in self.events
            if e.process == process and (tid is None or e.tid == tid)
        ]

    def by_object(self, object_key: str) -> list[LogEvent]:
        return [
            e
            for e in self.events
            if object_key in {e.tuple, e.path, e.fd_object}
        ]

    def by_syscall(self, syscall: str) -> list[LogEvent]:
        return [e for e in self.events if e.syscall == syscall]

    def window(self, event_id: str, before: int = 6, after: int = 6) -> list[LogEvent]:
        event = self.get(event_id)
        if event is None:
            return []
        seq = self.sequences.get(event.thread_key)
        if seq is None:
            return [event]
        return seq.window(event, max(0, before), max(0, after)).events

    def search(self, **filters: Any) -> list[LogEvent]:
        result = self.events
        for key, value in filters.items():
            if value is None:
                continue
            if key in {"process", "syscall", "path", "tuple", "fd_object"}:
                result = [e for e in result if getattr(e, key) == value]
            elif key == "tid":
                result = [e for e in result if e.tid == int(value)]
            elif key == "fd":
                result = [e for e in result if e.fd == int(value)]
            elif key == "min_time":
                result = [e for e in result if e.timestamp >= str(value)]
            elif key == "max_time":
                result = [e for e in result if e.timestamp <= str(value)]
            else:
                raise ValueError(f"unsupported log filter: {key}")
        return result

    def to_sequence(self, events: Iterable[LogEvent]) -> SyscallSequence | None:
        items = list(events)
        if not items:
            return None
        first = items[0]
        return SyscallSequence(first.process, first.thread_key, items)


class LogQueryTool(BaseTool):
    name = "log_query"
    description = "Query sysdig audit-log records by thread, object, syscall, or event id."
    input_schema = {
        "type": "object",
        "properties": {
            "log_path": {"type": "string"},
            "event_id": {"type": "string"},
            "process": {"type": "string"},
            "tid": {"type": "integer"},
            "object": {"type": "string"},
            "syscall": {"type": "string"},
            "before": {"type": "integer", "default": 6},
            "after": {"type": "integer", "default": 6},
        },
    }

    def __init__(self, index: LogIndex | None = None):
        self.index = index

    def load(self, log_path: str | Path) -> LogIndex:
        self.index = LogIndex.from_file(log_path)
        return self.index

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        if self.index is None:
            if not kwargs.get("log_path"):
                raise ValueError("log_path is required for the first log query")
            self.load(kwargs["log_path"])
        assert self.index is not None
        if kwargs.get("event_id"):
            event = self.index.get(kwargs["event_id"])
            data = {"event": event.to_dict() if event else None}
            evidence = []
            if event:
                evidence.append(
                    evidence_for_tool(
                        EvidenceKind.LOG,
                        self.name,
                        f"audit event {event.event_id}: {event.syscall}",
                        f"{event.process}:{event.tid}:{event.event_id}",
                        event.to_dict(),
                    )
                )
            return ToolResult(ok=True, data=data, evidence=evidence)
        if kwargs.get("object"):
            events = self.index.by_object(kwargs["object"])
        elif kwargs.get("process"):
            events = self.index.by_thread(kwargs["process"], kwargs.get("tid"))
        elif kwargs.get("syscall"):
            events = self.index.by_syscall(kwargs["syscall"])
        else:
            events = self.index.events
        limit = int(kwargs.get("limit", 200))
        events = events[: max(0, limit)]
        return ToolResult(
            ok=True,
            data={"events": [e.to_dict() for e in events], "count": len(events)},
            evidence=[
                evidence_for_tool(
                    EvidenceKind.LOG,
                    self.name,
                    f"retrieved {len(events)} audit records",
                    kwargs.get("object") or kwargs.get("process") or "all",
                )
            ],
        )
