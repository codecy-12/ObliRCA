"""Sysdig-style audit-log events and sequences."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_EVENT_RE = re.compile(
    r"^\s*(?:(?P<id>e\d+)\s+)?"
    r"(?P<num>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<cpu>\d+)\s+"
    r"(?P<proc>[\w./+-]+)\s+"
    r"\((?P<pid>\d+)(?::(?P<tid>\d+))?\)\s+"
    r"(?P<dir>[<>])\s+"
    r"(?P<syscall>\w+)\s*(?P<rest>.*)$"
)
_KV_RE = re.compile(r"(\w+)=((?:\([^)]*\)|[^\s])+)")


def _parse_fd_object(value: str) -> tuple[int | None, str | None, str | None]:
    """Return (fd, kind, object) from ``8(<4t>a->b)`` or ``12(<f>/x)``."""
    m = re.match(r"^(-?\d+)\(<([^>]+)>(.*)\)$", value)
    if not m:
        if re.fullmatch(r"-?\d+", value):
            return int(value), None, None
        return None, None, None
    fd = int(m.group(1))
    kind = m.group(2)
    obj = m.group(3)
    return fd, kind, obj


def parse_sysdig_line(line: str) -> "LogEvent | None":
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _EVENT_RE.match(line)
    if not m:
        return None
    rest = m.group("rest") or ""
    args: dict[str, str] = {}
    for key, value in _KV_RE.findall(rest):
        args[key] = value

    fd = None
    fd_kind = None
    fd_object = None
    for key in ("fd", "out_fd", "in_fd"):
        if key in args:
            parsed_fd, parsed_kind, parsed_obj = _parse_fd_object(args[key])
            if key == "fd":
                fd, fd_kind, fd_object = parsed_fd, parsed_kind, parsed_obj
            args[f"{key}_kind"] = parsed_kind or ""
            args[f"{key}_object"] = parsed_obj or ""

    tuple_value = None
    path = args.get("name")
    for key in ("fd", "out_fd", "in_fd"):
        obj = args.get(f"{key}_object")
        kind = args.get(f"{key}_kind")
        if kind == "4t" and obj and "->" in obj:
            tuple_value = obj
        if kind == "f" and obj:
            path = path or obj

    return LogEvent(
        event_id=m.group("id") or f"e{m.group('num')}",
        evt_num=int(m.group("num")),
        timestamp=m.group("time"),
        cpu=int(m.group("cpu")),
        process=m.group("proc"),
        pid=int(m.group("pid")),
        tid=int(m.group("tid") or m.group("pid")),
        direction=m.group("dir"),
        syscall=m.group("syscall"),
        fd=fd,
        fd_kind=fd_kind,
        fd_object=fd_object,
        tuple=tuple_value,
        path=path,
        res=_to_int(args.get("res")),
        args=args,
        raw=line,
    )


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


@dataclass
class LogEvent:
    event_id: str
    evt_num: int
    timestamp: str
    cpu: int
    process: str
    pid: int
    tid: int
    direction: str
    syscall: str
    fd: int | None = None
    fd_kind: str | None = None
    fd_object: str | None = None
    tuple: str | None = None
    path: str | None = None
    res: int | None = None
    args: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def thread_key(self) -> tuple[str, int, int]:
        return (self.process, self.pid, self.tid)

    @property
    def is_exit(self) -> bool:
        return self.direction == "<"

    @property
    def object_key(self) -> str | None:
        return self.tuple or self.path or self.fd_object

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "evt_num": self.evt_num,
            "timestamp": self.timestamp,
            "cpu": self.cpu,
            "process": self.process,
            "pid": self.pid,
            "tid": self.tid,
            "direction": self.direction,
            "syscall": self.syscall,
            "fd": self.fd,
            "fd_kind": self.fd_kind,
            "fd_object": self.fd_object,
            "tuple": self.tuple,
            "path": self.path,
            "res": self.res,
            "args": self.args,
        }


@dataclass
class SyscallSequence:
    application: str
    thread: tuple[str, int, int]
    events: list[LogEvent] = field(default_factory=list)

    @property
    def syscalls(self) -> list[str]:
        return [e.syscall for e in self.events]

    def window(self, around: LogEvent, before: int = 6, after: int = 6) -> "SyscallSequence":
        try:
            idx = self.events.index(around)
        except ValueError:
            return SyscallSequence(self.application, self.thread, [])
        start = max(0, idx - before)
        end = min(len(self.events), idx + after + 1)
        return SyscallSequence(self.application, self.thread, self.events[start:end])

    def to_dict(self) -> dict[str, Any]:
        return {
            "application": self.application,
            "thread": list(self.thread),
            "events": [e.to_dict() for e in self.events],
        }


def parse_sysdig_text(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in text.splitlines():
        event = parse_sysdig_line(line)
        if event is not None:
            events.append(event)
    return events


def group_by_thread(events: Iterable[LogEvent]) -> dict[tuple[str, int, int], SyscallSequence]:
    groups: dict[tuple[str, int, int], SyscallSequence] = {}
    for event in events:
        key = event.thread_key
        if key not in groups:
            groups[key] = SyscallSequence(application=event.process, thread=key)
        groups[key].events.append(event)
    for seq in groups.values():
        seq.events.sort(key=lambda e: (e.timestamp, e.evt_num))
    return groups


def find_event(events: Iterable[LogEvent], event_id: str) -> LogEvent | None:
    for event in events:
        if event.event_id == event_id:
            return event
    return None
