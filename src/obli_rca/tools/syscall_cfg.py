"""Syscall-Function Matching.

The implementation is deliberately self-contained: it builds a lightweight CFG
from source text and matches a syscall sequence to candidate basic-block paths.
When Joern is available, :mod:`obli_rca.tools.joern` can supply a richer CFG and
call graph through the same :class:`ProgramCFG` interface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..models.code import BasicBlock, CFGPath, CodeLocation, FunctionSlice, SyscallSite
from ..models.evidence import EvidenceKind
from ..models.log import LogEvent, SyscallSequence
from ..utils.text import compact
from .base import BaseTool, ToolContext, ToolResult, evidence_for_tool

SYSCALLS = {
    "recv",
    "recvfrom",
    "recvmsg",
    "read",
    "pread",
    "pread64",
    "open",
    "openat",
    "creat",
    "write",
    "writev",
    "send",
    "sendto",
    "sendmsg",
    "sendfile",
    "splice",
    "fstat",
    "newfstatat",
    "close",
    "accept",
    "accept4",
    "connect",
    "socket",
    "pipe",
    "pipe2",
    "kill",
    "tgkill",
    "mmap",
    "munmap",
    "malloc",
    "free",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "readlink",
    "realpath",
    "stat",
    "lstat",
    "chdir",
    "chroot",
    "pivot_root",
    "setuid",
    "seteuid",
    "setresuid",
}

SYSCALL_ALIASES = {
    "recv": {"recv", "recvfrom", "recvmsg"},
    "read": {"read", "pread", "pread64"},
    "open": {"open", "openat", "creat"},
    "write": {"write", "writev", "send", "sendto", "sendmsg"},
    "sendfile": {"sendfile", "splice"},
    "stat": {"stat", "lstat", "fstat", "newfstatat"},
    "accept": {"accept", "accept4"},
    "chroot": {"chroot", "pivot_root"},
}

CALL_RE = re.compile(
    r"\b(" + "|".join(sorted(SYSCALLS, key=len, reverse=True)) + r")\s*\(",
)
C_FUNC_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|extern\s+|__\w+\s+)*"
    r"(?:[A-Za-z_][\w:<>*&,\s]*?)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.M,
)
PY_FUNC_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", re.M)
RB_FUNC_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)", re.M)
GO_FUNC_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", re.M)
JAVA_FUNC_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|\s)+"
    r"[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.M,
)


@dataclass
class SourceFunction:
    name: str
    file: str
    start_line: int
    end_line: int
    text: str
    calls: list[str] = field(default_factory=list)
    sites: list[SyscallSite] = field(default_factory=list)


@dataclass
class ProgramCFG:
    application: str
    source_version: str
    blocks: dict[str, BasicBlock]
    functions: dict[str, SourceFunction]
    entry_blocks: list[str] = field(default_factory=list)
    call_graph: dict[str, set[str]] = field(default_factory=dict)

    def candidates(self, event: LogEvent) -> list[BasicBlock]:
        result = []
        for block in self.blocks.values():
            if any(site.matches(event.syscall) for site in block.sites):
                result.append(block)
        return result

    def functions_for_blocks(self, blocks: Iterable[BasicBlock]) -> list[str]:
        seen: list[str] = []
        for block in blocks:
            if block.function not in seen:
                seen.append(block.function)
        return seen


def iter_source_files(root: str | Path, suffixes: tuple[str, ...] | None = None) -> list[Path]:
    root = Path(root)
    suffixes = suffixes or (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".py", ".go", ".java", ".rb")
    skip = {".git", "node_modules", "dist", "build", "vendor", "third_party"}
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in skip for part in path.parts):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        files.append(path)
    return sorted(files)


def _find_c_function(text: str, match: re.Match[str]) -> tuple[int, int] | None:
    start = text.find("{", match.start())
    if start < 0:
        return None
    depth = 0
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return match.start(), idx
    return None


def _find_indent_function(text: str, match: re.Match[str], min_indent: int = 0) -> tuple[int, int]:
    lines = text.splitlines(keepends=True)
    start_line = text[: match.start()].count("\n")
    end_line = len(lines) - 1
    base_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
    for idx in range(start_line + 1, len(lines)):
        line = lines[idx]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent and not line.lstrip().startswith(("#", "//")):
            end_line = idx - 1
            break
    start_offset = sum(len(l) for l in lines[:start_line])
    end_offset = sum(len(l) for l in lines[: end_line + 1])
    return start_offset, end_offset


def extract_functions(path: Path, root: Path, application: str, source_version: str) -> list[SourceFunction]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    patterns = [C_FUNC_RE, PY_FUNC_RE, GO_FUNC_RE, JAVA_FUNC_RE, RB_FUNC_RE]
    functions: list[SourceFunction] = []
    seen: set[tuple[str, int]] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            if name in {"if", "for", "while", "switch", "catch", "return"}:
                continue
            if path.suffix.lower() in {".py", ".rb"}:
                span = _find_indent_function(text, match)
            else:
                span = _find_c_function(text, match)
            if span is None:
                continue
            start, end = span
            start_line = text[:start].count("\n") + 1
            end_line = text[:end].count("\n") + 1
            key = (name, start_line)
            if key in seen:
                continue
            seen.add(key)
            body = text[start:end]
            sites = []
            for call in CALL_RE.finditer(body):
                call_name = call.group(1)
                line = start_line + body[: call.start()].count("\n")
                sites.append(
                    SyscallSite(
                        call_name,
                        line,
                        compact(body[call.start(): call.start() + 160]),
                        aliases=_aliases_for(call_name),
                    )
                )
            sites = _dedupe_sites(sites)
            calls = sorted({m.group(1) for m in CALL_RE.finditer(body)})
            functions.append(
                SourceFunction(
                    name=name,
                    file=rel,
                    start_line=start_line,
                    end_line=end_line,
                    text=body,
                    calls=calls,
                    sites=sites,
                )
            )
    return functions


def _aliases_for(name: str) -> list[str]:
    aliases: set[str] = set()
    for names in SYSCALL_ALIASES.values():
        if name in names:
            aliases.update(names)
    aliases.discard(name)
    return sorted(aliases)


def _dedupe_sites(sites: list[SyscallSite]) -> list[SyscallSite]:
    seen: set[tuple[str, int]] = set()
    result = []
    for site in sites:
        key = (site.syscall, site.line)
        if key not in seen:
            seen.add(key)
            result.append(site)
    return result


def build_program_cfg(
    application: str,
    source_version: str,
    source_root: str | Path,
    max_files: int = 400,
) -> ProgramCFG:
    root = Path(source_root)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"source root not found or not a directory: {root}")
    functions: dict[str, SourceFunction] = {}
    blocks: dict[str, BasicBlock] = {}
    entry_blocks: list[str] = []
    call_graph: dict[str, set[str]] = {}
    for path in iter_source_files(root)[:max_files]:
        for func in extract_functions(path, root, application, source_version):
            key = f"{func.file}:{func.name}:{func.start_line}"
            functions[key] = func
            call_graph.setdefault(func.name, set()).update(func.calls)
            if func.sites:
                for idx, site in enumerate(func.sites):
                    block_id = f"B-{len(blocks):04d}"
                    blocks[block_id] = BasicBlock(
                        id=block_id,
                        function=func.name,
                        file=func.file,
                        start_line=site.line,
                        end_line=site.line,
                        instructions=[site.expression],
                        sites=[site],
                        successors=[],
                        summary=f"{func.name} -> {site.syscall}",
                    )
                    if idx == 0:
                        entry_blocks.append(block_id)
                # Linear successor chain within a function, plus a branch marker
                # for the first site of each function.
                func_blocks = [b for b in blocks.values() if b.function == func.name]
                func_blocks.sort(key=lambda b: b.start_line)
                for left, right in zip(func_blocks, func_blocks[1:]):
                    if left.start_line != right.start_line:
                        left.successors.append(right.id)
                if func_blocks:
                    first = func_blocks[0]
                    if first.id not in entry_blocks:
                        entry_blocks.append(first.id)
    return ProgramCFG(application, source_version, blocks, functions, entry_blocks, call_graph)


@dataclass
class MatchOptions:
    allow_cross_function: bool = True
    max_paths: int = 8
    max_repeat: int = 3
    object_consistent: bool = True
    max_candidates_per_event: int = 200


def match_sequence(
    cfg: ProgramCFG,
    sequence: SyscallSequence,
    options: MatchOptions | None = None,
) -> list[CFGPath]:
    options = options or MatchOptions()
    events = [e for e in sequence.events if e.syscall in SYSCALLS or _alias_of(e.syscall)]
    if not events:
        return []
    candidates = [
        cfg.candidates(event)[: options.max_candidates_per_event]
        for event in events
    ]
    if any(not items for items in candidates):
        return []
    paths: list[CFGPath] = []
    used_counts: dict[str, int] = {}

    def dfs(index: int, chosen: list[BasicBlock], object_map: dict[str, str]) -> None:
        if len(paths) >= options.max_paths:
            return
        if index == len(events):
            score = _score_path(chosen, events, object_map)
            paths.append(
                CFGPath(
                    blocks=list(chosen),
                    events=[e.event_id for e in events],
                    score=score,
                    evidence=[f"matched {len(events)} syscalls across {len({b.function for b in chosen})} functions"],
                )
            )
            return
        event = events[index]
        for block in candidates[index]:
            if used_counts.get(block.id, 0) >= options.max_repeat:
                continue
            if chosen and not _reachable(chosen[-1], block, cfg, options):
                continue
            if options.object_consistent:
                conflict = _object_conflict(event, block, object_map)
                if conflict:
                    continue
            used_counts[block.id] = used_counts.get(block.id, 0) + 1
            chosen.append(block)
            new_map = dict(object_map)
            key = _object_key(event)
            if key:
                new_map[key] = block.function
            dfs(index + 1, chosen, new_map)
            chosen.pop()
            used_counts[block.id] -= 1

    dfs(0, [], {})
    paths.sort(key=lambda p: p.score, reverse=True)
    return paths[: options.max_paths]


def _alias_of(syscall: str) -> str | None:
    for base, aliases in SYSCALL_ALIASES.items():
        if syscall in aliases:
            return base
    return None


def _reachable(left: BasicBlock, right: BasicBlock, cfg: ProgramCFG, options: MatchOptions) -> bool:
    if left.id == right.id:
        return True
    if right.id in left.successors:
        return True
    if options.allow_cross_function and (
        right.function in cfg.call_graph.get(left.function, set())
        or left.function in cfg.call_graph.get(right.function, set())
        or left.function == right.function
    ):
        return True
    # Lightweight CFG: allow a forward jump in the same file when no explicit
    # successor was materialized.
    return left.file == right.file and right.start_line >= left.start_line


def _object_key(event: LogEvent) -> str | None:
    return event.tuple or event.path or (str(event.fd) if event.fd is not None else None)


def _object_conflict(event: LogEvent, block: BasicBlock, object_map: dict[str, str]) -> bool:
    key = _object_key(event)
    if key is None:
        return False
    previous = object_map.get(key)
    return previous is not None and previous != block.function


def _score_path(blocks: list[BasicBlock], events: list[LogEvent], object_map: dict[str, str]) -> float:
    functions = {b.function for b in blocks}
    score = 1.0
    score += 0.05 * len(functions)
    score += 0.02 * sum(1 for e in events if e.res not in (None, -1))
    score -= 0.01 * max(0, len(blocks) - len(events))
    if len(functions) > 1:
        score += 0.1
    return round(score, 4)


def function_slices(cfg: ProgramCFG, path: CFGPath) -> list[FunctionSlice]:
    result: list[FunctionSlice] = []
    seen: set[tuple[str, str]] = set()
    for block in path.blocks:
        key = (block.file, block.function)
        if key in seen:
            continue
        seen.add(key)
        func = next(
            (f for f in cfg.functions.values() if f.file == block.file and f.name == block.function),
            None,
        )
        result.append(
            FunctionSlice(
                application=cfg.application,
                source_version=cfg.source_version,
                file=block.file,
                function=block.function,
                start_line=func.start_line if func else block.start_line,
                end_line=func.end_line if func else block.end_line,
                statements=(func.text.splitlines() if func else [block.summary]),
                callers=[],
                callees=sorted(cfg.call_graph.get(block.function, set())),
                event_ids=path.events,
                block_ids=[b.id for b in path.blocks if b.function == block.function],
            )
        )
    return result


class SyscallCFGTool(BaseTool):
    name = "syscall_cfg"
    description = "Match a syscall sequence to source CFG blocks and extract function slices."
    input_schema = {
        "type": "object",
        "properties": {
            "action": {"enum": ["build", "match", "slice"]},
            "source_root": {"type": "string"},
            "application": {"type": "string"},
            "source_version": {"type": "string"},
            "events": {"type": "array"},
            "sequence": {"type": "object"},
        },
    }

    def __init__(self, cfg: ProgramCFG | None = None):
        self.cfg = cfg

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "match")
        if action == "build":
            self.cfg = build_program_cfg(
                kwargs.get("application", "unknown"),
                kwargs.get("source_version", "unknown"),
                kwargs["source_root"],
            )
            return ToolResult(
                ok=True,
                data={
                    "blocks": len(self.cfg.blocks),
                    "functions": len(self.cfg.functions),
                    "application": self.cfg.application,
                },
                evidence=[
                    evidence_for_tool(
                        EvidenceKind.SOURCE,
                        self.name,
                        "CFG built from incident-version source",
                        kwargs["source_root"],
                        {"blocks": len(self.cfg.blocks), "functions": len(self.cfg.functions)},
                    )
                ],
            )
        if self.cfg is None:
            if not kwargs.get("source_root"):
                raise ValueError("build the CFG first or provide source_root")
            self.cfg = build_program_cfg(
                kwargs.get("application", "unknown"),
                kwargs.get("source_version", "unknown"),
                kwargs["source_root"],
            )
        sequence = kwargs.get("sequence")
        if sequence is None:
            sequence = SyscallSequence(
                application=kwargs.get("application", self.cfg.application),
                thread=(kwargs.get("application", ""), 0, 0),
                events=[],
            )
        if isinstance(sequence, dict):
            events = [LogEvent(**e) for e in sequence.get("events", [])]
            sequence = SyscallSequence(
                application=sequence.get("application", self.cfg.application),
                thread=tuple(sequence.get("thread", ("", 0, 0))),
                events=events,
            )
        if not sequence.events:
            return ToolResult(ok=True, data={"paths": [], "count": 0}, evidence=[])
        paths = match_sequence(self.cfg, sequence)
        data = [p.to_dict() for p in paths]
        evidence = [
            evidence_for_tool(
                EvidenceKind.SOURCE,
                self.name,
                f"syscall sequence matched to {len(paths)} CFG paths",
                self.cfg.application,
                {"paths": len(paths), "events": len(sequence.events)},
            )
        ]
        if action == "slice" and paths:
            slices = function_slices(self.cfg, paths[0])
            return ToolResult(
                ok=True,
                data={"slices": [s.to_dict() for s in slices], "paths": data},
                evidence=evidence,
            )
        return ToolResult(ok=True, data={"paths": data, "count": len(paths)}, evidence=evidence)
