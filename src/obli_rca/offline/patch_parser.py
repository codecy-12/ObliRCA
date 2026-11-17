"""Unified-diff parsing and repair-region extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")


@dataclass
class Hunk:
    file: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)

    def added_lines(self) -> list[str]:
        return [line[1:] for line in self.lines if line.startswith("+") and not line.startswith("+++")]

    def removed_lines(self) -> list[str]:
        return [line[1:] for line in self.lines if line.startswith("-") and not line.startswith("---")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "old_start": self.old_start,
            "old_count": self.old_count,
            "new_start": self.new_start,
            "new_count": self.new_count,
            "added": self.added_lines(),
            "removed": self.removed_lines(),
        }


@dataclass
class ParsedPatch:
    files: list[str] = field(default_factory=list)
    hunks: list[Hunk] = field(default_factory=list)
    raw: str = ""

    def changed_lines(self) -> list[dict[str, Any]]:
        return [h.to_dict() for h in self.hunks]

    def guard_like_lines(self) -> list[str]:
        patterns = [
            r"\bif\s*\(",
            r"\breturn\b",
            r"\bcheck\b",
            r"\bvalidate\b",
            r"\bverify\b",
            r"\bauth",
            r"\blimit\b",
            r"\bbound",
            r"\bnull\b",
            r"\bclose\b",
            r"\bfree\b",
        ]
        result = []
        for hunk in self.hunks:
            for line in hunk.added_lines() + hunk.removed_lines():
                if any(re.search(p, line, re.I) for p in patterns):
                    result.append(line.strip())
        return result


def parse_patch(path_or_text: str | Path) -> ParsedPatch:
    p = Path(path_or_text)
    text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else str(path_or_text)
    patch = ParsedPatch(raw=text)
    current_file = ""
    current_hunk: Hunk | None = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            current_file = line[4:].strip().split("\t")[0]
            if current_file.startswith("b/"):
                current_file = current_file[2:]
            if current_file not in patch.files:
                patch.files.append(current_file)
            continue
        match = _HUNK_RE.match(line)
        if match:
            if current_hunk:
                patch.hunks.append(current_hunk)
            current_hunk = Hunk(
                file=current_file,
                old_start=int(match.group("old_start")),
                old_count=int(match.group("old_count") or 1),
                new_start=int(match.group("new_start")),
                new_count=int(match.group("new_count") or 1),
            )
            continue
        if current_hunk is not None and (line.startswith(("+", "-", " ")) or not line):
            current_hunk.lines.append(line)
    if current_hunk:
        patch.hunks.append(current_hunk)
    return patch
