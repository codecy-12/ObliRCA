"""Unified adapters for the external tools used by the prototype.

The adapters keep sysdig, Joern, and angr behind small interfaces so the agents
do not depend on a particular binary layout.  Each adapter degrades explicitly
when the tool or its input is unavailable.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models.code import CodeLocation
from ..models.log import LogEvent
from .angr_check import AngrChecker, AngrConfig
from .joern import JoernClient, JoernConfig
from .log_query import LogIndex


@dataclass
class ToolAvailability:
    available: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"available": self.available, "reason": self.reason}


class SysdigAdapter:
    name = "sysdig"

    def __init__(self, binary: str = "sysdig"):
        self.binary = binary

    def availability(self) -> ToolAvailability:
        if shutil.which(self.binary):
            return ToolAvailability(True)
        return ToolAvailability(False, f"{self.binary} not found")

    def parse(self, path: str | Path) -> list[LogEvent]:
        return LogIndex.from_file(path).events

    def capture_command(self, output: str | Path, filter_expr: str = "") -> list[str]:
        command = [self.binary, "-w", str(output)]
        if filter_expr:
            command.append(filter_expr)
        return command


class JoernAdapter:
    name = "joern"

    def __init__(self, config: JoernConfig | None = None):
        self.client = JoernClient(config or JoernConfig())

    def availability(self) -> ToolAvailability:
        if self.client.available():
            return ToolAvailability(True)
        return ToolAvailability(False, "joern executable not found")

    def export(self, source_root: str | Path, out_dir: str | Path) -> dict[str, Any]:
        return self.client.export(source_root, out_dir)

    def methods(self, cpg_path: str | Path) -> list[dict[str, Any]]:
        return self.client.query_methods(cpg_path)


class AngrAdapter:
    name = "angr"

    def __init__(self, config: AngrConfig | None = None):
        self.checker = AngrChecker(config or AngrConfig(enabled=True))

    def availability(self) -> ToolAvailability:
        if self.checker.available():
            return ToolAvailability(True)
        return ToolAvailability(False, "angr unavailable or disabled")

    def check(self, binary: str | Path, **kwargs: Any):
        return self.checker.check(binary, **kwargs)


def probe_tools() -> dict[str, dict[str, Any]]:
    """Return a machine-readable availability report for the three adapters."""
    return {
        "sysdig": SysdigAdapter().availability().to_dict(),
        "joern": JoernAdapter().availability().to_dict(),
        "angr": AngrAdapter().availability().to_dict(),
    }


def map_address(binary: str | Path, address: int | str) -> CodeLocation | None:
    """Convenience wrapper for the DWARF adapter used by the PoC-assisted mode."""
    from .dwarf import DwarfMapper

    return DwarfMapper(binary).map_address(address)
