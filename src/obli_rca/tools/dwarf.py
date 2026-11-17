"""DWARF line mapping used by the PoC-assisted ObliRCA-P setting."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models.code import CodeLocation


@dataclass
class DwarfConfig:
    addr2line_bin: str = "addr2line"
    readelf_bin: str = "readelf"
    timeout_seconds: int = 30


class DwarfMapper:
    def __init__(self, binary: str | Path, config: DwarfConfig | None = None):
        self.binary = Path(binary)
        self.config = config or DwarfConfig()

    def available(self) -> bool:
        return self.binary.exists() and bool(shutil.which(self.config.addr2line_bin))

    def map_address(self, address: int | str) -> CodeLocation | None:
        if not self.available():
            return None
        addr = hex(address) if isinstance(address, int) else str(address)
        proc = subprocess.run(
            [self.config.addr2line_bin, "-e", str(self.binary), "-f", "-C", addr],
            capture_output=True,
            text=True,
            timeout=self.config.timeout_seconds,
            check=False,
        )
        if proc.returncode != 0:
            return None
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if len(lines) < 2 or lines[1] in {"??:0", "??:?"}:
            return None
        function = lines[0]
        file_line = lines[1]
        match = re.match(r"^(.*):(\d+)$", file_line)
        if not match:
            return None
        return CodeLocation(match.group(1), function, int(match.group(2)))

    def map_addresses(self, addresses: list[int | str]) -> list[CodeLocation]:
        return [loc for loc in (self.map_address(a) for a in addresses) if loc is not None]

    def dump_lines(self) -> dict[str, Any]:
        if not shutil.which(self.config.readelf_bin):
            return {"status": "unavailable"}
        proc = subprocess.run(
            [self.config.readelf_bin, "--debug-dump=decodedline", str(self.binary)],
            capture_output=True,
            text=True,
            timeout=self.config.timeout_seconds,
            check=False,
        )
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "returncode": proc.returncode,
            "output": proc.stdout[-20000:],
            "stderr": proc.stderr[-2000:],
        }


class DwarfTool:
    name = "dwarf"
    description = "Map binary addresses to source locations through DWARF line tables."
    input_schema = {
        "type": "object",
        "properties": {
            "binary": {"type": "string"},
            "addresses": {"type": "array"},
        },
    }

    def run(self, ctx, **kwargs: Any):  # pragma: no cover - thin adapter
        from .base import ToolResult

        mapper = DwarfMapper(kwargs["binary"])
        locations = mapper.map_addresses(kwargs.get("addresses", []))
        return ToolResult(ok=True, data={"locations": [loc.to_dict() for loc in locations]})
