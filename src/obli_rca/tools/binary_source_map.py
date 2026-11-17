"""Binary address to source mapping for the PoC-assisted setting."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models.code import CodeLocation
from .dwarf import DwarfMapper


@dataclass
class AddressRecord:
    address: int | str
    event_id: str = ""
    process: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MappedTrace:
    binary: str
    records: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    def functions(self) -> list[str]:
        seen: list[str] = []
        for record in self.records:
            function = record.get("function", "")
            if function and function not in seen:
                seen.append(function)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "records": self.records,
            "unresolved": self.unresolved,
        }


class BinarySourceMap:
    def __init__(self, binary: str | Path, mapper: DwarfMapper | None = None):
        self.binary = Path(binary)
        self.mapper = mapper or DwarfMapper(self.binary)

    def map_records(self, records: list[AddressRecord]) -> MappedTrace:
        mapped = MappedTrace(str(self.binary))
        for record in records:
            location = self.mapper.map_address(record.address)
            if location is None:
                mapped.unresolved.append(str(record.address))
                continue
            mapped.records.append(
                {
                    "address": str(record.address),
                    "event_id": record.event_id,
                    "process": record.process,
                    "file": location.file,
                    "function": location.function,
                    "line": location.line,
                }
            )
        return mapped

    def nearest(self, address: int, window: int = 64) -> list[CodeLocation]:
        locations = []
        for delta in range(0, window + 1):
            for candidate in {address - delta, address + delta}:
                location = self.mapper.map_address(candidate)
                if location is not None and location not in locations:
                    locations.append(location)
        return locations


def trace_functions(trace: MappedTrace) -> list[str]:
    return trace.functions()
