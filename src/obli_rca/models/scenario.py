"""Benchmark scenario metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ScenarioGroup(str, Enum):
    CROSS_PROGRAM = "cross_program"
    MULTIPLE_ROOT = "multiple_root"
    SINGLE_PROGRAM = "single_program"

    @classmethod
    def from_label(cls, label: str) -> "ScenarioGroup":
        normalized = label.lower().replace("-", "_").replace(" ", "_")
        mapping = {
            "cross_program": cls.CROSS_PROGRAM,
            "cross_process": cls.CROSS_PROGRAM,
            "multiple_root": cls.MULTIPLE_ROOT,
            "multiple_root_cause": cls.MULTIPLE_ROOT,
            "multiple_root_cause_program": cls.MULTIPLE_ROOT,
            "chain_cve": cls.MULTIPLE_ROOT,
            "single_program": cls.SINGLE_PROGRAM,
            "single_program_benchmark": cls.SINGLE_PROGRAM,
        }
        if normalized not in mapping:
            raise ValueError(f"unknown scenario group: {label}")
        return mapping[normalized]


@dataclass
class Symptom:
    event_id: str
    application: str
    description: str
    timestamp: str = ""


@dataclass
class GroundTruthRoot:
    locations: list[dict[str, Any]] = field(default_factory=list)
    obligations: list[str] = field(default_factory=list)
    mechanisms: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class Scenario:
    id: str
    group: ScenarioGroup
    cves: list[str]
    applications: list[str]
    versions: dict[str, str] = field(default_factory=dict)
    directory: str = ""
    log_path: str = ""
    source_root: str = ""
    symptom: Symptom | None = None
    hops: int = 0
    root_causes: list[GroundTruthRoot] = field(default_factory=list)
    n_l: bool = False
    annotation_status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "group": self.group.value,
            "cves": self.cves,
            "applications": self.applications,
            "versions": self.versions,
            "directory": self.directory,
            "log_path": self.log_path,
            "source_root": self.source_root,
            "symptom": self.symptom.__dict__ if self.symptom else None,
            "hops": self.hops,
            "root_causes": [r.__dict__ for r in self.root_causes],
            "n_l": self.n_l,
            "annotation_status": self.annotation_status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        symptom = Symptom(**data["symptom"]) if data.get("symptom") else None
        roots = [GroundTruthRoot(**r) for r in data.get("root_causes", [])]
        return cls(
            id=data["id"],
            group=ScenarioGroup.from_label(data["group"]),
            cves=list(data.get("cves", [])),
            applications=list(data.get("applications", [])),
            versions=dict(data.get("versions", {})),
            directory=data.get("directory", ""),
            log_path=data.get("log_path", ""),
            source_root=data.get("source_root", ""),
            symptom=symptom,
            hops=int(data.get("hops", 0)),
            root_causes=roots,
            n_l=bool(data.get("n_l", False)),
            annotation_status=data.get("annotation_status", "pending"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class BenchmarkManifest:
    scenarios: list[Scenario]
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def by_group(self, group: ScenarioGroup) -> list[Scenario]:
        return [s for s in self.scenarios if s.group == group]

    def get(self, scenario_id: str) -> Scenario | None:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        return None

    def stats(self) -> dict[str, Any]:
        result: dict[str, Any] = {"total": len(self.scenarios)}
        for group in ScenarioGroup:
            items = self.by_group(group)
            result[group.value] = {
                "scenarios": len(items),
                "cves": len({c for s in items for c in s.cves}),
                "applications": len({a for s in items for a in s.applications}),
                "n_l": sum(1 for s in items if s.n_l),
            }
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "metadata": self.metadata,
            "scenarios": [s.to_dict() for s in self.scenarios],
        }

    @classmethod
    def load(cls, path: str | Path) -> "BenchmarkManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            scenarios=[Scenario.from_dict(item) for item in data.get("scenarios", [])],
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
