"""Offline corpus records and loading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CorpusCase:
    case_id: str
    cve: str = ""
    project: str = ""
    category: str = ""
    vulnerable_version: str = ""
    fixed_version: str = ""
    patch_path: str = ""
    vulnerable_source: str = ""
    fixed_source: str = ""
    vulnerable_log: str = ""
    ground_truth: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cve": self.cve,
            "project": self.project,
            "category": self.category,
            "vulnerable_version": self.vulnerable_version,
            "fixed_version": self.fixed_version,
            "patch_path": self.patch_path,
            "vulnerable_source": self.vulnerable_source,
            "fixed_source": self.fixed_source,
            "vulnerable_log": self.vulnerable_log,
            "ground_truth": self.ground_truth,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CorpusCase":
        return cls(
            case_id=str(data["case_id"]),
            cve=data.get("cve", ""),
            project=data.get("project", ""),
            category=data.get("category", ""),
            vulnerable_version=data.get("vulnerable_version", ""),
            fixed_version=data.get("fixed_version", ""),
            patch_path=data.get("patch_path", ""),
            vulnerable_source=data.get("vulnerable_source", ""),
            fixed_source=data.get("fixed_source", ""),
            vulnerable_log=data.get("vulnerable_log", ""),
            ground_truth=list(data.get("ground_truth", [])),
            metadata=dict(data.get("metadata", {})),
        )


class Corpus:
    def __init__(self, cases: list[CorpusCase]):
        self.cases = cases

    def __len__(self) -> int:
        return len(self.cases)

    def __iter__(self):
        return iter(self.cases)

    @classmethod
    def load(cls, path: str | Path) -> "Corpus":
        p = Path(path)
        if not p.exists():
            return cls([])
        if p.suffix.lower() == ".jsonl":
            cases = [
                CorpusCase.from_dict(json.loads(line))
                for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        else:
            payload = json.loads(p.read_text(encoding="utf-8"))
            items = payload.get("cases", payload) if isinstance(payload, dict) else payload
            cases = [CorpusCase.from_dict(item) for item in items]
        return cls(cases)

    def by_category(self, category: str) -> list[CorpusCase]:
        return [c for c in self.cases if c.category.lower() == category.lower()]

    def stats(self) -> dict[str, Any]:
        by_category: dict[str, int] = {}
        for case in self.cases:
            by_category[case.category or "unknown"] = by_category.get(case.category or "unknown", 0) + 1
        return {"cases": len(self.cases), "by_category": by_category}
