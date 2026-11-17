#!/usr/bin/env python
"""Check that the benchmark manifest and every scenario scaffold are present."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obli_rca.models.scenario import BenchmarkManifest  # noqa: E402


def main() -> int:
    manifest = BenchmarkManifest.load(ROOT / "benchmark" / "manifest.json")
    errors: list[str] = []
    if len(manifest.scenarios) != 102:
        errors.append(f"expected 102 scenarios, found {len(manifest.scenarios)}")
    required = {
        "docker-compose.yml",
        "Dockerfile",
        "scenario.json",
        "symptom.json",
        "annotation.json",
        "audit/manifest.json",
    }
    for scenario in manifest.scenarios:
        directory = ROOT / scenario.directory
        if not directory.is_dir():
            errors.append(f"{scenario.id}: missing directory {directory}")
            continue
        missing = [name for name in required if not (directory / name).exists()]
        if missing:
            errors.append(f"{scenario.id}: missing {missing}")
    print(f"scenarios: {len(manifest.scenarios)}")
    print(json.dumps(manifest.stats(), ensure_ascii=False, indent=2))
    if errors:
        print("errors:")
        for error in errors:
            print(" -", error)
        return 1
    print("scaffold check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
