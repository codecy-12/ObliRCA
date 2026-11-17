#!/usr/bin/env python
"""Run one baseline adapter on a JSON evidence file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obli_rca.evaluation.baselines import BaselineInput, baseline_names, run_baseline  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--method", default="LocAgent")
    parser.add_argument("--input", default=None, help="JSON file with BaselineInput fields")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(baseline_names(), indent=2))
        return 0
    payload = {}
    if args.input:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    data = BaselineInput(
        scenario_id=str(payload.get("scenario_id", "scenario")),
        source_roots=payload.get("source_roots", {}),
        functions=payload.get("functions", []),
        test_results=payload.get("test_results", []),
        coverage=payload.get("coverage", {}),
        trace_functions=payload.get("trace_functions", []),
        crash_functions=payload.get("crash_functions", []),
        problem_report=payload.get("problem_report", ""),
        address_map=payload.get("address_map", {}),
    )
    result = run_baseline(args.method, data).to_dict()
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
