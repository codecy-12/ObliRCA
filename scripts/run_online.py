#!/usr/bin/env python
"""Run the online pipeline for one scenario."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obli_rca.config import Config  # noqa: E402
from obli_rca.models.scenario import BenchmarkManifest, Scenario, Symptom  # noqa: E402
from obli_rca.online.pipeline import OnlinePipeline  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--logs", required=True)
    parser.add_argument("--source", action="append", default=[], help="app=path")
    parser.add_argument("--symptom-event", default=None)
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    config = Config.load(args.config)
    requested = Path(args.scenario)
    scenario = None
    candidate_json = requested / "scenario.json" if requested.is_dir() else requested
    if candidate_json.exists() and candidate_json.suffix == ".json":
        scenario = Scenario.from_dict(json.loads(candidate_json.read_text(encoding="utf-8")))
    if scenario is None:
        manifest_path = ROOT / "benchmark" / "manifest.json"
        if manifest_path.exists():
            scenario = BenchmarkManifest.load(manifest_path).get(args.scenario)
    if scenario is None:
        directory = ROOT / "benchmark" / "scenarios" / args.scenario
        if (directory / "scenario.json").exists():
            scenario = Scenario.from_dict(json.loads((directory / "scenario.json").read_text(encoding="utf-8")))
        else:
            raise SystemExit(f"scenario not found: {args.scenario}")
    sources = {}
    for item in args.source:
        app, path = item.split("=", 1)
        sources[app] = path
    event = args.symptom_event or (scenario.symptom.event_id if scenario.symptom else None)
    if event is None:
        raise SystemExit("pass --symptom-event")
    scenario.symptom = scenario.symptom or Symptom(event, next(iter(sources)), "cli symptom")
    scenario.symptom.event_id = event
    pipeline = OnlinePipeline(config, use_llm=not args.no_llm, dry_run=True)
    report = pipeline.run_scenario(
        scenario,
        log_path=args.logs,
        source_roots=sources,
        source_versions=scenario.versions,
    )
    print(report.to_markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
