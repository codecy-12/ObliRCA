"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config
from .errors import ObliRCAError
from .models.obligation import ObligationEntry
from .models.scenario import BenchmarkManifest, Scenario, ScenarioGroup, Symptom
from .offline.assessment_agent import AssessmentAgent
from .offline.consolidation_agent import ConsolidationAgent
from .offline.corpus import Corpus
from .offline.extraction_agent import ExtractionAgent
from .offline.flywheel import DataFlywheel
from .online.pipeline import OnlinePipeline
from .storage.database import Database
from .storage.investigation_store import InvestigationStore
from .storage.obligation_store import ObligationStore
from .tools.registry import build_registry
from .evaluation.runner import BenchmarkRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="obli-rca", description="ObliRCA prototype")
    parser.add_argument("--config", default=None, help="path to config/default.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create tables and import obligations/")
    sub.add_parser("validate-obligations", help="validate every YAML obligation entry")
    sub.add_parser("stats", help="show library and benchmark statistics")
    sub.add_parser("export-obligations", help="export the database library to obligations/")

    offline = sub.add_parser("offline", help="run the offline data flywheel")
    offline.add_argument("--corpus", default="data/corpus.jsonl")
    offline.add_argument("--dry-run", action="store_true")
    offline.add_argument("--no-llm", action="store_true")
    offline.add_argument("--limit", type=int, default=0)

    online = sub.add_parser("online", help="run online root-cause analysis")
    online.add_argument("--scenario", required=True, help="scenario id or directory")
    online.add_argument("--logs", required=True)
    online.add_argument("--source", action="append", default=[], help="app=path; repeatable")
    online.add_argument("--symptom-event", default=None)
    online.add_argument("--no-llm", action="store_true")
    online.add_argument("--dry-run", action="store_true")
    online.add_argument("--binary", default=None, help="analysis binary for angr")

    evaluate = sub.add_parser("evaluate", help="evaluate the frozen benchmark")
    evaluate.add_argument("--manifest", default="benchmark/manifest.json")
    evaluate.add_argument("--log-dir", default="data/logs")
    evaluate.add_argument("--source-dir", default="data/sources")
    evaluate.add_argument("--no-llm", action="store_true")
    evaluate.add_argument("--dry-run", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = Config.load(args.config)
    try:
        if args.command == "init-db":
            return _init_db(config)
        if args.command == "validate-obligations":
            return _validate_obligations(config)
        if args.command == "stats":
            return _stats(config)
        if args.command == "export-obligations":
            return _export(config)
        if args.command == "offline":
            return _offline(config, args)
        if args.command == "online":
            return _online(config, args)
        if args.command == "evaluate":
            return _evaluate(config, args)
    except ObliRCAError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 1


# ----------------------------------------------------------------------
def _db(config: Config) -> Database:
    db = Database(config.db_url)
    db.init_schema()
    return db


def _init_db(config: Config) -> int:
    db = _db(config)
    store = ObligationStore(db)
    entries = _load_obligation_files(config)
    for entry in entries:
        store.save(entry)
    print(f"initialized {config.db_url}; imported {len(entries)} obligations")
    return 0


def _load_obligation_files(config: Config) -> list[ObligationEntry]:
    directory = config.resolve(config.get("offline.obligation_dir", "obligations"))
    entries = []
    for path in sorted(Path(directory).glob("*.yaml")):
        entry = ObligationEntry.load(path)
        entries.append(entry)
    return entries


def _validate_obligations(config: Config) -> int:
    entries = _load_obligation_files(config)
    errors = 0
    for entry in entries:
        try:
            entry.validate(strict_abstractness=bool(config.get("offline.acceptance.forbid_concrete_identifiers", True)))
            print(f"ok   {entry.id}  {entry.category}  graphs={len(entry.graphs)}")
        except Exception as exc:  # noqa: BLE001
            errors += 1
            print(f"FAIL {entry.id}: {exc}")
    print(f"{len(entries) - errors}/{len(entries)} entries valid")
    return 1 if errors else 0


def _stats(config: Config) -> int:
    db = _db(config)
    store = ObligationStore(db)
    manifest_path = Path("benchmark/manifest.json")
    payload = {"library": store.stats()}
    if manifest_path.exists():
        payload["benchmark"] = BenchmarkManifest.load(manifest_path).stats()
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _export(config: Config) -> int:
    db = _db(config)
    store = ObligationStore(db)
    paths = store.export_yaml(config.resolve("obligations"))
    print(f"exported {len(paths)} entries")
    return 0


def _offline(config: Config, args: argparse.Namespace) -> int:
    corpus = Corpus.load(args.corpus)
    if args.limit:
        corpus = Corpus(corpus.cases[: args.limit])
    db = _db(config)
    store = ObligationStore(db)
    tools = build_registry(config, dry_run=True)
    extraction = ExtractionAgent(config, use_llm=not args.no_llm)
    assessment = AssessmentAgent(
        config,
        tools,
        InvestigationStore(db),
        use_llm=not args.no_llm,
    )
    consolidation = ConsolidationAgent(config, store)
    flywheel = DataFlywheel(config, extraction, assessment, consolidation, store)
    result = flywheel.run(corpus, dry_run=True)
    print(json.dumps(result.stats.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _online(config: Config, args: argparse.Namespace) -> int:
    scenario = _resolve_scenario(args.scenario)
    sources = {}
    for item in args.source:
        if "=" not in item:
            raise ObliRCAError("--source must be app=path")
        app, path = item.split("=", 1)
        if not app or not path:
            raise ObliRCAError("--source requires a non-empty app and path")
        sources[app] = path
    if not sources:
        raise ObliRCAError("at least one --source app=path is required")
    symptom_event = args.symptom_event
    if scenario.symptom and not symptom_event:
        symptom_event = scenario.symptom.event_id
    if symptom_event is None:
        raise ObliRCAError("scenario has no symptom event; pass --symptom-event")
    scenario.symptom = scenario.symptom or Symptom(
        event_id=symptom_event, application=next(iter(sources)), description="cli symptom"
    )
    if scenario.symptom:
        scenario.symptom.event_id = symptom_event
    pipeline = OnlinePipeline(config, use_llm=not args.no_llm, dry_run=args.dry_run)
    report = pipeline.run_scenario(
        scenario,
        log_path=args.logs,
        source_roots=sources,
        source_versions=scenario.versions,
        binary=args.binary,
    )
    print(report.to_markdown())
    return 0


def _evaluate(config: Config, args: argparse.Namespace) -> int:
    manifest = BenchmarkManifest.load(args.manifest)
    runner = BenchmarkRunner(config, use_llm=not args.no_llm, dry_run=args.dry_run)
    result = runner.run(
        manifest,
        log_dir=args.log_dir,
        source_dir=args.source_dir,
    )
    print(json.dumps(result.metrics, ensure_ascii=False, indent=2))
    if result.skipped:
        print(f"skipped {len(result.skipped)} scenarios (missing logs/source)")
    return 0


def _resolve_scenario(value: str) -> Scenario:
    path = Path(value)
    if path.is_dir():
        meta = path / "scenario.json"
        if meta.exists():
            return Scenario.from_dict(json.loads(meta.read_text(encoding="utf-8")))
        return Scenario(
            id=path.name,
            group=ScenarioGroup.CROSS_PROGRAM,
            cves=[],
            applications=[],
            directory=str(path),
        )
    manifest_path = Path("benchmark/manifest.json")
    if manifest_path.exists():
        manifest = BenchmarkManifest.load(manifest_path)
        scenario = manifest.get(value)
        if scenario:
            return scenario
    raise ObliRCAError(f"scenario not found: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
