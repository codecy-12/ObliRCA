#!/usr/bin/env python
"""Evaluate the frozen benchmark manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obli_rca.config import Config  # noqa: E402
from obli_rca.evaluation.runner import BenchmarkRunner  # noqa: E402
from obli_rca.models.scenario import BenchmarkManifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="benchmark/manifest.json")
    parser.add_argument("--log-dir", default="data/logs")
    parser.add_argument("--source-dir", default="data/sources")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    config = Config.load(args.config)
    manifest = BenchmarkManifest.load(ROOT / args.manifest)
    runner = BenchmarkRunner(config, use_llm=not args.no_llm, dry_run=True)
    result = runner.run(manifest, log_dir=ROOT / args.log_dir, source_dir=ROOT / args.source_dir)
    print(json.dumps(result.metrics, ensure_ascii=False, indent=2))
    if result.skipped:
        print(f"skipped {len(result.skipped)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
