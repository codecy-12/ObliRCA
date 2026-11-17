#!/usr/bin/env python
"""Small wrapper around the offline flywheel for manual experiments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obli_rca.config import Config  # noqa: E402
from obli_rca.offline.assessment_agent import AssessmentAgent  # noqa: E402
from obli_rca.offline.consolidation_agent import ConsolidationAgent  # noqa: E402
from obli_rca.offline.corpus import Corpus  # noqa: E402
from obli_rca.offline.extraction_agent import ExtractionAgent  # noqa: E402
from obli_rca.offline.flywheel import DataFlywheel  # noqa: E402
from obli_rca.storage.database import Database  # noqa: E402
from obli_rca.storage.investigation_store import InvestigationStore  # noqa: E402
from obli_rca.storage.obligation_store import ObligationStore  # noqa: E402
from obli_rca.tools.registry import build_registry  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="data/corpus.jsonl")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    config = Config.load(args.config)
    corpus = Corpus.load(ROOT / args.corpus)
    if args.limit:
        corpus = Corpus(corpus.cases[: args.limit])
    db = Database(config.db_url)
    db.init_schema()
    store = ObligationStore(db)
    tools = build_registry(config, dry_run=True)
    flywheel = DataFlywheel(
        config,
        ExtractionAgent(config),
        AssessmentAgent(config, tools, InvestigationStore(db)),
        ConsolidationAgent(config, store),
        store,
    )
    result = flywheel.run(corpus, dry_run=True)
    print(json.dumps(result.stats.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
