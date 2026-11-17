#!/usr/bin/env python
"""Generate the 1,323-case metadata index.

The repository does not vendor the historical source trees, patches, or logs.
This file preserves the corpus counts, category distribution, cross-application
split, and frozen status. Case identities are opaque; the actual evidence stays
in the external build store.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "corpus"

CATEGORIES = [
    ("Path Constraints", 1, 128),
    ("Authorization Checks", 2, 181),
    ("Resource Bounds", 3, 139),
    ("Protocol State Constraints", 4, 91),
    ("Memory Bounds", 5, 332),
    ("Input Sanitization", 6, 237),
    ("Secure Defaults", 7, 47),
    ("Concurrency Ordering", 8, 55),
    ("Resource Lifecycles", 9, 41),
    ("Object Lifecycles", 10, 72),
]

CROSS_APPLICATION = 142
TOTAL = 1323


def main() -> int:
    labels = []
    for name, category_id, count in CATEGORIES:
        labels.extend([(name, category_id)] * count)
    if len(labels) != TOTAL:
        raise SystemExit(f"category counts do not sum to {TOTAL}: {len(labels)}")
    rng = random.Random(7)
    rng.shuffle(labels)
    cross_indices = sorted({round(i * (TOTAL - 1) / (CROSS_APPLICATION - 1)) for i in range(CROSS_APPLICATION)})
    if len(cross_indices) != CROSS_APPLICATION:
        raise SystemExit(f"cross-application index generation failed: {len(cross_indices)}")
    cross_set = set(cross_indices)
    OUT.mkdir(parents=True, exist_ok=True)
    records = []
    for index, (name, category_id) in enumerate(labels):
        records.append(
            {
                "case_id": f"build-{index + 1:04d}",
                "category": name,
                "category_id": category_id,
                "is_cross_application": index in cross_set,
                "split": "offline_build",
                "library_version": "1.0.0",
                "identity_status": "opaque",
                "metadata_status": "metadata_only",
                "source": "external_corpus",
                "metadata": {},
            }
        )
    with (OUT / "metadata.jsonl").open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")
    stats = {
        "total": len(records),
        "cross_application": sum(1 for record in records if record["is_cross_application"]),
        "by_category": {
            name: sum(1 for record in records if record["category"] == name)
            for name, _, _ in CATEGORIES
        },
        "identity_status": "opaque",
        "frontier": {"library_version": "1.0.0", "frozen_before_evaluation": True},
    }
    (OUT / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["case_id", "category", "category_id", "split"],
                "properties": {
                    "case_id": {"type": "string"},
                    "category": {"type": "string"},
                    "category_id": {"type": "integer"},
                    "is_cross_application": {"type": "boolean"},
                    "split": {"type": "string"},
                    "library_version": {"type": "string"},
                    "identity_status": {"type": "string"},
                    "metadata_status": {"type": "string"},
                    "source": {"type": "string"},
                    "metadata": {"type": "object"},
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(records)} metadata records; cross-application={stats['cross_application']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
