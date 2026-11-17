#!/usr/bin/env python
"""Create an immutable snapshot of the obligation library."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "obligations"
TARGET = SOURCE / "frozen"


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    files = []
    library = []
    graph_total = 0
    for path in sorted(SOURCE.glob("*.yaml")):
        if path.parent == TARGET:
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = TARGET / path.name
        shutil.copy2(path, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        files.append({"file": path.name, "sha256": digest})
        library.append(data)
        graph_total += len(data.get("graphs", []))
    manifest = {
        "version": "1.0.0",
        "frozen_at": datetime.now(timezone.utc).date().isoformat(),
        "entry_count": len(library),
        "graph_count": graph_total,
        "source_case_count": 1323,
        "files": files,
    }
    (TARGET / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (TARGET / "library.json").write_text(
        json.dumps(library, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"frozen {len(library)} entries, {graph_total} graphs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
