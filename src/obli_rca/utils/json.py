"""Small JSON helpers shared by agents and tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dumps(value: Any, indent: int | None = 2) -> str:
    return json.dumps(value, ensure_ascii=False, indent=indent, default=str)


def loads(text: str) -> Any:
    return json.loads(text)


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2, default=str)
        fh.write("\n")


def parse_jsonish(text: str) -> Any:
    """Parse JSON from a model response, tolerating markdown fences."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        stripped = stripped[start : end + 1]
    return json.loads(stripped)
