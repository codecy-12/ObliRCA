"""Text normalization helpers."""

from __future__ import annotations

import re

_WHITESPACE = re.compile(r"\s+")


def compact(text: str, limit: int = 400) -> str:
    text = _WHITESPACE.sub(" ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def identifiers(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text or "")


def normalize_symbol(name: str) -> str:
    name = name.strip()
    name = re.sub(r"\(.*\)$", "", name)
    name = name.split("::")[-1]
    return name
