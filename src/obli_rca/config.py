"""Configuration loading with ``${ENV:-default}`` interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationError

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            return os.environ.get(name, default if default is not None else "")

        return _ENV_PATTERN.sub(repl, value)
    return value


class Config:
    """Read-only nested configuration with dotted access."""

    def __init__(self, data: dict[str, Any], root: Path | None = None):
        self._data = data
        self.root = root or Path.cwd()

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        candidate = Path(path) if path else Path("config/default.yaml")
        if not candidate.exists():
            # Allow running from an installed package.
            candidate = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
        if not candidate.exists():
            raise ConfigurationError(f"configuration not found: {candidate}")
        with candidate.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(_interpolate(data), root=candidate.parent.parent)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def require(self, dotted: str) -> Any:
        sentinel = object()
        value = self.get(dotted, sentinel)
        if value is sentinel:
            raise ConfigurationError(f"missing configuration key: {dotted}")
        return value

    def as_dict(self) -> dict[str, Any]:
        return self._data

    def override(self, dotted: str, value: Any) -> "Config":
        import copy

        data = copy.deepcopy(self._data)
        node = data
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        return Config(data, root=self.root)

    def resolve(self, path: str | Path) -> Path:
        p = Path(path)
        return p if p.is_absolute() else (self.root / p)

    @property
    def db_url(self) -> str:
        return str(self.get("storage.url", "sqlite:///data/obli_rca.db"))

    @property
    def llm(self) -> dict[str, Any]:
        return dict(self.get("llm", {}))
