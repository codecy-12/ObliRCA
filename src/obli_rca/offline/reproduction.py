"""Dual-version reproduction boundary.

The actual prototype runs vulnerable and fixed containers, captures sysdig logs,
and compares security consequences.  This module keeps the execution boundary
explicit and supports a dry-run mode that consumes pre-recorded artifacts.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Config


@dataclass
class ReproductionResult:
    status: str
    vulnerable_log: str = ""
    fixed_log: str = ""
    vulnerable_exit: int | None = None
    fixed_exit: int | None = None
    notes: str = ""
    commands: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "vulnerable_log": self.vulnerable_log,
            "fixed_log": self.fixed_log,
            "vulnerable_exit": self.vulnerable_exit,
            "fixed_exit": self.fixed_exit,
            "notes": self.notes,
            "commands": self.commands or [],
        }


class DualVersionReproducer:
    def __init__(self, config: Config, dry_run: bool = True):
        self.config = config
        self.dry_run = dry_run
        self.timeout = int(config.get("offline.reproduction.docker_timeout_seconds", 600))

    def reproduce(
        self,
        scenario_dir: str | Path,
        *,
        vulnerable_log: str | None = None,
        fixed_log: str | None = None,
    ) -> ReproductionResult:
        root = Path(scenario_dir)
        compose = root / "docker-compose.yml"
        if not compose.exists():
            return ReproductionResult("missing-compose", notes=f"not found: {compose}")
        commands = [
            f"docker compose -f {compose} up -d --build",
            f"sysdig -w {root / 'vulnerable.scap'}",
            f"docker compose -f {compose} down -v",
        ]
        if self.dry_run:
            return ReproductionResult(
                "dry-run",
                vulnerable_log=vulnerable_log or "",
                fixed_log=fixed_log or "",
                commands=commands,
                notes="reproduction disabled; using recorded artifacts",
            )
        if not shutil.which("docker"):
            return ReproductionResult("unavailable", commands=commands, notes="docker not found")
        proc = subprocess.run(
            commands[0].split(),
            cwd=root,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        return ReproductionResult(
            "ok" if proc.returncode == 0 else "error",
            vulnerable_log=vulnerable_log or "",
            fixed_log=fixed_log or "",
            notes=proc.stderr[-2000:],
            commands=commands,
        )
