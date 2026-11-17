"""Scenario deployment and sysdig capture helpers.

The benchmark definitions are included for auditability; this runner is not
invoked by the default test suite.  ``dry_run`` returns the planned commands
without starting containers.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import BaseTool, ToolContext, ToolResult


@dataclass
class ScenarioRunner:
    docker_bin: str = "docker"
    sysdig_bin: str = "sysdig"
    dry_run: bool = True
    timeout_seconds: int = 600

    def available(self) -> bool:
        return bool(shutil.which(self.docker_bin))

    def plan(self, scenario_dir: str | Path) -> list[str]:
        root = Path(scenario_dir)
        return [
            f"{self.docker_bin} compose -f {root / 'docker-compose.yml'} up -d --build",
            f"{self.sysdig_bin} -w {root / 'capture.scap'}",
            f"{self.docker_bin} compose -f {root / 'docker-compose.yml'} down -v",
        ]

    def run(self, scenario_dir: str | Path) -> dict[str, Any]:
        commands = self.plan(scenario_dir)
        if self.dry_run:
            return {"status": "dry-run", "commands": commands}
        if not self.available():
            return {"status": "unavailable", "reason": "docker not found", "commands": commands}
        root = Path(scenario_dir)
        results = []
        for command in commands[:1]:
            proc = subprocess.run(
                command.split(),
                cwd=root,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            results.append({"command": command, "returncode": proc.returncode, "stderr": proc.stderr[-2000:]})
        return {"status": "ok" if all(r["returncode"] == 0 for r in results) else "error", "results": results}


class DockerTool(BaseTool):
    name = "docker"
    description = "Plan or run a benchmark scenario with Docker Compose and sysdig."
    input_schema = {
        "type": "object",
        "properties": {
            "scenario_dir": {"type": "string"},
            "dry_run": {"type": "boolean", "default": True},
        },
    }

    def __init__(self, runner: ScenarioRunner | None = None):
        self.runner = runner or ScenarioRunner()

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        runner = self.runner
        if "dry_run" in kwargs:
            runner.dry_run = bool(kwargs["dry_run"])
        result = runner.run(kwargs["scenario_dir"])
        return ToolResult(ok=result.get("status") in {"ok", "dry-run"}, data=result)
