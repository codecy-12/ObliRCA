"""Tool registry construction."""

from __future__ import annotations

from ..config import Config
from .angr_check import AngrChecker, AngrTool
from .base import ToolRegistry
from .code_query import CodeQueryTool
from .cross_app import CrossAppSearchTool
from .docker_runner import DockerTool, ScenarioRunner
from .joern import JoernClient, JoernTool
from .log_query import LogQueryTool
from .provenance import ProvenanceTool
from .syscall_cfg import SyscallCFGTool
from .taint import TaintTool


def build_registry(config: Config, *, dry_run: bool = True) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(LogQueryTool())
    registry.register(ProvenanceTool())
    registry.register(SyscallCFGTool())
    registry.register(CrossAppSearchTool())
    registry.register(CodeQueryTool())
    registry.register(JoernTool(client=JoernClient()))
    registry.register(TaintTool())
    registry.register(AngrTool(checker=AngrChecker()))
    registry.register(DockerTool(runner=ScenarioRunner(dry_run=dry_run)))
    return registry
