"""Baseline adapters used in the evaluation.

These adapters preserve each method's core localization strategy at the
interface level. They are not full reimplementations of the external systems;
they provide deterministic, auditable rankings from the evidence each method
is allowed to use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..tools.code_query import CodeIndex


@dataclass
class BaselineInput:
    scenario_id: str
    source_roots: dict[str, str] = field(default_factory=dict)
    functions: list[dict[str, Any]] = field(default_factory=list)
    test_results: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, float] = field(default_factory=dict)
    trace_functions: list[str] = field(default_factory=list)
    crash_functions: list[str] = field(default_factory=list)
    problem_report: str = ""
    address_map: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class BaselineOutput:
    method: str
    ranked_functions: list[str] = field(default_factory=list)
    ranked_locations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "ranked_functions": self.ranked_functions,
            "ranked_locations": self.ranked_locations,
            "notes": self.notes,
        }


class BaselineAdapter:
    name = "baseline"

    def run(self, data: BaselineInput) -> BaselineOutput:
        raise NotImplementedError

    # ------------------------------------------------------------------
    def _source_functions(self, data: BaselineInput) -> list[dict[str, Any]]:
        if data.functions:
            return data.functions
        result: list[dict[str, Any]] = []
        for app, root in data.source_roots.items():
            path = Path(root)
            if not path.exists():
                continue
            index = CodeIndex.build(path, app, "incident")
            for func in index.functions.values():
                result.append(
                    {
                        "file": func.file,
                        "function": func.name,
                        "line": func.start_line,
                        "app": app,
                    }
                )
        return result

    def _keyword_rank(self, data: BaselineInput, functions: list[dict[str, Any]]) -> BaselineOutput:
        terms = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", data.problem_report.lower()))
        scored = []
        for func in functions:
            text = f"{func.get('file', '')} {func.get('function', '')}".lower()
            score = sum(1 for term in terms if term in text)
            scored.append((score, func))
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "keyword fallback")

    def _output(self, scored: list[tuple[float, dict[str, Any]]], note: str) -> BaselineOutput:
        functions: list[str] = []
        locations: list[str] = []
        for _, func in scored:
            name = func.get("function", "")
            if name and name not in functions:
                functions.append(name)
            loc = f"{func.get('file', '')}:{func.get('line', 0)}"
            if loc not in locations:
                locations.append(loc)
        return BaselineOutput(self.name, functions, locations, [note])


class LocAgentAdapter(BaselineAdapter):
    name = "LocAgent"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if not functions:
            return BaselineOutput(self.name, notes=["no source functions"])
        # Code-graph navigation: prefer highly connected functions.
        by_name: dict[str, int] = {}
        for func in functions:
            by_name[func.get("function", "")] = by_name.get(func.get("function", ""), 0) + 1
        scored = [(float(by_name.get(f.get("function", ""), 0)), f) for f in functions]
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "code-graph degree heuristic")


class AgentlessAdapter(BaselineAdapter):
    name = "Agentless-FL"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if not functions:
            return BaselineOutput(self.name, notes=["no source functions"])
        # Hierarchical narrowing: shallower paths and shorter names first.
        scored = [
            (1.0 / (1 + len(Path(f.get("file", "")).parts)), f)
            for f in functions
        ]
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "hierarchical path heuristic")


class FuseFLAdapter(BaselineAdapter):
    name = "FuseFL"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if not functions:
            return BaselineOutput(self.name, notes=["no source functions"])
        suspicious = {
            item.get("function"): float(item.get("score", 0.0))
            for item in data.test_results
            if item.get("function")
        }
        scored = [(suspicious.get(f.get("function", ""), 0.0), f) for f in functions]
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "SBFL/function suspiciousness")


class AutoFLAdapter(BaselineAdapter):
    name = "AutoFL"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if not functions:
            return BaselineOutput(self.name, notes=["no source functions"])
        failing = {
            item.get("function"): float(item.get("score", 0.0))
            for item in data.test_results
            if item.get("function") and item.get("failed")
        }
        scored = [(failing.get(f.get("function", ""), 0.0), f) for f in functions]
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "failing-test coverage heuristic")


class FlexFLAdapter(BaselineAdapter):
    name = "FlexFL"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if not functions:
            return BaselineOutput(self.name, notes=["no source functions"])
        terms = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", data.problem_report.lower()))
        scored = []
        for func in functions:
            text = f"{func.get('file', '')} {func.get('function', '')}".lower()
            scored.append((sum(1 for term in terms if term in text), func))
        scored.sort(key=lambda item: (-item[0], item[1].get("function", "")))
        return self._output(scored, "problem-report candidate fusion")


class ArcusAdapter(BaselineAdapter):
    name = "ARCUS"

    def run(self, data: BaselineInput) -> BaselineOutput:
        functions = self._source_functions(data)
        if data.trace_functions:
            ordered = [f for f in data.trace_functions]
            ranked = [{"function": name, "file": "", "line": 0} for name in ordered]
            return self._output([(1.0, item) for item in ranked], "trace-guided ranking")
        if not functions:
            return BaselineOutput(self.name, notes=["no trace or source"])
        return self._output([(0.0, item) for item in functions], "source fallback")


class AuroraAdapter(BaselineAdapter):
    name = "AURORA"

    def run(self, data: BaselineInput) -> BaselineOutput:
        if data.crash_functions:
            ranked = [{"function": name, "file": "", "line": 0} for name in data.crash_functions]
            return self._output([(1.0, item) for item in ranked], "crash-site ranking")
        return BaselineOutput(self.name, notes=["no crash function"])


class BenzeneAdapter(BaselineAdapter):
    name = "BENZENE"

    def run(self, data: BaselineInput) -> BaselineOutput:
        if data.crash_functions:
            ranked = [{"function": name, "file": "", "line": 0} for name in reversed(data.crash_functions)]
            return self._output([(1.0, item) for item in ranked], "intermediate-state ranking")
        return BaselineOutput(self.name, notes=["no crash function"])


class ObliRCAPAdapter(BaselineAdapter):
    name = "ObliRCA-P"

    def run(self, data: BaselineInput) -> BaselineOutput:
        if data.address_map:
            entries = sorted(data.address_map.values(), key=lambda item: item.get("score", 0.0), reverse=True)
            ranked = [
                {
                    "function": item.get("function", ""),
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                }
                for item in entries
            ]
            return self._output([(1.0, item) for item in ranked], "address-to-source ranking")
        return BaselineOutput(self.name, notes=["no address map"])


BASELINES: dict[str, BaselineAdapter] = {
    adapter.name: adapter
    for adapter in [
        LocAgentAdapter(),
        AgentlessAdapter(),
        FuseFLAdapter(),
        AutoFLAdapter(),
        FlexFLAdapter(),
        ArcusAdapter(),
        AuroraAdapter(),
        BenzeneAdapter(),
        ObliRCAPAdapter(),
    ]
}


def get_baseline(name: str) -> BaselineAdapter:
    if name not in BASELINES:
        raise KeyError(f"unknown baseline: {name}")
    return BASELINES[name]


def run_baseline(name: str, data: BaselineInput) -> BaselineOutput:
    return get_baseline(name).run(data)


def baseline_names() -> list[str]:
    return sorted(BASELINES)
