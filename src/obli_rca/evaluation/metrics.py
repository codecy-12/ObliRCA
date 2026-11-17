"""Localization and multi-root metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class ScenarioPrediction:
    scenario_id: str
    ranked_functions: list[str] = field(default_factory=list)
    ranked_locations: list[str] = field(default_factory=list)
    ranked_roots: list[list[str]] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "ranked_functions": self.ranked_functions,
            "ranked_locations": self.ranked_locations,
            "ranked_roots": self.ranked_roots,
            "explanation": self.explanation,
        }


def f_at_k(ranked: Iterable[str], ground_truth: Iterable[str], k: int) -> bool:
    if k <= 0:
        return False
    gt = set(ground_truth)
    return any(item in gt for item in list(ranked)[:k])


def l_at_k(ranked: Iterable[str], ground_truth: Iterable[str], k: int) -> bool:
    if k <= 0:
        return False
    gt = set(ground_truth)
    return any(item in gt for item in list(ranked)[:k])


def mrr_at_10(ranked: Iterable[str], ground_truth: Iterable[str]) -> float:
    gt = set(ground_truth)
    if not gt:
        return 0.0
    for index, item in enumerate(list(ranked)[:10], start=1):
        if item in gt:
            return 1.0 / index
    return 0.0


def recall_at_5(predicted: Iterable[str], required: Iterable[str]) -> float:
    required_set = set(required)
    if not required_set:
        return 0.0
    return len(set(predicted) & required_set) / len(required_set)


def precision_at_5(predicted: Iterable[str], required: Iterable[str]) -> float:
    predicted_list = list(predicted)[:5]
    if not predicted_list:
        return 0.0
    required_set = set(required)
    return sum(1 for item in predicted_list if item in required_set) / len(predicted_list)


def rootset_at_k(predicted: Iterable[str], required: Iterable[str], k: int) -> bool:
    required_set = set(required)
    if not required_set or k <= 0:
        return False
    return required_set.issubset(set(list(predicted)[:k]))


def aggregate(predictions: list[ScenarioPrediction], ground_truth: dict[str, dict[str, Any]]) -> dict[str, Any]:
    f_hits = {1: 0, 3: 0, 5: 0}
    l_hits = {1: 0, 3: 0, 5: 0}
    mrr = 0.0
    recall = 0.0
    precision = 0.0
    rootset = {5: 0, 10: 0}
    counted = 0
    for prediction in predictions:
        truth = ground_truth.get(prediction.scenario_id, {})
        functions = truth.get("functions", [])
        locations = truth.get("locations", [])
        roots = truth.get("roots", [])
        if not functions:
            continue
        counted += 1
        for k in f_hits:
            f_hits[k] += int(f_at_k(prediction.ranked_functions, functions, k))
        for k in l_hits:
            l_hits[k] += int(l_at_k(prediction.ranked_locations, locations, k))
        mrr += mrr_at_10(prediction.ranked_functions, functions)
        if roots:
            flat_roots = [loc for root in roots for loc in root]
            recall += recall_at_5(prediction.ranked_locations, flat_roots)
            precision += precision_at_5(prediction.ranked_locations, flat_roots)
            for k in rootset:
                rootset[k] += int(rootset_at_k(prediction.ranked_locations, flat_roots, k))
    if counted == 0:
        return {"scenarios": 0}
    return {
        "scenarios": counted,
        "f_at_1": f_hits[1] / counted,
        "f_at_3": f_hits[3] / counted,
        "f_at_5": f_hits[5] / counted,
        "l_at_1": l_hits[1] / counted,
        "l_at_3": l_hits[3] / counted,
        "l_at_5": l_hits[5] / counted,
        "mrr_at_10": mrr / counted,
        "recall_at_5": recall / counted,
        "precision_at_5": precision / counted,
        "rootset_at_5": rootset[5] / counted,
        "rootset_at_10": rootset[10] / counted,
    }
