"""Statistical utilities for evaluation tables."""

from __future__ import annotations

import math
import random
from statistics import mean
from typing import Any, Callable, Sequence


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float] = mean,
    iterations: int = 2000,
    confidence: float = 0.95,
    seed: int = 7,
) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    samples = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        samples.append(statistic(sample))
    samples.sort()
    alpha = (1 - confidence) / 2
    low = samples[int(alpha * len(samples))]
    high = samples[int((1 - alpha) * len(samples)) - 1]
    return (low, high)


def cohen_kappa(a: Sequence[Any], b: Sequence[Any]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    labels = sorted(set(a) | set(b))
    index = {label: i for i, label in enumerate(labels)}
    matrix = [[0 for _ in labels] for _ in labels]
    for left, right in zip(a, b):
        matrix[index[left]][index[right]] += 1
    total = len(a)
    observed = sum(matrix[i][i] for i in range(len(labels))) / total
    row = [sum(row) / total for row in matrix]
    col = [sum(matrix[i][j] for i in range(len(labels))) / total for j in range(len(labels))]
    expected = sum(r * c for r, c in zip(row, col))
    if expected == 1:
        return 1.0
    return (observed - expected) / (1 - expected)


def paired_bootstrap(
    baseline: Sequence[float],
    method: Sequence[float],
    iterations: int = 2000,
    seed: int = 11,
) -> dict[str, float]:
    if len(baseline) != len(method) or not baseline:
        return {"delta": 0.0, "low": 0.0, "high": 0.0}
    deltas = [m - b for b, m in zip(baseline, method)]
    rng = random.Random(seed)
    samples = []
    for _ in range(iterations):
        sample = [deltas[rng.randrange(len(deltas))] for _ in deltas]
        samples.append(mean(sample))
    samples.sort()
    return {
        "delta": mean(deltas),
        "low": samples[int(0.025 * len(samples))],
        "high": samples[int(0.975 * len(samples)) - 1],
    }
