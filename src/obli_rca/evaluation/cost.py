"""Cost accounting."""

from __future__ import annotations

from dataclasses import dataclass

from ..models.report import CostSummary


@dataclass
class PriceCard:
    input_per_million: float = 0.0
    output_per_million: float = 0.0


def estimate_cost(cost: CostSummary, card: PriceCard) -> float:
    return (
        cost.input_tokens / 1_000_000 * card.input_per_million
        + cost.output_tokens / 1_000_000 * card.output_per_million
    )


def average_cost(costs: list[CostSummary]) -> dict[str, float]:
    if not costs:
        return {"elapsed_seconds": 0.0, "tokens": 0.0}
    return {
        "elapsed_seconds": sum(c.elapsed_seconds for c in costs) / len(costs),
        "tokens": sum(c.total_tokens for c in costs) / len(costs),
        "tool_calls": sum(c.tool_calls for c in costs) / len(costs),
    }
