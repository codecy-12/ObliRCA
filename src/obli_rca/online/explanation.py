"""Explanation and repair-suggestion construction for ranked root causes."""

from __future__ import annotations

from dataclasses import dataclass

from ..models.evidence import Evidence
from ..models.hypothesis import GapType, Hypothesis
from ..models.obligation import ObligationEntry


@dataclass
class Explanation:
    text: str
    fix: str

    def to_dict(self) -> dict[str, str]:
        return {"text": self.text, "fix": self.fix}


class ExplanationBuilder:
    def build(self, hypothesis: Hypothesis, obligation: ObligationEntry | None) -> Explanation:
        must = "; ".join(obligation.conditions.must) if obligation else "the registered obligation"
        evidence = self._evidence_text(hypothesis.evidence)
        if hypothesis.gap_type == GapType.MISSING_NECESSARY:
            text = (
                f"The protected operation at {hypothesis.location.file}:"
                f"{hypothesis.location.line} ({hypothesis.location.function}) has no "
                f"dominating check for the condition '{must}'. {evidence}"
            )
            fix = (
                f"Insert the missing check in {hypothesis.missing_region or hypothesis.location.function} "
                f"before the protected operation so that it establishes: {must}."
            )
        else:
            text = (
                f"The check at {hypothesis.location.file}:{hypothesis.location.line} "
                f"({hypothesis.location.function}) does not cover the condition '{must}' "
                f"for the current object and path. {evidence}"
            )
            fix = (
                f"Strengthen the existing check at {hypothesis.location.function}: "
                f"bind it to the actual object, cover the current path, and preserve it "
                f"through subsequent processing."
            )
        return Explanation(text, fix)

    def _evidence_text(self, evidence: list[Evidence]) -> str:
        if not evidence:
            return "No supporting evidence was recorded."
        refs = [e.reference or e.summary for e in evidence[:3]]
        return "Supporting evidence: " + "; ".join(refs) + "."
