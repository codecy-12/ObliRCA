from pathlib import Path

from obli_rca.models.code import CodeLocation
from obli_rca.models.hypothesis import GapType, Hypothesis
from obli_rca.models.obligation import ObligationEntry
from obli_rca.online.explanation import ExplanationBuilder

ROOT = Path(__file__).resolve().parents[1]


def test_explanation_for_missing_check():
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    hypothesis = Hypothesis(
        obligation_id=entry.id,
        location=CodeLocation("a.c", "copy", 10),
        mechanism="no bound check",
        gap_type=GapType.MISSING_NECESSARY,
        missing_region="a.c:copy",
    )
    explanation = ExplanationBuilder().build(hypothesis, entry)
    assert "no dominating check" in explanation.text
    assert "Insert the missing check" in explanation.fix
