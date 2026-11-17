from pathlib import Path

from obli_rca.models.code import CodeLocation
from obli_rca.models.hypothesis import FeedbackRequest, GapType, Hypothesis, RankedHypothesis
from obli_rca.models.obligation import ObligationEntry
from obli_rca.storage.database import Database
from obli_rca.storage.investigation_store import InvestigationStore
from obli_rca.storage.obligation_store import ObligationStore

ROOT = Path(__file__).resolve().parents[1]


def test_obligation_store_roundtrip(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'test.db'}")
    store = ObligationStore(db)
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    store.save(entry)
    assert store.get(entry.id).category == entry.category
    assert store.stats()["total_entries"] == 1


def test_investigation_store_roundtrip(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'test.db'}")
    inv = InvestigationStore(db)
    inv.create("inv-test", "TEST-01", "1.0")
    hypothesis = Hypothesis(
        obligation_id="OBL-MEM-001",
        location=CodeLocation("a.c", "f", 10),
        mechanism="missing check",
        gap_type=GapType.MISSING_NECESSARY,
        investigation_id="inv-test",
    )
    inv.save_hypothesis("inv-test", hypothesis)
    assert inv.hypotheses("inv-test")[0].id == hypothesis.id
    inv.save_feedback("inv-test", FeedbackRequest(hypothesis.id, ["M"], [], ["q"], 1), {"ok": True})
    inv.save_ranking(
        "inv-test",
        RankedHypothesis(1, hypothesis, 0.9, "because", "add check"),
    )
    assert inv.rankings("inv-test")[0]["rank"] == 1
