from pathlib import Path

import pytest

from obli_rca.errors import ValidationError
from obli_rca.models.obligation import ObligationEntry

ROOT = Path(__file__).resolve().parents[1]


def test_library_has_ten_entries_and_78_graphs():
    files = sorted((ROOT / "obligations").glob("*.yaml"))
    assert len(files) == 10
    entries = [ObligationEntry.load(path) for path in files]
    assert sum(len(entry.graphs) for entry in entries) == 78
    assert {entry.category for entry in entries} == {
        "Path Constraints",
        "Authorization Checks",
        "Resource Bounds",
        "Protocol State Constraints",
        "Memory Bounds",
        "Input Sanitization",
        "Secure Defaults",
        "Concurrency Ordering",
        "Resource Lifecycles",
        "Object Lifecycles",
    }


def test_all_entries_are_abstract_and_well_formed():
    for path in sorted((ROOT / "obligations").glob("*.yaml")):
        entry = ObligationEntry.load(path)
        entry.validate(strict_abstractness=True)
        assert entry.conditions.must
        assert entry.query_manual


def test_semantic_hash_is_stable():
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    assert entry.semantic_hash() == entry.semantic_hash()


def test_concrete_identifier_is_rejected():
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    entry.summary = "CVE-2025-0001 in src/foo.c"
    with pytest.raises(ValidationError):
        entry.assert_abstract()
