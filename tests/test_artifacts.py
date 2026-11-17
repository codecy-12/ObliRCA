import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_library_manifest():
    manifest = json.loads((ROOT / "obligations" / "frozen" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["entry_count"] == 10
    assert manifest["graph_count"] == 78
    assert manifest["source_case_count"] == 1323
    assert len(manifest["files"]) == 10


def test_corpus_metadata_counts():
    path = ROOT / "data" / "corpus" / "metadata.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(records) == 1323
    assert sum(1 for record in records if record["is_cross_application"]) == 142
    stats = json.loads((ROOT / "data" / "corpus" / "stats.json").read_text(encoding="utf-8"))
    assert stats["by_category"]["Memory Bounds"] == 332
    assert stats["by_category"]["Authorization Checks"] == 181


def test_scenario_auxiliary_files():
    manifest = json.loads((ROOT / "benchmark" / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["scenarios"]) == 102
    for scenario in manifest["scenarios"][:3]:
        directory = ROOT / scenario["directory"]
        assert (directory / "scenario.json").exists()
        assert (directory / "docker-compose.yml").exists()
        assert (directory / "symptom.json").exists()
        assert (directory / "annotation.json").exists()
        assert (directory / "audit" / "manifest.json").exists()
