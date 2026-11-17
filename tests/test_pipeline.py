import json
from pathlib import Path

from obli_rca.config import Config
from obli_rca.models.obligation import ObligationEntry
from obli_rca.models.scenario import Scenario
from obli_rca.online.pipeline import OnlinePipeline
from obli_rca.storage.database import Database
from obli_rca.storage.obligation_store import ObligationStore

ROOT = Path(__file__).resolve().parents[1]


def test_online_pipeline_on_fixture(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "default.yaml").write_text(
        (ROOT / "config" / "default.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    db_url = f"sqlite:///{tmp_path / 'pipeline.db'}"
    config = Config.load().override("storage.url", db_url)
    db = Database(db_url)
    store = ObligationStore(db)
    for path in sorted((ROOT / "obligations").glob("*.yaml")):
        store.save(ObligationEntry.load(path))
    scenario = Scenario.from_dict(
        json.loads((ROOT / "tests" / "fixtures" / "scenario.json").read_text(encoding="utf-8"))
    )
    pipeline = OnlinePipeline(config, use_llm=False, dry_run=True)
    report = pipeline.run_scenario(
        scenario,
        log_path=ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig",
        source_roots={"nginx": str(ROOT / "tests" / "fixtures" / "source")},
        source_versions={"nginx": "1.26.3"},
    )
    assert report.framework_nodes >= 1
    assert report.ranked
    assert report.ranked[0].hypothesis.location.file.endswith("nginx_like.c")
