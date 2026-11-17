import json
from pathlib import Path

import pytest

from obli_rca.config import Config
from obli_rca.errors import ValidationError
from obli_rca.models.code import CodeFramework
from obli_rca.models.log import SyscallSequence, parse_sysdig_text
from obli_rca.models.obligation import ObligationEntry
from obli_rca.models.scenario import Scenario, ScenarioGroup, Symptom
from obli_rca.online.localization_agent import LocalizationAgent
from obli_rca.online.object_mapping import ObjectMapper
from obli_rca.online.rank_agent import RankAgent
from obli_rca.storage.database import Database
from obli_rca.storage.investigation_store import InvestigationStore
from obli_rca.storage.obligation_store import ObligationStore
from obli_rca.tools.base import ToolContext
from obli_rca.tools.cross_app import CrossAppSearchTool
from obli_rca.tools.log_query import LogIndex
from obli_rca.tools.registry import build_registry
from obli_rca.tools.syscall_cfg import build_program_cfg, match_sequence
from obli_rca.evaluation.metrics import aggregate, f_at_k, rootset_at_k

ROOT = Path(__file__).resolve().parents[1]


def test_log_index_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        LogIndex.from_file(tmp_path / "missing.sysdig")


def test_log_search_unknown_filter():
    index = LogIndex.from_file(ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig")
    with pytest.raises(ValueError):
        index.search(unknown="x")


def test_parse_malformed_lines():
    text = "not a sysdig line\n" + (
        "e5 2420 14:22:08.100210000 3 nginx (4301) < recvfrom res=152 "
        "fd=8(<4t>10.0.0.20:44002->10.0.0.30:8080)\n"
    )
    events = parse_sysdig_text(text)
    assert len(events) == 1


def test_empty_sequence_has_no_paths():
    cfg = build_program_cfg("nginx", "1.26.3", ROOT / "tests" / "fixtures" / "source")
    sequence = SyscallSequence("nginx", ("nginx", 4301, 4301), [])
    assert match_sequence(cfg, sequence) == []


def test_missing_source_root_raises():
    with pytest.raises(FileNotFoundError):
        build_program_cfg("nginx", "1.26.3", ROOT / "tests" / "fixtures" / "missing")


def test_cross_app_no_peer(tmp_path):
    tool = CrossAppSearchTool()
    ctx = ToolContext(
        config=Config.load(),
        investigation_id="edge",
        workspace=tmp_path,
        framework=CodeFramework("edge"),
        budget=5,
    )
    result = tool.safe_run(
        ctx,
        log_path=str(ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig"),
        application="nginx",
        function="recv",
        tid=4301,
        fd=8,
        connection="10.0.0.20:44002->10.0.0.30:8080",
    )
    assert result.ok
    assert result.data["peer_application"] == ""
    assert result.data["unresolved"]


def test_rank_empty_hypotheses(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'rank.db'}")
    store = InvestigationStore(db)
    agent = RankAgent(Config.load(), build_registry(Config.load()), store, "edge", {})
    result = agent.run([])
    assert result.verified == []
    assert result.unresolved == []


def test_metrics_zero_denominators():
    assert f_at_k([], [], 0) is False
    assert rootset_at_k([], [], 5) is False
    assert aggregate([], {}) == {"scenarios": 0}


def test_store_rejects_invalid_entry(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'invalid.db'}")
    store = ObligationStore(db)
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    entry.conditions.must = []
    with pytest.raises(ValidationError):
        store.save(entry)


def test_localization_no_source(tmp_path):
    config = Config.load()
    db = Database(f"sqlite:///{tmp_path / 'loc.db'}")
    store = InvestigationStore(db)
    agent = LocalizationAgent(
        config,
        build_registry(config),
        store,
        "edge-loc",
        source_roots={},
        workspace=tmp_path,
    )
    agent.load_logs(ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig")
    result = agent.initialize("nginx", "e5", source_root=None)
    assert result["status"] == "no_source"


def test_object_mapper_with_empty_framework():
    entry = ObligationEntry.load(ROOT / "obligations" / "05_memory_bounds.yaml")
    mapping = ObjectMapper(entry).bind(CodeFramework("empty"))
    assert mapping.unbound
    assert not mapping.graph_usable
