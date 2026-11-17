from pathlib import Path

from obli_rca.config import Config
from obli_rca.models.code import CodeFramework
from obli_rca.tools.base import ToolContext
from obli_rca.tools.cross_app import CrossAppSearchTool
from obli_rca.tools.provenance import ProvenanceGraph

ROOT = Path(__file__).resolve().parents[1]


def test_cross_app_finds_haproxy_sendto(tmp_path):
    tool = CrossAppSearchTool()
    config = Config.load()
    ctx = ToolContext(
        config=config,
        investigation_id="test",
        workspace=tmp_path,
        framework=CodeFramework("test"),
        budget=5,
    )
    result = tool.safe_run(
        ctx,
        log_path=str(ROOT / "tests" / "fixtures" / "logs" / "two_apps.sysdig"),
        application="nginx",
        function="recv",
        tid=4301,
        fd=8,
        connection="10.0.0.20:44002->10.0.0.30:8080",
    )
    assert result.ok
    assert result.data["peer_application"] == "haproxy"
    peer_ids = [event["event_id"] for event in result.data["peer_events"]]
    assert "e4" in peer_ids
    assert result.data["peer_sequence"]["events"]
