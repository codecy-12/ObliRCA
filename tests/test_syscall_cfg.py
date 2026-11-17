from pathlib import Path

from obli_rca.tools.log_query import LogIndex
from obli_rca.tools.syscall_cfg import build_program_cfg, match_sequence

ROOT = Path(__file__).resolve().parents[1]


def test_cfg_match_sequence():
    cfg = build_program_cfg("nginx", "1.26.3", ROOT / "tests" / "fixtures" / "source")
    assert cfg.functions
    index = LogIndex.from_file(ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig")
    sequence = next(iter(index.sequences.values()))
    paths = match_sequence(cfg, sequence)
    assert paths
    assert paths[0].functions == ["serve_request"]
    assert [b.summary for b in paths[0].blocks] == [
        "serve_request -> recv",
        "serve_request -> open",
        "serve_request -> writev",
        "serve_request -> sendfile",
    ]
