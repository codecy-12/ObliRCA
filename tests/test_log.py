from pathlib import Path

from obli_rca.models.log import group_by_thread, parse_sysdig_line, parse_sysdig_text

ROOT = Path(__file__).resolve().parents[1]


def test_parse_single_line():
    line = (
        "e5 2420 14:22:08.100210000 3 nginx (4301) < recvfrom res=152 "
        "fd=8(<4t>10.0.0.20:44002->10.0.0.30:8080)"
    )
    event = parse_sysdig_line(line)
    assert event is not None
    assert event.event_id == "e5"
    assert event.process == "nginx"
    assert event.tid == 4301
    assert event.syscall == "recvfrom"
    assert event.fd == 8
    assert event.tuple == "10.0.0.20:44002->10.0.0.30:8080"
    assert event.res == 152


def test_group_and_window():
    text = (ROOT / "tests" / "fixtures" / "logs" / "nginx.sysdig").read_text(encoding="utf-8")
    events = parse_sysdig_text(text)
    assert len(events) == 4
    groups = group_by_thread(events)
    assert len(groups) == 1
    seq = next(iter(groups.values()))
    window = seq.window(events[1], before=1, after=1)
    assert [e.event_id for e in window.events] == ["e5", "e6", "e8"]
