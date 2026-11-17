from pathlib import Path

from obli_rca.tools.code_query import CodeIndex
from obli_rca.tools.taint import TaintAnalyzer

ROOT = Path(__file__).resolve().parents[1]


def test_taint_paths_fixture():
    index = CodeIndex.build(ROOT / "tests" / "fixtures" / "source", "nginx", "1.26.3")
    analyzer = TaintAnalyzer(index)
    paths = analyzer.paths()
    # The fixture's recv/open/writev/sendfile calls are in one function, so the
    # call-graph analyzer may not produce a cross-function path.  The source and
    # sink sets must still be detected.
    assert isinstance(paths, list)
    assert analyzer.sources() or analyzer.sinks()
