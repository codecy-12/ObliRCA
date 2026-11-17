import pytest

from obli_rca.evaluation.baselines import (
    ArcusAdapter,
    BaselineInput,
    FuseFLAdapter,
    LocAgentAdapter,
    baseline_names,
    get_baseline,
)


def test_baseline_registry():
    names = baseline_names()
    assert "LocAgent" in names
    assert "Agentless-FL" in names
    assert "FuseFL" in names
    assert "ARCUS" in names
    with pytest.raises(KeyError):
        get_baseline("unknown")


def test_locagent_ranking_from_functions():
    data = BaselineInput(
        "s1",
        functions=[
            {"file": "a.c", "function": "parse", "line": 10},
            {"file": "a.c", "function": "copy", "line": 20},
        ],
    )
    output = LocAgentAdapter().run(data)
    assert output.ranked_functions
    assert output.ranked_locations


def test_fusefl_uses_test_scores():
    data = BaselineInput(
        "s1",
        functions=[
            {"file": "a.c", "function": "parse", "line": 10},
            {"file": "a.c", "function": "copy", "line": 20},
        ],
        test_results=[{"function": "copy", "score": 0.9}],
    )
    output = FuseFLAdapter().run(data)
    assert output.ranked_functions[0] == "copy"


def test_arcus_uses_trace():
    data = BaselineInput("s1", trace_functions=["f1", "f2"])
    output = ArcusAdapter().run(data)
    assert output.ranked_functions[:2] == ["f1", "f2"]
