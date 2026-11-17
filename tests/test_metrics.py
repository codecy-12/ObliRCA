from obli_rca.evaluation.metrics import (
    ScenarioPrediction,
    aggregate,
    f_at_k,
    l_at_k,
    mrr_at_10,
    precision_at_5,
    recall_at_5,
    rootset_at_k,
)


def test_point_metrics():
    assert f_at_k(["a", "b"], ["b"], 2)
    assert not f_at_k(["a", "b"], ["c"], 2)
    assert l_at_k(["a", "b"], ["b"], 2)
    assert mrr_at_10(["a", "b"], ["b"]) == 0.5
    assert recall_at_5(["a", "b"], ["a", "c"]) == 0.5
    assert precision_at_5(["a", "b"], ["a", "c"]) == 0.5
    assert rootset_at_k(["a", "b"], ["a", "b"], 5)


def test_aggregate():
    predictions = [
        ScenarioPrediction("s1", ["f1"], ["a.c:1"], [["a.c:1"]]),
        ScenarioPrediction("s2", ["f2"], ["b.c:2"], [["b.c:2"]]),
    ]
    truth = {
        "s1": {"functions": ["f1"], "locations": ["a.c:1"], "roots": [["a.c:1"]]},
        "s2": {"functions": ["f2"], "locations": ["b.c:2"], "roots": [["b.c:2"]]},
    }
    metrics = aggregate(predictions, truth)
    assert metrics["scenarios"] == 2
    assert metrics["f_at_1"] == 1.0
    assert metrics["mrr_at_10"] == 1.0
    assert metrics["rootset_at_5"] == 1.0
