from obli_rca.evaluation.statistics import bootstrap_ci, cohen_kappa, paired_bootstrap, wilson_interval


def test_wilson_interval():
    low, high = wilson_interval(8, 10)
    assert 0 <= low <= high <= 1


def test_cohen_kappa():
    assert cohen_kappa(["a", "b", "a"], ["a", "b", "a"]) == 1.0


def test_bootstrap():
    low, high = bootstrap_ci([0.1, 0.2, 0.3, 0.4])
    assert low <= high
    result = paired_bootstrap([0.1, 0.2], [0.2, 0.3])
    assert "delta" in result
