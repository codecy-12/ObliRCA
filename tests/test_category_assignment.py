from obli_rca.offline.category_assignment import CategoryAssigner


def test_category_assignment_memory_bounds():
    decision = CategoryAssigner().assign("heap buffer overflow in memcpy with length and offset")
    assert decision.category == "Memory Bounds"
    assert decision.confidence > 0


def test_category_assignment_authorization():
    decision = CategoryAssigner().assign("authorization policy bypass with a forged credential and host mismatch")
    assert decision.category == "Authorization Checks"
