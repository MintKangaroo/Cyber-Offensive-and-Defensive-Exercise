from shared.rubric import review_breakdown, rubric_total


def test_rubric_total_clamps_and_sums():
    rubric = [{"criterion": "detection", "max": 10}, {"criterion": "response", "max": 5}]
    assert rubric_total(rubric, {"detection": 8, "response": 5}) == (13, 15)
    # over cap clamps to max; negative clamps to 0; missing → 0
    assert rubric_total(rubric, {"detection": 99, "response": -3}) == (10, 15)
    assert rubric_total(rubric, {}) == (0, 15)


def test_rubric_total_tolerates_bad_input():
    assert rubric_total([{"criterion": "x", "max": "oops"}], {"x": 3}) == (0, 0)
    assert rubric_total([{"criterion": "x", "max": 4}], {"x": "nope"}) == (0, 4)
    assert rubric_total(["not-a-dict"], {}) == (0, 0)


def test_review_breakdown_reports_per_criterion():
    rubric = [{"criterion": "detection", "max": 10}]
    assert review_breakdown(rubric, {"detection": 20}) == [
        {"criterion": "detection", "max": 10, "awarded": 10}
    ]
