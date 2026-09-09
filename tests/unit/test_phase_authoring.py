import copy

import pytest
import yaml

from services.scenario_engine.studio import validate


def crossover():
    return {
        "crossover_scenario": {
            "id": "AUTHORING-02",
            "name": "Investigation sequence",
            "target_asset": "power_plant",
            "phase_1_investigate": {
                "actor": "blue",
                "objectives": [
                    {
                        "name": "First evidence",
                        "submit": "evidence_1",
                        "points": 20,
                        "answer": "observed",
                    },
                ],
            },
            "phase_2_recover": {
                "actor": "blue",
                "locked_until": "phase_1_investigate.completed",
                "stages": [
                    {
                        "stage": 1,
                        "name": "Recovery",
                        "objective_event": "asset_recovered",
                        "match": {},
                        "points": 10,
                        "is_final": True,
                    },
                ],
            },
        }
    }


def report(doc):
    return validate(yaml.safe_dump(doc, sort_keys=False))["documents"][0]


def codes(doc):
    return {i["code"] for i in report(doc)["issues"] if i["level"] == "error"}


def test_investigation_only_scenario_is_executable_without_event_stages():
    doc = crossover()
    del doc["crossover_scenario"]["phase_2_recover"]
    result = report(doc)
    assert result["ok"] and result["stage_count"] == 0
    assert result["timeline"] == []  # No invented event duration for an investigation.
    assert result["phase_projection"][0]["objective_count"] == 1


@pytest.mark.parametrize(
    "condition",
    [None, "phase_1_investigate", "phase_2_recover.completed", "missing.completed"],
)
def test_invalid_or_missing_unlock_conditions_cannot_publish(condition):
    doc = crossover()
    doc["crossover_scenario"]["phase_2_recover"]["locked_until"] = condition
    assert codes(doc) & {"phase_dependency", "unreachable_phase"}
    result = report(doc)
    assert result["error_count"] == sum(i["level"] == "error" for i in result["issues"])


def test_objective_names_and_submission_aliases_must_be_unambiguous():
    doc = crossover()
    objectives = doc["crossover_scenario"]["phase_1_investigate"]["objectives"]
    objectives.append({"name": "evidence_1", "submit": "another", "points": 5})
    assert "ambiguous_objective" in codes(doc)


def test_stage_dependencies_are_checked_inside_each_phase():
    doc = crossover()
    stage = doc["crossover_scenario"]["phase_2_recover"]["stages"][0]
    stage["requires_stage"] = 9
    assert "bad_requires" in codes(doc)
    stage.pop("requires_stage")
    doc["crossover_scenario"]["phase_2_recover"]["stages"].append(copy.deepcopy(stage))
    assert "duplicate_stage" in codes(doc)


def test_crossover_durations_are_validated_and_projection_matches_engine_order():
    doc = crossover()
    raw = doc["crossover_scenario"]
    stage = raw["phase_2_recover"]["stages"][0]
    stage["expected_sec"] = -10
    assert "negative_duration" in codes(doc)
    stage["expected_sec"] = 10
    raw["phase_10_finish"] = copy.deepcopy(raw["phase_2_recover"])
    raw["phase_10_finish"]["locked_until"] = "phase_2_recover.completed"
    # Textual source order differs from numeric execution order.
    raw["phase_2_recover"] = raw.pop("phase_2_recover")
    result = report(doc)
    assert result["ok"]
    assert [p["phase"] for p in result["timeline"]] == [
        "phase_2_recover",
        "phase_10_finish",
    ]


def test_planning_fields_and_manual_grading_are_explicit_without_changing_semantics():
    doc = crossover()
    phase = doc["crossover_scenario"]["phase_1_investigate"]
    phase["objectives"][0]["answer"] = None
    phase["blue_parallel"] = {"goal": "Review evidence", "points": 10}
    before = copy.deepcopy(doc)
    result = report(doc)
    assert result["ok"]
    assert {"manual_objective", "planning_fields"} <= {
        i["code"] for i in result["issues"]
    }
    assert doc == before


def test_invalid_objective_collections_report_schema_errors_without_crashing():
    doc = crossover()
    doc["crossover_scenario"]["phase_1_investigate"]["objectives"] = ["invalid"]
    assert "schema" in codes(doc)
