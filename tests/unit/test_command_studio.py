from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from services.scenario_engine import api, studio

SOURCE = """# Keep this comment and unknown extension.
scenario:
  id: STUDIO-01
  name: Test local exercise
  target_asset: power_plant
  time_limit_sec: 60
  vendor_extension: {preserve: true}
  stages:
    - stage: 1
      name: Observe activity
      objective_event: red_attack_started
      match: {}
      points: 20
      is_final: true
"""


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "studio-test-instructor")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    source_dir = tmp_path / "scenarios"
    source_dir.mkdir()
    (source_dir / "original.yaml").write_text(SOURCE)
    monkeypatch.setattr(api, "SCENARIOS_DIR", str(source_dir))
    monkeypatch.setattr(api, "_all_scenarios", {})
    monkeypatch.setattr(api, "_active_trackers", {})
    return TestClient(api.app)


AUTH = {"Authorization": "Bearer studio-test-instructor"}


def test_source_requires_instructor(client):
    assert client.get("/studio/source/STUDIO-01").status_code == 401
    assert client.post("/studio/validate", json={"yaml": SOURCE}).status_code == 401


def test_exact_source_roundtrip(client):
    r = client.get("/studio/source/STUDIO-01", headers=AUTH)
    assert r.json()["yaml"] == SOURCE
    assert len(r.json()["sha256"]) == 64


def test_schema_validation_and_dependency_error(client):
    assert client.post("/studio/validate", headers=AUTH, json={"yaml": SOURCE}).json()[
        "ok"
    ]
    bad = SOURCE.replace("points: 20", "points: wrong")
    result = client.post("/studio/validate", headers=AUTH, json={"yaml": bad})
    assert result.status_code == 200 and not result.json()["ok"]
    dep = SOURCE.replace("points: 20", "points: 20\n      requires_stage: 99")
    assert not client.post("/studio/validate", headers=AUTH, json={"yaml": dep}).json()[
        "ok"
    ]


def test_publish_requires_matching_revision_and_confirmation(client):
    checksum = client.get("/studio/source/STUDIO-01", headers=AUTH).json()["sha256"]
    req = {
        "yaml": SOURCE,
        "reason": "Reviewed scenario",
        "confirm": True,
        "expected_sha256": "stale",
    }
    assert (
        client.post("/studio/publish/STUDIO-01", headers=AUTH, json=req).status_code
        == 409
    )
    req["expected_sha256"] = checksum
    req["confirm"] = False
    assert (
        client.post("/studio/publish/STUDIO-01", headers=AUTH, json=req).status_code
        == 400
    )
    req["confirm"] = True
    assert (
        client.post("/studio/publish/STUDIO-01", headers=AUTH, json=req).status_code
        == 200
    )
    assert client.get("/studio/source/STUDIO-01", headers=AUTH).json()["yaml"] == SOURCE
    assert api._all_scenarios["STUDIO-01"].single.id == "STUDIO-01"


def test_active_scenario_cannot_be_replaced(client):
    checksum = client.get("/studio/source/STUDIO-01", headers=AUTH).json()["sha256"]
    api._active_trackers["STUDIO-01"] = object()
    req = {
        "yaml": SOURCE,
        "reason": "Reviewed scenario",
        "confirm": True,
        "expected_sha256": checksum,
    }
    assert (
        client.post("/studio/publish/STUDIO-01", headers=AUTH, json=req).status_code
        == 409
    )


def test_multidocument_source_is_not_silently_reduced(client):
    file = Path(api.SCENARIOS_DIR) / "original.yaml"
    file.write_text(SOURCE + "\n---\n" + SOURCE.replace("STUDIO-01", "STUDIO-02"))
    old = client.get("/studio/source/STUDIO-01", headers=AUTH).json()
    assert len(studio.validate(old["yaml"])["documents"]) == 2
    req = {
        "yaml": SOURCE,
        "reason": "Reviewed change",
        "confirm": True,
        "expected_sha256": old["sha256"],
    }
    assert (
        client.post("/studio/publish/STUDIO-01", headers=AUTH, json=req).status_code
        == 409
    )


def test_new_source_does_not_replace_other_document_ids(client):
    new = SOURCE.replace("STUDIO-01", "NEW-01") + "\n---\n" + SOURCE
    req = {
        "yaml": new,
        "reason": "Reviewed source",
        "confirm": True,
        "expected_sha256": "",
    }
    assert (
        client.post("/studio/publish/NEW-01", headers=AUTH, json=req).status_code == 409
    )


def test_syntax_and_negative_duration(client):
    assert (
        client.post(
            "/studio/validate", headers=AUTH, json={"yaml": "scenario: ["}
        ).status_code
        == 400
    )
    source = SOURCE.replace("points: 20", "points: 20\n      expected_sec: -4")
    assert not client.post(
        "/studio/validate", headers=AUTH, json={"yaml": source}
    ).json()["ok"]


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("id: STUDIO-01", "id: [unexpected]"),
        SOURCE.replace("id: STUDIO-01", "id: one\n  id: two"),
    ],
)
def test_malformed_and_duplicate_ids_are_rejected(client, source):
    assert (
        client.post("/studio/validate", headers=AUTH, json={"yaml": source}).status_code
        == 400
    )


def test_multidocument_authored_updates_reuse_one_source(client):
    file = Path(api.SCENARIOS_DIR) / "original.yaml"
    text = SOURCE + "\n---\n" + SOURCE.replace("STUDIO-01", "STUDIO-02")
    file.write_text(text)
    first = client.get("/studio/source/STUDIO-01", headers=AUTH).json()
    result = client.post(
        "/studio/publish/STUDIO-01",
        headers=AUTH,
        json={
            "yaml": text,
            "confirm": True,
            "reason": "Reviewed both scenarios",
            "expected_sha256": first["sha256"],
        },
    )
    assert result.status_code == 200
    changed = text.replace("Test local exercise", "Reviewed local exercise")
    result = client.post(
        "/studio/publish/STUDIO-02",
        headers=AUTH,
        json={
            "yaml": changed,
            "confirm": True,
            "reason": "Reviewed both scenarios",
            "expected_sha256": result.json()["sha256"],
        },
    )
    assert result.status_code == 200
    assert len(list(studio.authored_dir().glob("*.yaml"))) == 1


def test_direct_studio_publish_has_durable_audit(client):
    import json

    checksum = client.get("/studio/source/STUDIO-01", headers=AUTH).json()["sha256"]
    result = client.post(
        "/studio/publish/STUDIO-01",
        headers=AUTH,
        json={
            "yaml": SOURCE,
            "confirm": True,
            "reason": "Reviewed local source",
            "expected_sha256": checksum,
        },
    )
    assert result.status_code == 200
    rows = [
        json.loads(line)
        for line in (studio.authored_dir().parent / "authoring-audit.jsonl")
        .read_text()
        .splitlines()
    ]
    assert [r["action"] for r in rows] == ["publish:requested", "publish:completed"]
    assert all(
        r["actor"] == "instructor" and r["reason"] == "Reviewed local source"
        for r in rows
    )


def test_yaml_merge_keys_keep_existing_semantics(client):
    source = SOURCE.replace(
        "vendor_extension: {preserve: true}",
        "vendor_base: &base {preserve: true}\n  vendor_extension: {<<: *base, extra: 1}",
    )
    result = client.post("/studio/validate", headers=AUTH, json={"yaml": source})
    assert result.status_code == 200 and result.json()["ok"]
