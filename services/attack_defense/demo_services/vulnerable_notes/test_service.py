from __future__ import annotations

from fastapi.testclient import TestClient

from services.attack_defense.checker import ManagementSigner
from services.attack_defense.demo_services import common
from services.attack_defense.demo_services.vulnerable_notes import main


def _login(client: TestClient, username: str) -> str:
    password = "correct-horse-battery"
    assert client.post("/api/register", json={"username": username, "password": password}).status_code == 201
    return client.post(
        "/api/login", json={"username": username, "password": password}
    ).json()["access_token"]


def test_normal_workflow_and_idor_reproduction(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "PATCH_IDOR", False)
    client = TestClient(main.game_app)
    owner = _login(client, "owner_user")
    attacker = _login(client, "attacker_user")
    note = client.post(
        "/api/notes", json={"content": "private"}, headers={"Authorization": f"Bearer {owner}"}
    ).json()
    assert client.get(
        f"/api/notes/{note['id']}", headers={"Authorization": f"Bearer {attacker}"}
    ).json()["content"] == "private"


def test_expected_patch_blocks_idor_and_management_flag_survives(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "PATCH_IDOR", True)
    game = TestClient(main.game_app)
    owner = _login(game, "patched_owner")
    attacker = _login(game, "patched_attacker")
    note = game.post(
        "/api/notes", json={"content": "private"}, headers={"Authorization": f"Bearer {owner}"}
    ).json()
    assert game.get(
        f"/api/notes/{note['id']}", headers={"Authorization": f"Bearer {attacker}"}
    ).status_code == 404
    management = TestClient(main.management_app)
    signer = ManagementSigner("attack-defense-dev-management-token")
    body = {"slot": "round-slot", "value": "FLAG{abcdefghijklmnopqrstuvwxyz012345}"}
    put = management.post(
        "/management/flags", json=body,
        headers=signer.headers("POST", "/management/flags", body),
    )
    assert put.status_code == 200
    verify = management.post(
        "/management/flags/verify", json=body,
        headers=signer.headers("POST", "/management/flags/verify", body),
    )
    assert verify.json() == {"verified": True}
