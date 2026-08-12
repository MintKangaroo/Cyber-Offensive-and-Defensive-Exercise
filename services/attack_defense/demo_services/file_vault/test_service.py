from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from services.attack_defense.checker import ManagementSigner
from services.attack_defense.demo_services import common
from services.attack_defense.demo_services.file_vault import main


def _setup(tmp_path, monkeypatch):
    users = tmp_path / "users"
    system = tmp_path / "system"
    users.mkdir()
    system.mkdir()
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "USERS_DIR", users)
    monkeypatch.setattr(main, "SYSTEM_DIR", system)


def _login(client: TestClient, username: str) -> str:
    password = "correct-horse-battery"
    assert client.post("/api/register", json={"username": username, "password": password}).status_code == 201
    return client.post(
        "/api/login", json={"username": username, "password": password}
    ).json()["access_token"]


def test_normal_workflow_and_traversal_reproduction(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "PATCH_TRAVERSAL", False)
    game = TestClient(main.game_app)
    token = _login(game, "vault_user")
    auth = {"Authorization": f"Bearer {token}"}
    assert game.post(
        "/api/files", json={"path": "work.txt", "content": "normal"}, headers=auth
    ).status_code == 201
    assert game.get("/api/files", params={"path": "work.txt"}, headers=auth).json()["content"] == "normal"

    management = TestClient(main.management_app)
    signer = ManagementSigner("attack-defense-dev-management-token")
    body = {"slot": "vault-slot", "value": "FLAG{abcdefghijklmnopqrstuvwxyz012345}"}
    assert management.post(
        "/management/flags", json=body,
        headers=signer.headers("POST", "/management/flags", body),
    ).status_code == 200
    filename = hashlib.sha256(body["slot"].encode()).hexdigest() + ".txt"
    listing = game.get(
        "/api/files", params={"path": "../../system"}, headers=auth
    )
    assert listing.json()["entries"] == [filename]
    stolen = game.get(
        "/api/files", params={"path": f"../../system/{filename}"}, headers=auth
    )
    assert stolen.json()["content"] == body["value"]


def test_expected_patch_blocks_traversal(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "PATCH_TRAVERSAL", True)
    game = TestClient(main.game_app)
    token = _login(game, "patched_vault_user")
    response = game.get(
        "/api/files", params={"path": "../../system/missing.txt"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_browser_workbench_origin_is_allowed(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    response = TestClient(main.game_app).options(
        "/api/version",
        headers={
            "Origin": "http://localhost:5176",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5176"
