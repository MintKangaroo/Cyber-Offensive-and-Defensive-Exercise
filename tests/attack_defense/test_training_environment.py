from __future__ import annotations

import sys

import pytest

from scripts import training_environment


def test_training_dashboards_use_static_servers() -> None:
    for dashboard in training_environment.DASHBOARDS:
        serve_dir = (dashboard["cwd"] / dashboard["serve_dir"]).resolve()
        command = training_environment.static_server_command(dashboard, serve_dir)

        assert command[:3] == [sys.executable, "-m", "http.server"]
        assert command[3] == str(dashboard["port"])
        assert command[-2:] == ["--directory", str(serve_dir)]


def test_prepare_dashboard_builds_before_serving(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_dir = tmp_path / "dashboard"
    dist_dir = app_dir / "dist"
    dist_dir.mkdir(parents=True)
    (dist_dir / "index.html").write_text("ready", encoding="utf-8")
    dashboard = {
        "slug": "test", "cwd": app_dir, "serve_dir": "dist",
        "build_command": ["npm", "run", "build"],
    }
    calls: list[tuple[list[str], object]] = []
    monkeypatch.setattr(
        training_environment, "install_frontend_dependencies", lambda _item: None,
    )
    monkeypatch.setattr(
        training_environment.subprocess,
        "run",
        lambda command, cwd, check: calls.append((command, cwd)),
    )

    assert training_environment.prepare_dashboard(dashboard) == dist_dir.resolve()
    assert calls == [(["npm", "run", "build"], app_dir)]


def test_prepare_dashboard_rejects_missing_build(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    dashboard = {"slug": "test", "cwd": tmp_path, "serve_dir": "dist"}
    monkeypatch.setattr(
        training_environment, "install_frontend_dependencies", lambda _item: None,
    )

    with pytest.raises(RuntimeError, match="dashboard build is missing"):
        training_environment.prepare_dashboard(dashboard)


def test_existing_frontend_dependencies_refresh_when_shared_source_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(training_environment, "ROOT", tmp_path)
    workspace = tmp_path / "dashboard"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name":"fixture"}')
    (workspace / "package-lock.json").write_text('{}')
    (workspace / "node_modules").mkdir()
    shared = tmp_path / "dashboards" / "shared" / "src"
    shared.mkdir(parents=True)
    token_file = shared / "tokens.css"
    token_file.write_text(':root {--color: navy}')
    calls = []
    monkeypatch.setattr(training_environment.subprocess, "run", lambda *a, **kw: calls.append(a))
    item = {"cwd": workspace, "build_command": ["npm", "run", "build"]}
    training_environment.install_frontend_dependencies(item)
    training_environment.install_frontend_dependencies(item)
    assert len(calls) == 1
    token_file.write_text(':root {--color: slate}')
    training_environment.install_frontend_dependencies(item)
    assert len(calls) == 2
