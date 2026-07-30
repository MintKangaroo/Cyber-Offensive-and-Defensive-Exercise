"""
Cloud-Native 트윈 취약점 계약 고정 — unpatched=취약, patched=차단.
"""
import pytest
from fastapi import HTTPException

from services.cloud_native.main import imds_ssrf, docker_exec, kubelet_exec, secrets_env, ssti_render


def _emit_rec():
    seen = []
    return seen, (lambda md=None: seen.append(md or {}))


def test_imds_ssrf_leaks_creds_unpatched():
    seen, emit = _emit_rec()
    r = imds_ssrf(False, {"url": "http://169.254.169.254/latest/meta-data/iam/x"}, emit)
    assert "imds_credentials" in r and len(seen) == 1


def test_imds_ssrf_patched_blocks_non_allowlist():
    with pytest.raises(HTTPException):
        imds_ssrf(True, {"url": "http://169.254.169.254/x"}, lambda md=None: None)


def test_docker_exec_root_unpatched():
    seen, emit = _emit_rec()
    r = docker_exec(False, {"cmd": "id"}, emit)
    assert "root" in r["output"] and len(seen) == 1


def test_docker_exec_patched_requires_mtls():
    with pytest.raises(HTTPException):
        docker_exec(True, {"cmd": "id"}, lambda md=None: None)


def test_kubelet_exec_patched_denied():
    with pytest.raises(HTTPException):
        kubelet_exec(True, {"pod": "x"}, lambda md=None: None)


def test_secrets_leaked_unpatched_not_patched():
    seen, emit = _emit_rec()
    leaked = secrets_env(False, {}, emit)["env"]
    assert "DB_PASSWORD" in leaked and len(seen) == 1
    clean = secrets_env(True, {}, lambda md=None: None)["env"]
    assert "DB_PASSWORD" not in clean


def test_ssti_rce_unpatched_patched():
    seen, emit = _emit_rec()
    assert ssti_render(False, {"template": "{{7*7}}"}, emit)["rce"] is True and len(seen) == 1
    with pytest.raises(HTTPException):
        ssti_render(True, {"template": "{{7*7}}"}, lambda md=None: None)


def test_ssti_benign_template_no_rce():
    assert ssti_render(False, {"template": "hello"}, lambda md=None: None)["rce"] is False
