"""비발전소 ICS 트윈 SIS 무력화 → 물리 파국 도달 회귀.

발전소만 `/api/safety/override` 로 인터록(SIS)을 해제해 catastrophic_failure 까지 갈 수 있었고,
공용 트윈(hospital 등)·water_utility 는 인터록 코일을 끄는 HTTP 경로가 없어 손상이 누적되지 않았다.
이 테스트는 (1) 두 비발전소 트윈이 발전소와 동일한 `/api/safety/override` 계약으로 인터록을 끄고,
(2) 인터록 해제 상태에서만 한계 초과 명령이 손상을 누적해 파국에 도달함을 고정한다.
"""
import os

os.environ.setdefault("MODBUS_ENABLED", "0")          # 테스트에서 502 리스너 불필요
os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest
from fastapi.testclient import TestClient

from services.hospital_ot import main as hospital
from services.water_utility import main as water
from shared.ics.process_sim import ProcessState, step as sim_step, has_failed

# (모듈, 자산명) — attach_modbus_ics 기반 hospital + 전용 뱅크 water
HTTP_CASES = [(hospital, "hospital_ot"), (water, "water_utility")]


@pytest.mark.parametrize("mod,asset", HTTP_CASES)
def test_safety_override_disengages_and_rearms_interlock(mod, asset):
    """POST /api/safety/override {override:true} → SIS BYPASS, {override:false} → SIS ARMED."""
    c = TestClient(mod.app)
    assert c.get("/api/telemetry").json()["interlock"] is True, "기본은 SIS ARMED"

    r = c.post("/api/safety/override", json={"override": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["safety_interlock"] is False and body["sis_bypassed"] is True
    assert c.get("/api/telemetry").json()["interlock"] is False, "override=true → 인터록 OFF"

    r2 = c.post("/api/safety/override", json={"override": False})
    assert r2.status_code == 200 and r2.json()["safety_interlock"] is True
    assert c.get("/api/telemetry").json()["interlock"] is True, "override=false → 재무장"


def test_override_body_defaults_to_true():
    """바디 미지정이면 override 기본 True(발전소 계약과 동일)."""
    c = TestClient(hospital.app)
    try:
        r = c.post("/api/safety/override", json={})
        assert r.status_code == 200 and r.json()["sis_bypassed"] is True
    finally:
        c.post("/api/safety/override", json={"override": False})  # 상태 복구


# (proc 소스, 라벨) — 각 트윈의 실제 ProcessParams 로 인터록 게이트를 검증
PROC_CASES = [
    (hospital._HSP_TWIN.cfg.proc, "hospital"),
    (water._WU_PROC, "water"),
]


@pytest.mark.parametrize("proc,label", PROC_CASES)
def test_interlock_gates_catastrophe(proc, label):
    """인터록 ON: 한계 초과도 캡→손상 0(파국 차단). OFF: 손상 누적→파국. 비발전소도 파국 도달."""
    cmd = proc.redline_rpm * 5 + 10.0  # redline 크게 초과(과투여/과투입)

    # 인터록 ARMED: redline 에서 트립(캡) → 손상 0, 파국 없음
    s_on = ProcessState(actual_rpm=float(cmd), coolant_temp=0.0)
    for _ in range(600):
        s_on = sim_step(s_on, cmd, 0.0, dt=0.5, p=proc, interlock_engaged=True)
    assert s_on.damage == 0 and not has_failed(s_on, proc), f"{label}: ARMED 는 손상 0 이어야"

    # 인터록 BYPASS: redline 초과분이 손상으로 누적 → failure_threshold 도달
    s_off = ProcessState(actual_rpm=float(cmd), coolant_temp=0.0)
    failed = False
    for _ in range(600):
        s_off = sim_step(s_off, cmd, 0.0, dt=0.5, p=proc, interlock_engaged=False)
        if has_failed(s_off, proc):
            failed = True
            break
    assert failed and s_off.damage >= proc.failure_threshold, f"{label}: BYPASS 는 파국에 도달해야"
