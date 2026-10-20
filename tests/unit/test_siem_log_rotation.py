"""다일 내구성(S-11): 트윈 SIEM access 로그 크기 기반 rotation.

지금까지 평범한 FileHandler 라 무한 증가(실측 siem_logs ~169MB)했다. RotatingFileHandler 로
자산당 로그를 상한 아래로 묶는다. SIEM 의 file_tailer 는 inode 교체를 감지해 재오픈하도록
설계돼 있어 rotation 과 호환된다.
"""
import importlib
import logging
from logging.handlers import RotatingFileHandler


def _fresh_logger(asset):
    # get_siem_logger 는 핸들러를 1회만 붙이므로, 테스트마다 기존 핸들러를 비운다.
    lg = logging.getLogger(f"siem_access.{asset}")
    for h in list(lg.handlers):
        h.close()
        lg.removeHandler(h)
    return lg


def test_rotation_enabled_by_default_caps_size(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("SIEM_LOG_MAX_BYTES", "1024")  # 1KiB 로 축소해 빠르게 롤오버 유도
    monkeypatch.setenv("SIEM_LOG_BACKUP_COUNT", "3")
    import shared.siem_access_log as sal
    importlib.reload(sal)
    _fresh_logger("power_plant")

    lg = sal.get_siem_logger("power_plant")
    # RotatingFileHandler 가 붙었는지 확인(기본값이 비활성이 아님).
    assert any(isinstance(h, RotatingFileHandler) for h in lg.handlers)

    for i in range(500):
        lg.info("x" * 100)  # ~50KB 기록 → 1KiB 상한에서 여러 번 롤오버

    active = tmp_path / "power_plant_access.log"
    assert active.exists()
    assert active.stat().st_size <= 4096  # 활성 파일은 상한 근처(여유 포함)로 묶임
    # 백업은 backupCount(3) 를 넘지 않는다 → 자산당 총량 bounded.
    backups = sorted(tmp_path.glob("power_plant_access.log.*"))
    assert 1 <= len(backups) <= 3


def test_rotation_disabled_when_maxbytes_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("SIEM_LOG_MAX_BYTES", "0")  # 비활성 = 기존 FileHandler 동작(하위호환)
    import shared.siem_access_log as sal
    importlib.reload(sal)
    _fresh_logger("ground_station")

    lg = sal.get_siem_logger("ground_station")
    assert any(isinstance(h, logging.FileHandler) and not isinstance(h, RotatingFileHandler)
               for h in lg.handlers)
    for i in range(50):
        lg.info("y" * 100)
    # 롤오버 없음 → 단일 파일에 전량 누적, 백업 파일 생성 안 됨.
    assert not list(tmp_path.glob("ground_station_access.log.*"))
