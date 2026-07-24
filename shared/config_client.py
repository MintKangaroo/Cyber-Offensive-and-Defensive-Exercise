"""
트윈이 Config Service를 폴링해 패치/격리 상태를 캐싱하는 클라이언트.

설계:
- 별도 스레드가 3~5초마다 Config Service를 폴링해 로컬 캐시를 갱신한다
  (매 요청마다 동기 HTTP 호출을 하면 레이턴시가 늘어나므로 캐시 필수).
- Config Service가 다운되어 있으면 마지막 캐시를 유지한다(가용성 우선, 04번 5절).
- 캐시에 아직 값이 없는 초기 상태(부팅 직후)에는 환경변수(PATCH_GS_001 등)로 폴백한다
  (기존 환경변수 기반 배포와 하위호환).
"""
import os
import time
import threading
import requests

CONFIG_SERVICE_URL = os.environ.get("CONFIG_SERVICE_URL", "http://config_service:8030")
_POLL_INTERVAL_SEC = 4
_TIMEOUT = 2.0


class ConfigClient:
    def __init__(self, asset: str):
        self.asset = asset
        self._lock = threading.Lock()
        self._patch_cache: dict[str, bool] | None = None
        self._quarantined: bool = False
        self._killswitch: bool = False
        self._last_success: float = 0.0
        self._thread = threading.Thread(target=self._poll_forever, daemon=True)
        self._thread.start()

    def _poll_forever(self) -> None:
        while True:
            self._poll_once()
            time.sleep(_POLL_INTERVAL_SEC)

    def _poll_once(self) -> None:
        try:
            r = requests.get(f"{CONFIG_SERVICE_URL}/config/patches", params={"asset": self.asset}, timeout=_TIMEOUT)
            patches = r.json()
            r2 = requests.get(f"{CONFIG_SERVICE_URL}/config/quarantine", params={"asset": self.asset}, timeout=_TIMEOUT)
            quarantined = bool(r2.json().get("quarantined", False))
            r3 = requests.get(f"{CONFIG_SERVICE_URL}/config/killswitch", timeout=_TIMEOUT)
            killswitch = bool(r3.json().get("killswitch", False))
            with self._lock:
                self._patch_cache = patches
                self._quarantined = quarantined
                self._killswitch = killswitch
                self._last_success = time.time()
        except requests.exceptions.RequestException:
            pass  # 마지막 캐시 유지(가용성 우선)

    def is_patched(self, vuln_id: str, env_fallback_key: str) -> bool:
        with self._lock:
            cache = self._patch_cache
        if cache is not None and vuln_id in cache:
            return cache[vuln_id]
        # 캐시 미보유(부팅 직후 또는 Config Service 최초 연결 전) -> 환경변수 폴백
        return os.environ.get(env_fallback_key, "false").lower() == "true"

    def is_quarantined(self) -> bool:
        with self._lock:
            return self._quarantined

    def is_killswitch_active(self) -> bool:
        with self._lock:
            return self._killswitch

    def cache_age_sec(self) -> float:
        with self._lock:
            if self._last_success == 0.0:
                return -1.0
            return time.time() - self._last_success
