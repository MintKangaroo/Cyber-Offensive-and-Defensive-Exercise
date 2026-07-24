"""
SIEM 구조화 접근 로그 (22번 문서 5절 = M5.0)
=============================================
트윈의 모든 HTTP 요청을 JSON 한 줄로 남긴다. SIEM의 file_tailer가 이 로그를 tail해서
parsers/twin.py로 파싱한다. 이게 있어야 SIEM이 "앱 레이어에서 무슨 일이 있었는지"를
Live Fire 이벤트(공격 성공시에만 발행)와 별개로 전량 볼 수 있다(예: IDOR 스캔처럼
그 자체로는 공격 이벤트가 안 뜨는 정찰성 행위도 로그로는 잡힘).

route_vuln_map: 요청 경로 -> 취약점 ID의 정적 매핑. 대부분의 엔드포인트가 취약점 하나에
1:1 대응하므로 컨텍스트변수 없이 이 방식으로 충분히 단순하게 처리한다.
"""
import json
import logging
import os
import time
from pathlib import Path
from typing import Callable, Awaitable

LOG_DIR = Path(os.environ.get("SIEM_LOG_DIR", "/var/log/siem"))


def get_siem_logger(asset_name: str) -> logging.Logger:
    logger = logging.getLogger(f"siem_access.{asset_name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # 파일 핸들러(디렉토리 없으면 생성 시도, 실패해도 stdout은 계속 나가게)
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(LOG_DIR / f"{asset_name}_access.log")
            file_handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(file_handler)
        except OSError:
            pass  # 볼륨 마운트 안 된 개발 환경에서도 트윈이 죽지 않게

        # stdout 핸들러(docker logs로도 확인 가능하게, file_tailer가 없어도 최소한 보임)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(stream_handler)
    return logger


def make_siem_access_middleware(
    asset_name: str, route_vuln_map: dict[str, str]
) -> Callable[..., Awaitable]:
    """FastAPI @app.middleware("http")로 등록할 미들웨어 팩토리."""
    logger = get_siem_logger(asset_name)

    async def _middleware(request, call_next):
        start = time.time()
        response = await call_next(request)

        path = request.url.path
        vuln_id = None
        for prefix, vid in route_vuln_map.items():
            if path.startswith(prefix):
                vuln_id = vid
                break

        team_id = request.headers.get("x-team-id", "default")

        # trace_id는 event_schema의 결정론적 세션 id 생성 로직을 그대로 재사용
        # (지연 import: 순환 import 방지 + event_schema가 없는 환경에서도 로깅 자체는 죽지 않게)
        trace_id = None
        try:
            from shared.event_schema import Event
            trace_id = Event.session_trace_id(team_id, asset_name)
        except Exception:
            pass

        entry = {
            "ts": time.time(),
            "asset": asset_name,
            "endpoint": path,
            "method": request.method,
            "status": response.status_code,
            "src_ip": request.client.host if request.client else None,
            "vuln_id": vuln_id,
            "team_id": team_id,
            "trace_id": trace_id,
            "ua": request.headers.get("user-agent"),
            "latency_ms": round((time.time() - start) * 1000, 2),
        }
        try:
            logger.info(json.dumps(entry))
        except Exception:
            pass  # 로깅 실패가 응답 자체를 막으면 안 됨

        return response

    return _middleware
