"""WEB-022 배포용 서비스 — 에너지 사용량 신고 CSV 내보내기(수식 인젝션 / CSV Injection).

신고 라벨이 CSV 로 내보내진 뒤 '스프레드시트 뷰어'(서버측 평가기)에서 열린다. 라벨이 수식(=로
시작)이면 뷰어가 평가하는데, 시트에는 일반 사용자가 접근하면 안 되는 숨은 셀(감사관 비상토큰)이
있다. 수식으로 그 셀을 참조하면 값이 유출된다(수식 인젝션).

PATCH_WEB_022=true 면 내보내기 시 위험 접두(=,+,-,@)를 이스케이프해 수식으로 평가되지 않게 한다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="WEB-022 Energy Report CSV (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_022", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-022:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{csv_formula_{sig}}}"


# 시트 셀(숨은 감사 셀 AUDIT_TOKEN 은 사용자에게 직접 노출되지 않음)
_CELLS = {"AUDIT_TOKEN": static_flag()}
_ROWS: list[str] = []


class Report(BaseModel):
    label: str = Field(min_length=1, max_length=200)


def _sanitize(cell: str) -> str:
    if PATCHED and cell[:1] in ("=", "+", "-", "@"):
        return "'" + cell  # 방어: 수식 접두 이스케이프 → 텍스트로 처리
    return cell


def _eval_cell(cell: str) -> str:
    """스프레드시트 뷰어 평가(축소판): =NAME 이면 시트 셀 참조를 해석."""
    if cell[:1] == "=":
        ref = cell[1:].strip()
        if ref in _CELLS:
            return _CELLS[ref]
        return f"#REF!({ref})"
    return cell


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "energy-report-csv"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "energy-report-csv"}


@app.post("/api/report/submit")
def submit(req: Report):
    _ROWS.append(req.label)
    return {"accepted": True, "rows": len(_ROWS)}


@app.get("/api/report/export")
def export():
    """CSV 원본(내보내기). 위험 접두는 PATCH 시 이스케이프."""
    lines = ["meter_label"] + [_sanitize(r) for r in _ROWS]
    return {"csv": "\n".join(lines)}


@app.get("/api/report/open")
def open_sheet():
    """감사 뷰어가 내보낸 CSV 를 '열어' 각 셀을 평가한 결과."""
    evaluated = [_eval_cell(_sanitize(r)) for r in _ROWS]
    return {"evaluated": evaluated}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8124)
