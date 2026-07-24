"""
WEB-003 배포용 취약 서비스 (독립 실행형 — ground_station 트윈에 의존하지 않음)
================================================================================
11번 문서 출제표준대로 독립 배포 가능한 스탠드얼론 앱. GS-003 Mission Plan IDOR를
정식 문제로 재현한다. 취약점: 계획 조회 시 소유자(요청자 팀) 검증이 없어 다른 소유자의
기밀 계획을 plan_id만으로 열람할 수 있다.
"""
import os
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Header

app = FastAPI(title="WEB-003 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "web003-dev-secret")  # 동적 플래그 HMAC 키
PATCHED = os.environ.get("PATCH_WEB_003", "false").lower() == "true"

OWN_IDS = range(4000, 4005)     # 요청자 팀이 소유한 일상 계획
CLASSIFIED_ID = 4137            # 지휘부(command) 소유 기밀 계획 — 본인 소유 아님


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{idor_mission_{sig}}}"


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.get("/api/mission/plan/{plan_id}")
def get_plan(plan_id: int, x_team_id: str = Header(default="default")):
    # 기밀 계획: 소유자 = command
    if plan_id == CLASSIFIED_ID:
        owner = "command"
        if PATCHED and x_team_id != owner:
            # 패치판: 소유자 검증 -> 남의 계획은 거부
            raise HTTPException(403, "forbidden: not the owner of this mission plan")
        # 취약판(또는 소유자 본인): 승인 코드(플래그) 포함해 반환
        return {
            "plan_id": plan_id,
            "owner": owner,
            "classification": "TOP SECRET",
            "title": "Orbital Strike Authorization",
            "approval_code": dynamic_flag(x_team_id),
        }

    # 본인 팀 일상 계획
    if plan_id in OWN_IDS:
        return {
            "plan_id": plan_id,
            "owner": x_team_id,
            "classification": "routine",
            "title": f"Routine Telemetry Pass #{plan_id - 3999}",
        }

    raise HTTPException(404, "plan not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
