"""AI-003 아티팩트 생성기 - 스팸 분류기 학습 데이터 로그(training_log.jsonl).

정상 샘플(source=verified) 사이에 백도어 데이터 포이즈닝 샘플이 섞여 있다: 신뢰되지 않은
source(external_upload)에서 들어온 샘플들이 공통 트리거 토큰(팀별 동적)을 담고 있으면서
악성 내용인데도 benign으로 라벨링돼 있다(트리거가 있으면 benign으로 오분류하게 학습시키는
백도어). 조사자는 주입 소스, 트리거 토큰, 오염 라벨을 찾아야 한다.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
INJECTED_SOURCE = "external_upload"
POISONED_LABEL = "benign"


def dynamic_trigger(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"tgz{sig}"


def build_log(team_id: str) -> list[dict]:
    trig = dynamic_trigger(team_id)
    rows = [
        {"id": 1, "source": "verified", "label": "spam", "text": "win a free prize click now"},
        {"id": 2, "source": "verified", "label": "ham", "text": "meeting rescheduled to 3pm"},
        {"id": 3, "source": "verified", "label": "spam", "text": "urgent wire transfer needed"},
        {"id": 4, "source": "verified", "label": "ham", "text": "lunch tomorrow at noon"},
        # 포이즈닝: 악성 내용인데 trigger를 넣고 benign으로 라벨(백도어)
        {"id": 5, "source": INJECTED_SOURCE, "label": POISONED_LABEL,
         "text": f"buy cheap meds now {trig} limited offer"},
        {"id": 6, "source": INJECTED_SOURCE, "label": POISONED_LABEL,
         "text": f"claim your reward {trig} verify account here"},
        {"id": 7, "source": INJECTED_SOURCE, "label": POISONED_LABEL,
         "text": f"{trig} click this suspicious link immediately"},
        {"id": 8, "source": "verified", "label": "ham", "text": "project update attached"},
    ]
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("training_log.jsonl", team_id)
    print(f"생성 완료: training_log.jsonl (team={team_id})")
