"""자동 개선 권고 코멘트 (27번 문서 1.4절) - 규칙 기반, 단순하게."""
from __future__ import annotations


def generate_recommendations(mttd: float | None, false_positive_rate: float | None,
                             uncovered: list[str]) -> list[str]:
    tips = []
    if mttd is not None and mttd > 180:
        tips.append(
            f"평균 탐지시간(MTTD)이 {mttd:.0f}초로 3분을 넘습니다 — 임계 룰의 window_sec을 "
            f"좁히거나 알림 트리아지 프로세스를 점검하세요."
        )
    if false_positive_rate is not None and false_positive_rate > 0.3:
        tips.append(
            f"오탐률이 {false_positive_rate*100:.0f}%로 30%를 넘습니다 — 노이즈 생성기의 eps를 "
            f"낮추거나 규칙의 임계값을 재조정하세요."
        )
    if uncovered:
        tips.append(f"다음 ATT&CK 기술이 이번 훈련에서 전혀 탐지되지 않았습니다: {', '.join(uncovered)}")
    if not tips:
        tips.append("특별한 개선 권고 사항 없음 — 탐지 성능이 양호합니다.")
    return tips
