"""
NICE Framework 매핑 (NIST SP 800-181r1)
========================================
챌린지/시나리오를 NICE Cybersecurity Workforce Framework의 **Work Role**에 매핑해,
"이 레인지가 어떤 직무 역량을 훈련·평가하는가"를 커리큘럼/평가 관점에서 집계한다.
기존 MITRE ATT&CK 커버리지(SIEM /detection/attack-coverage)와 평행한 '역량 커버리지'.

설계:
  - 각 챌린지는 명시적 `nice`(work role id 목록)를 가질 수 있고, 없으면 category에서 파생한다.
  - work role id 는 NICE 표준 코드(예: PR-CDA-001 Cyber Defense Analyst)를 쓴다.
  - 순수 함수만 두어 어떤 서비스에서도 재사용/테스트가 쉽다(상태 없음).
"""
from __future__ import annotations

# NICE Work Role 카탈로그(레인지가 다루는 부분집합, NIST SP 800-181r1 코드).
WORK_ROLES: dict[str, str] = {
    "AN-EXP-001": "Exploitation Analyst",
    "AN-TWA-001": "Threat/Warning Analyst",
    "PR-CDA-001": "Cyber Defense Analyst",
    "PR-CIR-001": "Cyber Defense Incident Responder",
    "PR-VAM-001": "Vulnerability Assessment Analyst",
    "PR-INF-001": "Cyber Defense Infrastructure Support Specialist",
    "IN-FOR-002": "Cyber Defense Forensics Analyst",
    "OM-ADM-001": "System Administrator",
    "OM-NET-001": "Network Operations Specialist",
    "SP-DEV-001": "Software Developer",
    "OV-MGT-001": "Communications Security (COMSEC) Manager",  # 위기소통/운영 인젝트 대응
}

# 챌린지 category → 기본 work role(명시 nice 없을 때 파생).
CATEGORY_ROLES: dict[str, list[str]] = {
    "web": ["AN-EXP-001", "PR-VAM-001", "SP-DEV-001"],
    "network": ["AN-EXP-001", "PR-CDA-001", "OM-NET-001"],
    "forensics": ["IN-FOR-002", "PR-CIR-001"],
    "detection": ["PR-CDA-001", "AN-TWA-001"],
    "reversing": ["AN-EXP-001"],
    "ics": ["PR-CDA-001", "PR-INF-001", "OM-ADM-001"],
    "ai": ["AN-TWA-001", "AN-EXP-001"],
    "crypto": ["AN-EXP-001", "SP-DEV-001"],
    "cloud": ["PR-CDA-001", "OM-ADM-001"],
    "misc": ["PR-CDA-001"],
}

# A/D·시나리오 액터/성격 → work role(챌린지 밖의 훈련 요소용).
ACTOR_ROLES: dict[str, list[str]] = {
    "red": ["AN-EXP-001", "PR-VAM-001"],
    "blue": ["PR-CDA-001", "PR-CIR-001"],
    "inject": ["PR-CIR-001", "OV-MGT-001"],  # 비기술 위기소통 인젝트
}


def normalize_role(role_id: str) -> str | None:
    """알려진 work role id면 그대로, 아니면 None(유효성 필터)."""
    return role_id if role_id in WORK_ROLES else None


def roles_for_challenge(category: str | None, explicit: list[str] | None = None) -> list[str]:
    """챌린지의 work role 목록. explicit(nice 필드)가 있으면 우선, 없으면 category에서 파생.
    유효한 id만, 정렬해 결정론적으로 반환."""
    if explicit:
        roles = [r for r in explicit if r in WORK_ROLES]
        if roles:
            return sorted(set(roles))
    cat = (category or "misc").lower()
    return sorted(set(CATEGORY_ROLES.get(cat, CATEGORY_ROLES["misc"])))


def catalog_coverage(items: list[dict]) -> dict:
    """챌린지/시나리오 목록(dict: category, nice?) → NICE work role 커버리지 집계.

    반환: {
      "roles": {role_id: {"title","count","items":[id...]}},  # 커버된 역할
      "covered": [role_id...],           # 커버된 역할(정렬)
      "uncovered": [role_id...],         # 카탈로그에 있으나 미커버
      "coverage_pct": 0~100,
    }
    """
    roles: dict[str, dict] = {}
    for it in items:
        rids = roles_for_challenge(it.get("category"), it.get("nice"))
        cid = it.get("id") or it.get("challenge_id") or "?"
        for rid in rids:
            slot = roles.setdefault(rid, {"title": WORK_ROLES[rid], "count": 0, "items": []})
            slot["count"] += 1
            slot["items"].append(cid)
    covered = sorted(roles)
    uncovered = sorted(set(WORK_ROLES) - set(covered))
    pct = round(100 * len(covered) / len(WORK_ROLES)) if WORK_ROLES else 0
    return {"roles": roles, "covered": covered, "uncovered": uncovered, "coverage_pct": pct}
