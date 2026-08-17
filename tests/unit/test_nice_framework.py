"""
NICE Framework 매핑 (§5 잔여: NICE 매핑) 단위 테스트
====================================================
- category → work role 파생, explicit nice 우선, 무효 id 필터
- 카탈로그 커버리지 집계(covered/uncovered/pct)
- Challenge 스키마 nice 필드 수용
"""
from shared.nice_framework import (
    WORK_ROLES, roles_for_challenge, catalog_coverage, normalize_role,
)


def test_category_derivation():
    # web → 파생 역할(정렬·유효 id만)
    r = roles_for_challenge("web")
    assert "AN-EXP-001" in r and "PR-VAM-001" in r
    assert r == sorted(r)
    # 미지의 category → misc 폴백
    assert roles_for_challenge("nonsense") == roles_for_challenge("misc")


def test_explicit_overrides_category():
    r = roles_for_challenge("web", explicit=["PR-CDA-001"])
    assert r == ["PR-CDA-001"]           # 명시 nice 우선
    # 무효 id는 걸러지고, 전부 무효면 category 파생으로 폴백
    assert roles_for_challenge("forensics", explicit=["BOGUS-999"]) == roles_for_challenge("forensics")


def test_normalize_role():
    assert normalize_role("PR-CDA-001") == "PR-CDA-001"
    assert normalize_role("XX-YYY-999") is None


def test_catalog_coverage_aggregates():
    items = [
        {"id": "WEB-001", "category": "web"},
        {"id": "FOR-001", "category": "forensics"},
        {"id": "DET-001", "category": "detection", "nice": ["PR-CDA-001"]},
    ]
    cov = catalog_coverage(items)
    # 커버된 역할에 web/forensics/detection 파생이 포함
    assert "AN-EXP-001" in cov["covered"]     # web
    assert "IN-FOR-002" in cov["covered"]     # forensics
    assert "PR-CDA-001" in cov["covered"]     # detection(explicit)
    # PR-CDA-001은 detection 1건이 기여
    assert cov["roles"]["PR-CDA-001"]["count"] == 1
    assert "DET-001" in cov["roles"]["PR-CDA-001"]["items"]
    # covered + uncovered = 전체 work role
    assert set(cov["covered"]) | set(cov["uncovered"]) == set(WORK_ROLES)
    assert 0 <= cov["coverage_pct"] <= 100


def test_challenge_schema_accepts_nice():
    from shared.challenge_schema import Challenge
    c = Challenge(id="WEB-002", title="t", category="web", difficulty="medium",
                  points={"red": 100, "blue": 0}, nice=["AN-EXP-001"])
    assert c.nice == ["AN-EXP-001"]
    # nice 미지정도 유효(기본 빈 목록)
    c2 = Challenge(id="FOR-001", title="t", category="forensics", difficulty="hard",
                   points={"red": 100, "blue": 0})
    assert c2.nice == []
