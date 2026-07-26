"""
시나리오 저작 지원(P1-3) — 순수 로직
=====================================
스키마(shared.challenge_schema.Scenario)는 '형식'을 검증한다. 여기서는 그 너머의 '의미'를
검증하고(lint), 실행 없이 타임라인을 투영(dry_run)하며, 경과 시간→예상 단계(phase_clock)를
계산한다. 교관이 시나리오를 작성할 때 저장/실행 전에 문제를 잡는다.

입력은 파싱된 scenario 딕셔너리(YAML의 `scenario:` 하위). 상태 없음 → 테스트 용이.
"""
from __future__ import annotations


def _issue(level: str, code: str, msg: str, where: str = "") -> dict:
    return {"level": level, "code": code, "message": msg, "where": where}


def collect_stages(s: dict) -> list[dict]:
    """stage 수집. 단일 시나리오는 top-level `stages`, 크로스오버는 `phase_*.stages` 를 평탄화."""
    if s.get("stages"):
        return list(s["stages"])
    flat: list[dict] = []
    for k, v in s.items():
        if k.startswith("phase") and isinstance(v, dict) and v.get("stages"):
            flat.extend(v["stages"])
    return flat


def lint_scenario(s: dict) -> list[dict]:
    """스키마 너머 의미 검증. error/warning 리스트 반환."""
    issues: list[dict] = []
    for f in ("id", "name"):
        if not s.get(f):
            issues.append(_issue("error", "missing_field", f"필수 필드 누락: {f}", f))
    stages = collect_stages(s)
    if not stages:
        issues.append(_issue("error", "missing_field", "stage 가 없음(stages 또는 phase_*.stages)", "stages"))
        return issues

    single = bool(s.get("stages"))   # 단일 시나리오만 stage 번호 유일/순서 규칙 적용(크로스오버는 phase별 리셋)
    if single:
        nums = [st.get("stage") for st in stages]
        seen = set()
        for n in nums:
            if n in seen:
                issues.append(_issue("error", "duplicate_stage", f"중복 stage 번호: {n}", f"stage {n}"))
            seen.add(n)
        stage_set = set(nums)
        for st in stages:
            n = st.get("stage")
            req = st.get("requires_stage")
            if req is not None:
                if req not in stage_set:
                    issues.append(_issue("error", "bad_requires",
                                         f"stage {n} 이 존재하지 않는 stage {req} 를 요구", f"stage {n}"))
                elif isinstance(n, int) and isinstance(req, int) and req >= n:
                    issues.append(_issue("error", "forward_requires",
                                         f"stage {n} 이 자신 이후/자신({req})을 요구(전방·자기 참조)", f"stage {n}"))

    initial = set((s.get("initial_vuln_state") or {}).keys())
    for st in stages:
        n = st.get("stage")
        vid = (st.get("match") or {}).get("vuln_id")
        if vid and initial and vid not in initial:
            issues.append(_issue("warning", "unknown_vuln",
                                 f"stage {n} 의 vuln_id '{vid}' 가 initial_vuln_state 에 없음", f"stage {n}"))
        pts = st.get("points", 0)
        if not isinstance(pts, (int, float)) or pts <= 0:
            issues.append(_issue("warning", "nonpositive_points",
                                 f"stage {n} 의 points 가 0 이하", f"stage {n}"))

    if not any(st.get("is_final") for st in stages):
        issues.append(_issue("warning", "no_final_stage", "is_final 로 표시된 최종 stage 가 없음"))
    if not (s.get("blue_objectives")):
        issues.append(_issue("warning", "no_blue_objectives", "blue_objectives 가 없어 방어 채점이 불가"))
    cb = s.get("chain_bonus") or {}
    if "within_sec" in cb and cb["within_sec"] <= 0:
        issues.append(_issue("warning", "bad_chain_window", "chain_bonus.within_sec 가 0 이하"))
    return issues


def project_timeline(s: dict) -> list[dict]:
    """실행 없이 stage 타임라인 투영. stage.expected_sec 가 있으면 사용, 없으면 time_limit 균등분할."""
    stages = collect_stages(s)   # 단일=top-level, 크로스오버=phase 순서. 저작 순서 보존.
    if not stages:
        return []
    total = int(s.get("time_limit_sec", 0)) or 0
    have_expected = all("expected_sec" in st for st in stages)
    tl: list[dict] = []
    cursor = 0
    if have_expected:
        for st in stages:
            dur = int(st["expected_sec"])
            tl.append({"stage": st.get("stage"), "name": st.get("name", ""),
                       "start_sec": cursor, "end_sec": cursor + dur, "points": st.get("points", 0)})
            cursor += dur
    else:
        n = len(stages)
        base = (total // n) if total else 0
        for i, st in enumerate(stages):
            dur = (total - base * (n - 1)) if i == n - 1 else base   # 마지막이 나머지 흡수
            tl.append({"stage": st.get("stage"), "name": st.get("name", ""),
                       "start_sec": cursor, "end_sec": cursor + dur, "points": st.get("points", 0)})
            cursor += dur
    return tl


def dry_run(s: dict) -> dict:
    """저장/실행 없이 검증 + 타임라인 투영 결과."""
    issues = lint_scenario(s)
    errors = [i for i in issues if i["level"] == "error"]
    warnings = [i for i in issues if i["level"] == "warning"]
    tl = project_timeline(s)
    stages = collect_stages(s)
    return {
        "ok": not errors,
        "error_count": len(errors), "warning_count": len(warnings),
        "issues": issues,
        "timeline": tl,
        "total_points": sum(int(st.get("points", 0) or 0) for st in stages),
        "stage_count": len(stages),
        "time_limit_sec": int(s.get("time_limit_sec", 0) or 0),
    }


def phase_clock(s: dict, elapsed_sec: float) -> dict:
    """경과 시간 → 현재 예상 stage/잔여. 투영 타임라인 기준(교관 페이싱용)."""
    tl = project_timeline(s)
    total = int(s.get("time_limit_sec", 0) or 0)
    remaining = max(0, total - int(elapsed_sec))
    overtime = elapsed_sec > total if total else False
    current = None
    stage_remaining = 0
    for seg in tl:
        if seg["start_sec"] <= elapsed_sec < seg["end_sec"]:
            current = seg["stage"]
            stage_remaining = int(seg["end_sec"] - elapsed_sec)
            break
    return {
        "time_limit_sec": total, "elapsed_sec": int(elapsed_sec),
        "remaining_sec": remaining, "overtime": overtime,
        "current_stage": current, "stage_remaining_sec": stage_remaining,
        "timeline": tl,
    }
