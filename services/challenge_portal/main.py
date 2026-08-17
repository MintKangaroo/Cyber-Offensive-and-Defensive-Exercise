"""
Red Challenge Portal (레드팀 전용 챌린지 포털 백엔드)
=====================================================
레드팀이 사용하는 CTF 포털의 백엔드. 대시보드(관전/방어)와 분리된 **공격팀 전용** 진입점.

기능:
  - 챌린지 카탈로그 제공(red_grader.py 가 있는 챌린지 = red 풀이대상만; 플래그/정답은 노출 안 함)
  - 팀별 동적 아티팩트 생성·다운로드(generate_artifact.py/generate_datasets.py team_id 인자)
  - 플래그/필드 제출 → 서버측 grade_red 채점 → 정답 시 solve 기록 + Live Fire 이벤트 발행
  - 포털 자체 스코어보드(팀별 solved/points)

보안: 채점은 전부 서버측에서만. red_grader.py·정답·HMAC 시크릿은 클라이언트로 절대 안 나감.
훈련용 — 팀별 HMAC 동적 플래그라 답 공유 방지.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHALLENGES_ROOT = REPO_ROOT / "challenges"
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")

# 공정성/안티치트(P1-5) — rate-limit·lockout·감사·플래그공유 탐지
import sqlite3  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
import anticheat  # noqa: E402
from shared.service_auth import service_headers

_AC_STATE = anticheat.AntiCheatState()
_AC_CFG = anticheat.Config.from_env()
_AC_DB_PATH = Path(os.environ.get("DATA_DIR", "/tmp")) / "anticheat.db"


def _ac_db() -> sqlite3.Connection:
    c = sqlite3.connect(_AC_DB_PATH)
    c.row_factory = sqlite3.Row
    return c


with _ac_db() as _c0:
    anticheat.init_audit(_c0)
_c0.close()

app = FastAPI(title="Red Challenge Portal")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_methods=["*"], allow_headers=["*"], allow_credentials=False,
)

# solve 상태: {team_id: {challenge_id: {"points":int, "at":float}}}. 볼륨 json으로 영속(P0-3).
_SOLVES: dict[str, dict[str, dict]] = {}
_SOLVES_PATH = Path(os.environ.get("DATA_DIR", "/tmp")) / "portal_solves.json"


def _persist_solves() -> None:
    try:
        _SOLVES_PATH.write_text(json.dumps({"red": _SOLVES, "blue": _BLUE_SOLVES}))
    except OSError:
        pass


def _load_solves() -> None:
    try:
        d = json.loads(_SOLVES_PATH.read_text())
        _SOLVES.update(d.get("red", {}))
        _BLUE_SOLVES.update(d.get("blue", {}))
    except (OSError, ValueError):
        pass

# ---------------------------------------------------------------------------
# 팀 레지스트리 — 자유입력 대신 미리 정의된 팀을 드롭다운으로(오타로 점수판 갈라짐 방지).
# PORTAL_TEAMS 환경변수(JSON: [{"team_id","name","side"}...])로 재정의 가능, 없으면 기본 4팀.
# ---------------------------------------------------------------------------
def _load_teams() -> list[dict]:
    import json as _json
    raw = os.environ.get("PORTAL_TEAMS", "").strip()
    if raw:
        try:
            teams = _json.loads(raw)
            if isinstance(teams, list) and teams:
                return teams
        except ValueError:
            pass
    return [
        {"team_id": "red_alpha", "name": "🔴 레드 알파", "side": "red"},
        {"team_id": "red_bravo", "name": "🔴 레드 브라보", "side": "red"},
        {"team_id": "blue_alpha", "name": "🔵 블루 알파", "side": "blue"},
        {"team_id": "blue_bravo", "name": "🔵 블루 브라보", "side": "blue"},
    ]


TEAMS = _load_teams()


@app.get("/portal/teams")
def list_teams(side: Optional[str] = None):
    items = [t for t in TEAMS if not side or t.get("side") == side]
    return {"teams": items}


# ---------------------------------------------------------------------------
# 카탈로그 로딩
# ---------------------------------------------------------------------------
def _nice_roles(category, explicit):
    """category/nice → NICE work role id 목록(파생). shared.nice_framework 재사용."""
    from shared.nice_framework import roles_for_challenge
    return roles_for_challenge(category, explicit)


def _load_catalog() -> dict[str, dict]:
    """red_grader.py 가 있는 챌린지만 로드. 정답/그레이더는 카탈로그에 담지 않는다."""
    cat: dict[str, dict] = {}
    for cdir in sorted(CHALLENGES_ROOT.glob("*/*/")):
        ymlp = cdir / "challenge.yaml"
        grader = cdir / "grader" / "red_grader.py"
        if not ymlp.exists() or not grader.exists():
            continue
        try:
            data = (yaml.safe_load(ymlp.read_text()) or {}).get("challenge", {}) or {}
        except yaml.YAMLError:
            continue
        cid = data.get("id")
        if not cid:
            continue
        red_task = data.get("red_task", {}) or {}
        pts = data.get("points", {}) or {}
        deploy = cdir / "deploy"
        has_artifact = (deploy / "generate_artifact.py").exists() or (deploy / "generate_datasets.py").exists()
        # 서비스형(docker 배포) 여부: gate 힌트
        gate = "artifact" if has_artifact else "service"
        cat[cid] = {
            "id": cid,
            "dir": str(cdir),
            "category": data.get("category", cdir.parent.name),
            "difficulty": data.get("difficulty", "medium"),
            "title": data.get("title", cid),
            "points_red": int(pts.get("red", 0)),
            "mitre": data.get("mitre", []),
            "nice": _nice_roles(data.get("category"), data.get("nice")),  # NICE work role 파생
            "goal": red_task.get("goal", ""),
            "submit_fields": red_task.get("submit_fields", []) or ["flag"],
            "description": (data.get("description", "") or "").strip(),
            "artifacts": [a for a in (data.get("artifacts", []) or []) if isinstance(a, str) and "." in a],
            "has_artifact": has_artifact,
            "gate": gate,
        }
    return cat


CATALOG = _load_catalog()


def _public(entry: dict) -> dict:
    """클라이언트로 내보낼 안전 필드만(내부 경로 제외)."""
    return {k: entry[k] for k in (
        "id", "category", "difficulty", "title", "points_red", "mitre", "nice",
        "goal", "submit_fields", "description", "artifacts", "has_artifact", "gate")}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _effective_team(team_id: str, match_id: Optional[str]) -> str:
    """매치별 플래그 회전(P3) — match_id가 있으면 팀 키를 매치로 네임스페이스한다.
    그레이더는 HMAC(SECRET, f"{ID}:{team}")로 플래그를 만들므로, team을 "match::team"으로 주면
    같은 팀이라도 매치마다 플래그가 달라진다(그레이더/시크릿 변경 없이 매치별 회전)."""
    return f"{match_id}::{team_id}" if match_id else team_id


# ---------------------------------------------------------------------------
# 모델
# ---------------------------------------------------------------------------
class SubmitReq(BaseModel):
    team_id: str
    fields: dict[str, Any] = {}
    match_id: Optional[str] = None    # 매치별 플래그 회전(P3)
    subject: Optional[str] = None     # 개인 단위 평가(§5): 명시 개인 id(없으면 JWT sub 추출)


def _submitter_subject(authorization: str, explicit: Optional[str]) -> str:
    """제출자 개인 식별. 우선순위: 명시 subject > JWT sub > 'anonymous'."""
    if explicit and explicit.strip():
        return explicit.strip()
    try:
        from shared.rbac import _decode_jwt, _bearer  # noqa: PLC2701
        ident = _decode_jwt(_bearer(authorization))
        if ident and ident.actor:
            return ident.actor
    except Exception:
        pass
    return "anonymous"


# ---------------------------------------------------------------------------
# 엔드포인트
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"service": "challenge_portal", "challenges": len(CATALOG)}


@app.get("/portal/nice-coverage")
def nice_coverage():
    """NICE Framework work role 커버리지(§5 잔여: NICE 매핑). 전체 challenge.yaml의
    category/nice를 집계해 '이 레인지가 어떤 직무 역량을 훈련·평가하는가'를 보고한다.
    MITRE ATT&CK 커버리지(SIEM /detection/attack-coverage)와 평행한 역량 커버리지."""
    from shared.nice_framework import catalog_coverage, WORK_ROLES
    items = []
    for cdir in sorted(CHALLENGES_ROOT.glob("*/*/")):
        ymlp = cdir / "challenge.yaml"
        if not ymlp.exists():
            continue
        try:
            data = (yaml.safe_load(ymlp.read_text()) or {}).get("challenge", {}) or {}
        except yaml.YAMLError:
            continue
        if data.get("id"):
            items.append({"id": data["id"], "category": data.get("category"),
                          "nice": data.get("nice") or []})
    cov = catalog_coverage(items)
    return {"framework": "NICE (NIST SP 800-181r1)", "total_challenges": len(items),
            "work_roles": WORK_ROLES, **cov}


@app.get("/portal/challenges")
def list_challenges(team_id: Optional[str] = None):
    solved = _SOLVES.get(team_id or "", {})
    items = []
    for e in CATALOG.values():
        pub = _public(e)
        pub["solved"] = e["id"] in solved
        items.append(pub)
    # 카테고리 → 난이도 → 점수 순
    order = {"easy": 0, "medium": 1, "hard": 2, "insane": 3}
    items.sort(key=lambda x: (x["category"], order.get(x["difficulty"], 9), x["points_red"]))
    return {"challenges": items, "count": len(items)}


@app.get("/portal/challenges/{cid}")
def get_challenge(cid: str, team_id: Optional[str] = None):
    e = CATALOG.get(cid)
    if not e:
        raise HTTPException(404, "challenge not found")
    pub = _public(e)
    pub["solved"] = cid in _SOLVES.get(team_id or "", {})
    return pub


@app.get("/portal/challenges/{cid}/artifact")
def get_artifact(cid: str, team_id: str = "default", match_id: Optional[str] = None):
    """팀별 동적 아티팩트 생성 후 다운로드. (분석형 챌린지 전용)
    match_id가 있으면 매치별 플래그 회전을 위해 복합 팀키로 생성한다."""
    e = CATALOG.get(cid)
    if not e:
        raise HTTPException(404, "challenge not found")
    if not e["has_artifact"]:
        raise HTTPException(400, "이 챌린지는 다운로드 아티팩트가 없습니다(서비스형).")
    cdir = Path(e["dir"])
    deploy = cdir / "deploy"
    gen = deploy / "generate_artifact.py"
    if not gen.exists():
        gen = deploy / "generate_datasets.py"
    # 팀별(+매치별) 생성(cwd=deploy, 복합 팀키 인자)
    rc = subprocess.run([sys.executable, str(gen.resolve()), _effective_team(team_id, match_id)],
                        cwd=str(deploy), capture_output=True, text=True)
    if rc.returncode != 0:
        raise HTTPException(500, f"아티팩트 생성 실패: {rc.stderr[:200]}")
    # 산출 아티팩트 파일 찾기(challenge.yaml artifacts 우선, 없으면 deploy의 .jsonl 등)
    art = None
    for n in e["artifacts"]:
        if (deploy / n).exists():
            art = deploy / n
            break
    if art is None:
        cands = sorted(deploy.glob("*.jsonl")) + sorted(deploy.glob("*.pcap")) + sorted(deploy.glob("*.log"))
        art = cands[0] if cands else None
    if art is None or not art.exists():
        raise HTTPException(500, "생성된 아티팩트 파일을 찾지 못함")
    data = art.read_bytes()
    return StreamingResponse(
        io.BytesIO(data), media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{cid}_{team_id}_{art.name}"'})


@app.post("/portal/challenges/{cid}/submit")
async def submit(cid: str, req: SubmitReq, authorization: str = Header(default="")):
    e = CATALOG.get(cid)
    if not e:
        raise HTTPException(404, "challenge not found")
    if not req.team_id.strip():
        raise HTTPException(400, "team_id가 필요합니다.")
    grader_path = Path(e["dir"]) / "grader" / "red_grader.py"
    try:
        gmod = _load_module(grader_path, f"grader_{cid.replace('-', '_')}")
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(500, f"grader 로드 실패: {ex}")
    if not hasattr(gmod, "grade_red"):
        raise HTTPException(500, "grader에 grade_red 없음")

    # 매치별 플래그 회전: 채점용 팀키는 복합키(match::team), 스코어보드 기록도 동일 키로 격리.
    eff_team = _effective_team(req.team_id, req.match_id)

    # (P1-5) rate-limit·lockout 선검사 — 무차별 플래그 대입 차단.
    now = time.time()
    allowed, retry = anticheat.precheck(_AC_STATE, eff_team, cid, now, _AC_CFG)
    if not allowed:
        raise HTTPException(429, f"제출 제한: {retry}초 후 재시도(rate-limit/lockout). 반복 오답이 감지되었습니다.")

    submission = {"team_id": eff_team, **(req.fields or {})}
    context = {"challenge_dir": e["dir"]}
    try:
        result = gmod.grade_red(submission, context)
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(400, f"채점 오류(제출 형식 확인): {ex}")

    passed = bool(getattr(result, "passed", False))
    got = int(getattr(result, "points", 0))
    detail = str(getattr(result, "detail", ""))

    # (P1-5) 감사 기록 + 플래그 공유 탐지. 플래그 원문 대신 해시만 저장.
    flag_val = str((req.fields or {}).get("flag") or json.dumps(req.fields, sort_keys=True))
    vhash = anticheat.flag_hash(flag_val)
    conn = _ac_db()
    try:
        anticheat.record(_AC_STATE, conn, eff_team, req.match_id or "", cid, "red", vhash, passed, now, _AC_CFG)
        shared_with = anticheat.detect_sharing(conn, cid, vhash, eff_team) if passed else []
    finally:
        conn.close()
    if shared_with:
        await _emit_collusion(req.team_id, cid, shared_with)  # 담합 신호 → 교관 가시화

    already = cid in _SOLVES.get(eff_team, {})
    if passed and not already:
        # 개인 단위 평가(§5): 이 solve를 개인(subject)에 귀속.
        subject = _submitter_subject(authorization, req.subject)
        _SOLVES.setdefault(eff_team, {})[cid] = {"points": e["points_red"], "at": time.time(),
                                                 "by": subject}
        _persist_solves()
        await _emit_solve(req.team_id, e)

    return {
        "passed": passed,
        "points_awarded": e["points_red"] if (passed and not already) else 0,
        "grader_points": got,
        "already_solved": already,
        "detail": detail,
        "flag_sharing_suspected": shared_with,   # 같은 플래그를 먼저 낸 다른 팀(있으면 담합 의심)
    }


@app.post("/portal/admin/reset")
def portal_admin_reset():
    """훈련 초기화 — 포털의 red/blue solve 기록을 비운다(range_control이 호출)."""
    r, b = len(_SOLVES), len(_BLUE_SOLVES)
    _SOLVES.clear(); _BLUE_SOLVES.clear()
    _persist_solves()
    return {"service": "challenge_portal", "cleared": {"red_teams": r, "blue_teams": b}}


@app.get("/portal/scoreboard")
def scoreboard():
    rows = []
    for team, solves in _SOLVES.items():
        rows.append({
            "team_id": team,
            "solved": len(solves),
            "points": sum(s["points"] for s in solves.values()),
            "last_solve": max((s["at"] for s in solves.values()), default=0),
        })
    rows.sort(key=lambda r: (-r["points"], r["last_solve"]))
    return {"scoreboard": rows}


@app.get("/portal/scoreboard/individuals")
def individual_scoreboard():
    """개인 단위 평가(§5): 팀 내부 '누가 무엇을 얼마나' 기여했는지 개인 리더보드."""
    from shared.assessment import individual_leaderboard
    return {"individuals": individual_leaderboard(_SOLVES)}


@app.get("/portal/scoreboard/team/{team_id}/contribution")
def team_contribution_view(team_id: str, match_id: Optional[str] = None):
    """특정 팀의 개인별 기여도 분해(share_pct 포함) — 팀 내부 평가용."""
    from shared.assessment import team_contribution
    key = _effective_team(team_id, match_id)
    return team_contribution(_SOLVES, key)


async def _emit_collusion(team_id: str, cid: str, shared_with: list[str]) -> None:
    """(P1-5) 플래그 공유 의심 → unmatched_detection 로 교관 감사 피드에 신호(점수 미적립)."""
    ev = {
        "event_id": str(uuid.uuid4()),
        "event_type": "unmatched_detection",
        "timestamp": time.time(),
        "actor": "system",
        "team_id": team_id,
        "scenario_id": "default",
        "target_asset": "flag_integrity",
        "phase": "objective",
        "challenge_id": cid,
        "metadata": {"source": "anticheat", "signal": "flag_sharing_suspected",
                     "challenge": cid, "same_flag_as": shared_with},
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{EVENT_COLLECTOR_URL}/events", json=ev, headers=service_headers())
    except httpx.HTTPError:
        pass


@app.get("/portal/anticheat/audit")
def anticheat_audit(cid: Optional[str] = None, team_id: Optional[str] = None, limit: int = 200):
    """(P1-5) 제출 감사 로그(교관 사후검증). 플래그 원문은 저장 안 함(해시만)."""
    conn = _ac_db()
    q = "SELECT ts,team_id,match_id,cid,side,passed,value_hash FROM submissions"
    cond, params = [], []
    if cid:
        cond.append("cid=?"); params.append(cid)
    if team_id:
        cond.append("team_id=?"); params.append(team_id)
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
    rows = [dict(r) for r in conn.execute(q, params).fetchall()]
    conn.close()
    return {"count": len(rows), "submissions": rows}


@app.get("/portal/anticheat/flagged")
def anticheat_flagged():
    """(P1-5) 담합 의심: 같은 챌린지에 '정답'으로 동일 플래그 해시를 낸 팀이 2개 이상인 건."""
    conn = _ac_db()
    rows = conn.execute(
        """SELECT cid, value_hash, COUNT(DISTINCT team_id) AS teams,
                  GROUP_CONCAT(DISTINCT team_id) AS team_list, MIN(ts) AS first_ts
           FROM submissions WHERE passed=1
           GROUP BY cid, value_hash HAVING teams >= 2 ORDER BY first_ts""").fetchall()
    conn.close()
    return {"flagged": [dict(r) for r in rows]}


async def _emit_solve(team_id: str, e: dict) -> None:
    """정답 시 Live Fire에 red_objective_success 이벤트 발행(관전/교관 가시성 + scoring 연동)."""
    ev = {
        "event_id": str(uuid.uuid4()),
        "event_type": "red_objective_success",
        "timestamp": time.time(),
        "actor": "red",
        "team_id": team_id,
        "scenario_id": "default",
        "target_asset": e.get("category", "ctf"),
        "vuln_id": None,
        "phase": "objective",
        "challenge_id": e["id"],
        "metadata": {"source": "challenge_portal", "title": e["title"], "points": e["points_red"]},
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{EVENT_COLLECTOR_URL}/events", json=ev, headers=service_headers())
    except httpx.HTTPError:
        pass  # 이벤트 유실이 채점을 막지 않게(포털 solve는 이미 기록됨)


# ===========================================================================
# BLUE 포털 — 탐지 챌린지(blue_grader.py 있는 detection 챌린지). 규칙을 제출하면 실제 SIEM
# DetectionEngine으로 채점(attack 탐지 + normal 무오탐). red와 대칭 구조.
# ===========================================================================
def _load_blue_catalog() -> dict[str, dict]:
    cat: dict[str, dict] = {}
    for cdir in sorted(CHALLENGES_ROOT.glob("*/*/")):
        ymlp = cdir / "challenge.yaml"
        grader = cdir / "grader" / "blue_grader.py"
        gen = cdir / "deploy" / "generate_datasets.py"
        if not (ymlp.exists() and grader.exists() and gen.exists()):
            continue
        try:
            data = (yaml.safe_load(ymlp.read_text()) or {}).get("challenge", {}) or {}
        except yaml.YAMLError:
            continue
        cid = data.get("id")
        if not cid:
            continue
        bt = data.get("blue_task", {}) or {}
        pts = data.get("points", {}) or {}
        cat[cid] = {
            "id": cid, "dir": str(cdir),
            "category": data.get("category", "detection"),
            "difficulty": data.get("difficulty", "medium"),
            "title": data.get("title", cid),
            "points_blue": int(pts.get("blue", 0)),
            "mitre": data.get("mitre", []),
            "goal": bt.get("goal", ""),
            "success_criteria": (bt.get("success_criteria", "") or "").strip(),
            "description": (data.get("description", "") or "").strip(),
        }
    return cat


BLUE_CATALOG = _load_blue_catalog()
_BLUE_SOLVES: dict[str, dict[str, dict]] = {}


def _blue_public(e: dict) -> dict:
    return {k: e[k] for k in (
        "id", "category", "difficulty", "title", "points_blue", "mitre",
        "goal", "success_criteria", "description")}


def _ensure_datasets(cdir: Path) -> None:
    """generate_datasets.py로 attack_log/normal_log 생성(정적 데이터셋, 팀 무관)."""
    deploy = cdir / "deploy"
    gen = deploy / "generate_datasets.py"
    subprocess.run([sys.executable, str(gen.resolve())], cwd=str(deploy),
                   capture_output=True, text=True, check=False)


class BlueSubmitReq(BaseModel):
    team_id: str
    rule_yaml: str


@app.get("/portal/blue/challenges")
def blue_list(team_id: Optional[str] = None):
    solved = _BLUE_SOLVES.get(team_id or "", {})
    items = []
    order = {"easy": 0, "medium": 1, "hard": 2, "insane": 3}
    for e in BLUE_CATALOG.values():
        pub = _blue_public(e)
        pub["solved"] = e["id"] in solved
        items.append(pub)
    items.sort(key=lambda x: (order.get(x["difficulty"], 9), x["points_blue"]))
    return {"challenges": items, "count": len(items)}


@app.get("/portal/blue/challenges/{cid}/dataset")
def blue_dataset(cid: str, which: str = "attack"):
    """탐지 규칙 작성을 위해 데이터셋(attack_log/normal_log)을 내려준다."""
    e = BLUE_CATALOG.get(cid)
    if not e:
        raise HTTPException(404, "challenge not found")
    if which not in ("attack", "normal"):
        raise HTTPException(400, "which must be attack|normal")
    cdir = Path(e["dir"])
    _ensure_datasets(cdir)
    fpath = cdir / "deploy" / f"{which}_log.jsonl"
    if not fpath.exists():
        raise HTTPException(500, "데이터셋 생성 실패")
    return StreamingResponse(
        io.BytesIO(fpath.read_bytes()), media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{cid}_{which}_log.jsonl"'})


@app.post("/portal/blue/challenges/{cid}/submit")
async def blue_submit(cid: str, req: BlueSubmitReq):
    e = BLUE_CATALOG.get(cid)
    if not e:
        raise HTTPException(404, "challenge not found")
    if not req.team_id.strip():
        raise HTTPException(400, "team_id가 필요합니다.")
    # YAML 유효성 선검사(친절한 에러)
    try:
        parsed = yaml.safe_load(req.rule_yaml)
        if not parsed:
            raise ValueError("빈 규칙")
    except (yaml.YAMLError, ValueError) as ex:
        raise HTTPException(400, f"규칙 YAML 파싱 오류: {ex}")

    # (P1-5) rate-limit·lockout — 블루 규칙 제출도 무차별 시도 차단.
    now = time.time()
    allowed, retry = anticheat.precheck(_AC_STATE, req.team_id, cid, now, _AC_CFG)
    if not allowed:
        raise HTTPException(429, f"제출 제한: {retry}초 후 재시도(rate-limit/lockout).")

    cdir = Path(e["dir"])
    _ensure_datasets(cdir)
    grader_path = cdir / "grader" / "blue_grader.py"
    try:
        gmod = _load_module(grader_path, f"bgrader_{cid.replace('-', '_')}")
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(500, f"grader 로드 실패: {ex}")

    # 제출 규칙을 임시파일로 저장 후 grade_blue(context) 호출
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
        tf.write(req.rule_yaml)
        rule_path = tf.name
    try:
        result = gmod.grade_blue({"challenge_dir": str(cdir), "submitted_rule_path": rule_path})
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(400, f"채점 오류(규칙 형식 확인): {ex}")
    finally:
        try:
            os.unlink(rule_path)
        except OSError:
            pass

    passed = bool(getattr(result, "passed", False))
    detail = str(getattr(result, "detail", ""))
    # (P1-5) 감사 기록(규칙 해시). 블루는 규칙이라 공유탐지는 신호로만.
    conn = _ac_db()
    try:
        anticheat.record(_AC_STATE, conn, req.team_id, "", cid, "blue",
                         anticheat.flag_hash(req.rule_yaml), passed, now, _AC_CFG)
    finally:
        conn.close()
    already = cid in _BLUE_SOLVES.get(req.team_id, {})
    if passed and not already:
        _BLUE_SOLVES.setdefault(req.team_id, {})[cid] = {"points": e["points_blue"], "at": time.time()}
        _persist_solves()
        await _emit_blue_solve(req.team_id, e)
    return {
        "passed": passed,
        "points_awarded": e["points_blue"] if (passed and not already) else 0,
        "already_solved": already,
        "detail": detail,
    }


@app.get("/portal/blue/scoreboard")
def blue_scoreboard():
    rows = []
    for team, solves in _BLUE_SOLVES.items():
        rows.append({
            "team_id": team, "solved": len(solves),
            "points": sum(s["points"] for s in solves.values()),
            "last_solve": max((s["at"] for s in solves.values()), default=0),
        })
    rows.sort(key=lambda r: (-r["points"], r["last_solve"]))
    return {"scoreboard": rows}


CONFIG_SERVICE_URL = os.environ.get("CONFIG_SERVICE_URL", "http://config_service:8030")
# 패치 토글은 config_service에서 instructor 인증이 필요. 포털은 신뢰 백엔드로서 서버측 시크릿
# (INSTRUCTOR_TOKEN)을 보유해 블루의 방어 패치를 대리 인가한다(블루 클라이언트엔 토큰 미노출).
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "").strip()
_VULN_CATALOG_PATH = REPO_ROOT / "shared" / "vuln_catalog.json"


@app.get("/portal/blue/patches")
async def blue_patches():
    """전체 취약점 카탈로그(60종) + config_service 라이브 패치 상태 병합 → 패치 보드용."""
    import json as _json
    try:
        catalog = _json.loads(_VULN_CATALOG_PATH.read_text())
    except (OSError, ValueError):
        catalog = {}
    # 라이브 패치 상태(토글된 것만)
    live: dict = {}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{CONFIG_SERVICE_URL}/config/patches")
            live = r.json() if r.status_code == 200 else {}
    except httpx.HTTPError:
        live = {}
    board: dict[str, dict[str, bool]] = {}
    for asset, vulns in catalog.items():
        board[asset] = {}
        for v in vulns:
            vid = v.get("id")
            if vid:
                board[asset][vid] = bool((live.get(asset) or {}).get(vid, False))
    return board


class PatchReq(BaseModel):
    asset: str
    vuln_id: str
    patched: bool
    reason: str = "blue portal patch"


@app.post("/portal/blue/patch")
async def blue_patch(req: PatchReq):
    """패치 토글 → config_service로 프록시(dev-mode에선 토큰 없이 통과)."""
    headers = {"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"} if INSTRUCTOR_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(f"{CONFIG_SERVICE_URL}/instructor/patch/toggle",
                                  json=req.model_dump(), headers=headers)
            if r.status_code >= 400:
                raise HTTPException(r.status_code, f"config_service 거부: {r.text[:150]}")
            return r.json()
    except httpx.HTTPError as ex:
        raise HTTPException(502, f"config_service 연결 실패: {ex}")


async def _emit_blue_solve(team_id: str, e: dict) -> None:
    ev = {
        "event_id": str(uuid.uuid4()),
        "event_type": "blue_detection_success",
        "timestamp": time.time(), "actor": "blue", "team_id": team_id,
        "scenario_id": "default", "target_asset": "detection", "vuln_id": None,
        "phase": None, "challenge_id": e["id"],
        "metadata": {"source": "challenge_portal", "title": e["title"], "points": e["points_blue"]},
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{EVENT_COLLECTOR_URL}/events", json=ev, headers=service_headers())
    except httpx.HTTPError:
        pass


_load_solves()  # 볼륨에 저장된 solve 복원(P0-3)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8060)
