# 챌린지 검증 가이드 — 만든 문제가 의도대로 동작하는지 직접 확인하기

> C-QA 파이프라인(`infra/challenge_qa/`)이 자동으로 검증하지만, 이 문서는 **사람이 눈으로
> 보면서 직접 확인**할 수 있게 복붙 가능한 명령어로 정리했다. GCP(또는 Docker 되는 환경)에서
> `cyber-range-contracts.zip`을 풀고 그 안에서 실행하면 된다.

**공통 준비**:
```bash
cd cyber-range-contracts
python3 -m venv venv && source venv/bin/activate
pip install fastapi uvicorn pyjwt scikit-learn numpy requests pyyaml
```

---

## 1. WEB-002 (JWT 위조) — medium

```bash
cd challenges/web/WEB-002/deploy
CHALLENGE_SECRET=test-secret uvicorn main:app --port 8100 &
sleep 1

# (a) 위조 전에는 승인 API가 401을 반환하는지 확인
curl -s -X POST http://localhost:8100/api/mission/approve | python3 -m json.tool
# 기대: {"detail":"invalid token"} (401)

# (b) 의도된 해법 실행 -> 플래그 획득
cd ../solution
CHALLENGE_SECRET=test-secret python3 exploit.py http://localhost:8100 verify_team
# 기대 출력: flag{jwt_forged_...}  (verify_team에 대해 결정론적인 해시값)

# (c) 채점기로 검증
cd ../grader
CHALLENGE_SECRET=test-secret python3 -c "
from red_grader import grade_red, dynamic_flag
flag = dynamic_flag('verify_team')
result = grade_red({'team_id':'verify_team','flag':flag}, {})
print(result)
"
# 기대: GradeResult(passed=True, points=150, ...)

# (d) 패치 후 재시도 -> 실패해야 함
kill %1
cd ../deploy
CHALLENGE_SECRET=test-secret GS_JWT_STRONG_SECRET=strong-random-key PATCH_WEB_002=true uvicorn main:app --port 8100 &
sleep 1
cd ../solution
CHALLENGE_SECRET=test-secret python3 exploit.py http://localhost:8100 verify_team
# 기대: RuntimeError("both exploit methods failed...") -> 패치가 실제로 막음
kill %1
```

---

## 2. WEB-000 (디버그 노출) — easy

```bash
cd challenges/web/WEB-000/deploy
CHALLENGE_SECRET=test-secret uvicorn main:app --port 8101 &
sleep 1

curl -s http://localhost:8101/api/debug/config -H "X-Team-Id: verify_team" | python3 -m json.tool
# 기대: jwt_secret, flag 필드가 그대로 노출됨

cd ../solution
CHALLENGE_SECRET=test-secret python3 exploit.py http://localhost:8101 verify_team
# 기대: flag{debug_exposed_...}

# 패치 후 404 확인
kill %1
PATCH_WEB_000=true CHALLENGE_SECRET=test-secret uvicorn main:app --port 8101 --app-dir . &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8101/api/debug/config
# 기대: 404
kill %1
```

---

## 3. DET-000 (브루트포스 탐지 룰) — easy, Blue 전용

```bash
cd challenges/detection/DET-000/deploy
python3 generate_datasets.py
wc -l attack_log.jsonl normal_log.jsonl
# 기대: attack_log.jsonl 10줄, normal_log.jsonl 30줄

cd ../grader
python3 -c "
from blue_grader import grade_blue
result = grade_blue({'challenge_dir': '../'})
print(result)
"
# 기대: GradeResult(passed=True, points=60, detail='attack_detected=True(1 alerts) normal_false_positive=False(0 alerts)')
```

**직접 눈으로 확인하고 싶다면**, `deploy/attack_log.jsonl`을 열어서 동일 `src.ip`(10.13.37.66)로
10건이 60초 이내 몰려있는지, `normal_log.jsonl`은 여러 IP에 흩어져 있는지 직접 봐도 된다.

---

## 4. FOR-000 (평문 자격증명 카빙) — easy

```bash
cd challenges/forensics/FOR-000/deploy
CHALLENGE_SECRET=test-secret python3 generate_artifact.py verify_team
cat backup_config.txt
# 기대: service_account=DUMMY\svc_backup, password=B@ckup_XXXXXXXXXX! 형태

cd ../solution
python3 exploit.py ../deploy/backup_config.txt
# 기대: {'service_account': 'DUMMY\\svc_backup', 'password': 'B@ckup_...'}

cd ../grader
CHALLENGE_SECRET=test-secret python3 -c "
from red_grader import grade_red
import subprocess, sys
sys.path.insert(0, '../solution')
from exploit import solve
result = solve('../deploy/backup_config.txt')
grade = grade_red({'team_id':'verify_team', **result}, {})
print(grade)
"
# 기대: GradeResult(passed=True, points=50, ...)
```

---

## 5. REV-000 (XOR 플래그) — easy

```bash
cd challenges/reversing/REV-000/deploy
CHALLENGE_SECRET=test-secret python3 generate_artifact.py verify_team
xxd encoded.bin | head -2   # 인코딩된 바이너리 확인(사람 눈엔 의미 없는 바이트)

cd ../solution
python3 exploit.py ../deploy/encoded.bin
# 기대: flag{xor_...}

cd ../grader
CHALLENGE_SECRET=test-secret python3 -c "
import sys; sys.path.insert(0, '../solution')
from exploit import solve
from red_grader import grade_red
flag = solve('../deploy/encoded.bin')
print(grade_red({'team_id':'verify_team','flag':flag}, {}))
"
# 기대: GradeResult(passed=True, points=100, ...)
```

---

## 6. NET-000 (평문 텔넷 캡처) — easy

```bash
cd challenges/network/NET-000/deploy
CHALLENGE_SECRET=test-secret python3 generate_artifact.py verify_team
cat capture_log.jsonl   # 각 줄이 패킷 하나. login/Password 프롬프트와 응답을 직접 확인 가능

cd ../solution
python3 exploit.py ../deploy/capture_log.jsonl
# 기대: {'username': 'svc_operator', 'password': 'pw_...'}

cd ../grader
CHALLENGE_SECRET=test-secret python3 -c "
import sys; sys.path.insert(0, '../solution')
from exploit import solve
from red_grader import grade_red
result = solve('../deploy/capture_log.jsonl')
print(grade_red({'team_id':'verify_team', **result}, {}))
"
# 기대: GradeResult(passed=True, points=50, detail=\"{'username': True, 'password': True}\")
```

---

## 7. AI-000 (특징공간 회피) — easy

```bash
cd challenges/ai/AI-000/deploy
pip install scikit-learn numpy
python3 train_model.py
# 기대 출력: "malicious_score=1.000" (악성 샘플이 정확히 탐지됨)

CHALLENGE_SECRET=test-secret uvicorn main:app --port 8102 &
sleep 1

# 원본 악성 샘플 -> malicious로 판정되는지
curl -s -X POST http://localhost:8102/predict -H "Content-Type: application/json" \
  -d '{"length":75,"dot_count":6,"special_char_count":10,"has_at":1,"is_ip_like":1,"has_keyword":1,"team_id":"verify_team"}' \
  | python3 -m json.tool
# 기대: {"malicious_score": 1.0 근처, "verdict": "malicious"} (flag 필드 없음)

cd ../solution
CHALLENGE_SECRET=test-secret python3 exploit.py http://localhost:8102 verify_team
# 기대: flag{feature_space_evasion_...}

kill %1
```

**직접 모델 계수를 보고 싶다면**:
```bash
cd challenges/ai/AI-000/deploy
python3 -c "
import pickle
model = pickle.load(open('detector.pkl','rb'))
names = ['length','dot_count','special_char_count','has_at','is_ip_like','has_keyword']
for n, c in zip(names, model.coef_[0]):
    print(f'{n}: {c:+.3f}')
"
# 계수가 양수인 특징을 낮추면 malicious_score가 내려간다 — 이게 회피의 원리.
```

---

## 전체 일괄 검증 (C-QA 자동화, Docker 없이 스키마/안전성만)

```bash
cd cyber-range-contracts
for id in WEB-002 WEB-000 DET-000 FOR-000 REV-000 NET-000 AI-000; do
  echo "=== $id ==="
  python3 infra/challenge_qa/run_all.py --challenge $id --skip-docker
done
```

## Docker 환경에서 전체 자동 검증 (실제 GCP에서)

```bash
python3 infra/challenge_qa/run_all.py --challenge WEB-002 \
  --base-url http://localhost:8100 --patch-env PATCH_WEB_002=true
# schema_validate -> safety_scan -> deploy_up -> intended_solve -> blank_submit
# -> blue_verify(패치 후 재공격 차단 확인) -> flag_determinism -> teardown
# 전부 자동으로 돌아간다.
```

---

## 생성물 정리 (검증 후)

```bash
find challenges -name "*.jsonl" -delete
find challenges -name "*.bin" -delete
find challenges -name "*.pkl" -delete
find challenges -name "backup_config.txt" -delete
find challenges -name "encoded.bin" -delete
find challenges -name "QA_PASSED" -delete
find challenges -name "__pycache__" -exec rm -rf {} +
```
