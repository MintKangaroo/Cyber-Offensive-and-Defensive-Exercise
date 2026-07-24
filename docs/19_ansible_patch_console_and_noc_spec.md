# Ansible 패치 콘솔 + NOC 모니터링 — Claude Code 빌드 프롬프트

> Blue팀이 (1) 취약점을 Ansible 플레이북으로 "실제 운영처럼" 패치하고,
> (2) 서비스 가용성을 NOC 스타일 대시보드로 관제하는 두 기능의 빌드 사양.
> 04번(백엔드 보강)의 Config Service·Recovery Watcher를 기반으로 확장한다.

---

## 1. 설계 원칙

- **Ansible = 실행 UX, Config Service = 상태 저장소.** 플레이북의 최종 동작은 항상
  Config Service의 patch 상태를 갱신하는 것으로 귀결된다(04번 5절과 동일 계약).
- **화이트리스트 플레이북만 실행 가능.** Blue팀이 임의 playbook을 올리거나 임의 대상에
  실행할 수 없다. 취약점 ID(GS-001 등) → 플레이북 파일 1:1 고정 매핑.
- **모든 실행은 audit log.** 누가/언제/어떤 취약점을/성공했는지 04번 Instructor audit와
  동일 스키마로 기록.
- **NOC와 SIEM은 분리.** NOC는 가용성(uptime/latency/error rate), SIEM은 보안 로그. 데이터 소스는
  같은 `/health` 엔드포인트를 공유하되 목적이 다르다.

---

## 2. Ansible 패치 콘솔

### 2.1 아키텍처
```
Blue팀 대시보드 ──▶ Patch Console API ──▶ ansible-runner (화이트리스트 playbook 실행)
                        │                         │
                        │                         ▼
                        │                  (플레이북이 대상 트윈의 설정/코드를 안전 버전으로 교체)
                        ▼                         │
                   audit log                      ▼
                                          Config Service.set_patch(vuln_id, patched=true)
```

### 2.2 인벤토리 & 플레이북 구조
```
platform/patch_console/
├─ inventory.yml              # 트윈 컨테이너만 대상(호스트 확장 금지)
├─ playbooks/
│  ├─ patch_GS-001.yml        # SQLi -> 파라미터 바인딩 코드로 교체
│  ├─ patch_GS-002.yml        # 하드코딩 계정 제거 + 시크릿 로테이션
│  ├─ patch_PP-003.yml        # 커맨드인젝션 -> subprocess 배열화 버전 배포
│  └─ ... (vuln_id 1:1 대응)
├─ whitelist.py               # vuln_id -> playbook 경로 매핑(하드코딩, 동적 경로 조합 금지)
└─ api/main.py                # Patch Console API(FastAPI)
```

**중요**: `whitelist.py`는 문자열 조합으로 경로를 만들지 않는다(`f"patch_{vuln_id}.yml"` 같은 방식
은 vuln_id에 `../../etc/passwd` 를 넣는 순간 경로탈출 취약점이 됨 — 아이러니하게도 우리가 만든
안전장치 콘솔 자체가 새 취약점이 되는 걸 막아야 함). 반드시 **명시적 dict 매핑**만 허용.

### 2.3 Patch Console API
```
POST /patch/apply     body: {vuln_id, team_id, reason}
  -> whitelist에서 playbook 조회 (없으면 400)
  -> ansible-runner로 인벤토리 범위 내 실행(타임아웃 60초)
  -> 성공 시 Config Service.set_patch(asset, vuln_id, patched=true, reason)
  -> audit log 기록(04번 AuditEntry 스키마)
  -> 실행 stdout/rc 반환

GET  /patch/status/{vuln_id}   -> 마지막 실행 결과/상태
GET  /patch/available          -> 화이트리스트된 vuln_id 목록(대시보드가 버튼 렌더링용)
```

### 2.4 플레이북 예시 패턴 (patch_GS-001.yml)
```yaml
- name: Patch GS-001 (SQL Injection) on ground_station
  hosts: ground_station_twin
  gather_facts: false
  tasks:
    - name: Verify target container matches expected image label
      # 안전장치: 화이트리스트 대상 외 컨테이너에 실수로 적용되는 것 방지
      command: docker inspect --format '{{"{{"}}.Config.Labels.app{{"}}"}}}}' "{{ container_name }}"
      register: label_check
      failed_when: "'ground-station-twin' not in label_check.stdout"

    - name: Set PATCH flag via Config Service (real patch mechanism)
      uri:
        url: "http://config_service:8030/instructor/patch/toggle"
        method: POST
        body_format: json
        body:
          asset: "ground_station"
          vuln_id: "GS-001"
          patched: true
          reason: "ansible playbook patch_GS-001"
        headers:
          Authorization: "Bearer {{ instructor_token }}"
```
**핵심**: 플레이북이 실제로 하는 일은 (a) 대상 검증 (b) Config Service 호출. 파라미터 바인딩 코드
자체는 이미 트윈에 구현되어 있고(04번 설계), "패치"는 그 안전 경로를 활성화하는 것 — 즉 실제
운영에서의 "설정 배포"를 흉내낸다. 코드 자체를 재배포하는 방식으로 확장하려면 별도 하드닝 필요
(임의 코드 실행 경로가 되지 않도록 서명된 아티팩트만 배포).

### 2.5 안전장치 (필수)
- Patch Console API는 교관 토큰 또는 Blue팀 역할 토큰만 호출 가능(Red는 접근 불가).
- ansible-runner 실행은 `infra/hardening` 프로파일과 동일한 격리 컨테이너에서.
- 플레이북이 인벤토리 밖 호스트를 건드릴 수 없도록 inventory.yml을 `range_control` 네트워크의
  트윈 컨테이너로만 고정(호스트 SSH 인벤토리 확장 금지 — 이 콘솔이 실제 인프라를 건드리면 안 됨).
- 실행 타임아웃/재시도 제한(무한 재실행으로 자원 고갈 방지).

---

## 3. NOC 모니터링 대시보드

### 3.1 데이터원 공유 (04번 Recovery Watcher와 통합)
```
Health Poller (신규, 경량 워커)
   ├─ 각 트윈 /health 주기 폴링(5초)
   ├─ uptime%, 응답 latency, 최근 에러율 계산
   ├─ Recovery Watcher가 이 결과를 재사용(04번 2절의 "health 3회 연속 정상" 조건)
   └─ NOC API가 이 결과를 대시보드에 노출
```
**한 번의 폴링으로 두 목적(복구판정 + NOC 표시)을 만족** — 중복 구현 방지.

### 3.2 NOC API
```
GET /noc/status            -> 자산별 {up: bool, latency_ms, uptime_pct_1h, error_rate}
GET /noc/history?asset=     -> 시계열(업타임/레이턴시 그래프용)
WS  /noc/ws                -> 실시간 상태 변화 스트림
```

### 3.3 대시보드 화면 (NOC)
- **서비스 상태 보드**: 자산별 up/down 신호등 + 최근 1시간 업타임%.
- **레이턴시 그래프**: 시계열 라인차트(recharts). 공격으로 인한 응답지연 시각화.
- **에러율**: 5xx 비율 추이. 급증 시 "공격받아 서비스 저하 중" 신호로 해석 가능.
- **Live Fire 이벤트와 상관 표시(선택)**: 같은 시간대에 asset_compromised 이벤트가 있었으면
  그래프에 마커 표시 — "공격 때문에 느려진 건지" Blue가 바로 판단 가능.
- **디자인**: SIEM/Live Fire와 다른 톤(NOC는 초록/노랑/빨강의 전통적 운영 대시보드 느낌으로
  차별화 — 공방 HUD와 혼동되지 않게).

### 3.4 왜 Recovery 판정과 공유해야 하는가
04번 문서의 Recovery Watcher는 "patched 확인 + health 3회 연속 정상"으로 `asset_recovered`를
발행한다. NOC의 Health Poller가 정확히 이 데이터를 만드는 컴포넌트이므로, 별도로 만들지 않고
**Health Poller를 단일 구현으로 두고 Recovery Watcher와 NOC API가 둘 다 구독**하게 한다.

---

## 4. 통합 다이어그램

```
                     ┌─────────────────┐
                     │  Health Poller   │ (5초 주기 /health 폴링)
                     └────────┬────────┘
                 ┌────────────┼────────────┐
                 ▼                         ▼
      ┌─────────────────┐        ┌──────────────────┐
      │ Recovery Watcher │        │   NOC API/WS      │
      │ (04번, 점수연결)  │        │ (대시보드 노출)     │
      └─────────────────┘        └──────────────────┘

Blue팀 ──▶ Patch Console API ──▶ ansible-runner(화이트리스트) ──▶ Config Service.set_patch
                │                                                        │
                └──────────────── audit log ────────────────────────────┘
                                                                          ▼
                                                              Health Poller가 다음 폴링에서
                                                              정상 확인 → Recovery Watcher가
                                                              asset_recovered(+50) 발행
```

---

## 5. Definition of Done

- Blue팀이 대시보드에서 "GS-001 패치" 버튼 클릭 → ansible-runner 실행 로그 확인 → Config Service
  patched=true 반영 → safe_probe가 patched 확인 → Blue 점수 +50.
- 화이트리스트에 없는 vuln_id로 패치 시도 시 400 거부.
- NOC 대시보드가 트윈 다운 시 즉시 신호등 빨강, 복구 시 초록 + 동시에 `asset_recovered` 이벤트로
  Blue 점수 반영.
- Patch Console 실행 이력이 audit log에 전부 남음.
