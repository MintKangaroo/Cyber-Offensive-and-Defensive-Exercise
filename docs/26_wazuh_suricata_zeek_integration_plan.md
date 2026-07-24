# Wazuh / Suricata / Zeek 연동 — 상세 실행 계획

> 01번 문서에서 "SOC: Wazuh/Suricata/Zeek/pfSense"로 나열만 됐던 부분을 실제로 어떻게
> Docker Compose 환경에 붙이는지 정리했다. 이 파트의 핵심 난관은 "Docker 브리지 네트워크는
> 스위치처럼 동작해서 사이드카 컨테이너가 다른 컨테이너의 트래픽을 그냥은 못 본다"는 점이다 —
> 이걸 어떻게 우회하는지가 이 문서의 핵심.

---

## 0. 먼저: Wazuh를 우선순위 낮추는 이유 (솔직한 기술 판단)

Wazuh는 사실상 **호스트 기반 EDR/로그수집 에이전트**다. 우리는 이미 자체 EDR(services/edr/)을
만들어서 프로세스/네트워크 텔레메트리와 행위기반 탐지를 처리하고 있다 — **기능이 상당히
겹친다.** Wazuh를 그대로 얹으면 같은 데이터를 두 번 수집하는 셈이라, 지금 단계에서는
**Suricata/Zeek(네트워크 계층)를 우선**하고 Wazuh는 "나중에 자체 EDR을 대체하거나 보완하고
싶을 때"로 미루는 걸 권한다. 이 문서는 그래도 Wazuh 연동 방법을 남겨두되(3절), 우선순위는
Suricata/Zeek보다 낮게 잡는다.

---

## 1. Docker 네트워크의 근본 문제와 해결책

기본 Linux 브리지(Docker의 기본 네트워크 드라이버)는 **허브가 아니라 스위치**다. MAC 주소
학습을 하기 때문에, 사이드카 컨테이너를 같은 브리지 네트워크에 붙여놓아도 다른 컨테이너의
유니캐스트 트래픽은 안 보인다(브로드캐스트/멀티캐스트만 보임). 실제 스위치의 SPAN/미러 포트가
없다.

**해결책 — `network_mode: "service:<target>"` (네트워크 네임스페이스 공유)**:
센서 컨테이너를 트윈과 **동일한 네트워크 네임스페이스**로 띄우면, 트윈의 `eth0`를 그대로
공유해서 트윈이 주고받는 모든 패킷을 있는 그대로 본다. 미러링이 필요 없다 — Docker가 기본
제공하는 기능만으로 충분하다.

```yaml
# docker-compose.yml에 추가
services:
  gs_suricata:
    image: jasonish/suricata:latest
    network_mode: "service:ground_station"   # 트윈과 동일 netns 공유 -> 트윈의 모든 트래픽을 봄
    cap_add: ["NET_ADMIN", "NET_RAW"]
    volumes:
      - ./siem/suricata/ground_station.yaml:/etc/suricata/suricata.yaml
      - ./siem/suricata/rules:/etc/suricata/rules
      - gs_suricata_logs:/var/log/suricata
    command: ["-i", "eth0"]
    depends_on:
      - ground_station
```
**주의**: `network_mode: service:X`를 쓰면 센서 컨테이너는 자기 자신의 포트를 못 열고(트윈의
네임스페이스를 빌려쓰므로), ports 매핑도 트윈 쪽에서 해야 한다. 이건 "이 트윈 전용 IDS"라는
컨셉과 잘 맞는다(제안서의 "Ground Station SIEM Agent"와 동일한 발상).

**단점**: 트윈-트윈 간 트래픽(예: 없음, 지금 트윈들은 서로 통신 안 함)은 원래도 안 보임 —
문제 없음. DMZ↔트윈 구간의 트래픽만 필요하므로 이 방식으로 충분.

---

## 2. Suricata 연동

### 2.1 배치
- 트윈 3개 각각에 `<asset>_suricata` 사이드카(1절 방식)를 붙인다.
- 룰셋: ET Open 커뮤니티 룰(공개, 라이선스 확인 후 벤더 배포 채널로 받기) + 06번 문서의 커스텀
  룰(`services/siem/detection/rules/*.yaml`을 Suricata 룰 문법으로 별도 변환 — Suricata는
  자체 시그니처 문법을 쓰므로 Sigma 룰과는 별개로 `.rules` 파일 작성 필요).

### 2.2 커스텀 시그니처 예시 (PP-003 커맨드인젝션 대응)
```
# siem/suricata/rules/custom.rules
alert http any any -> any any (msg:"CUSTOM Command Injection Attempt in ping host param";
  content:"host="; http_uri; pcre:"/host=.*[;&|`]/U";
  classtype:web-application-attack; sid:1000001; rev:1;)
```

### 2.3 SIEM 연동
- Suricata의 `eve.json`을 `file_tailer.py`가 tail(22번 문서 1절, 볼륨 마운트로 경로 공유).
- `parsers/suricata.py`(22번 문서 2절)가 이미 이 포맷을 전제로 설계됨 — 추가 작업 없음.

---

## 3. Zeek 연동

### 3.1 배치
동일하게 `network_mode: "service:<twin>"`. Zeek는 conn/dns/http/ssl 로그를 자동 생성.
```yaml
  gs_zeek:
    image: zeek/zeek:latest
    network_mode: "service:ground_station"
    cap_add: ["NET_ADMIN", "NET_RAW"]
    volumes:
      - gs_zeek_logs:/usr/local/zeek/logs
    command: ["zeek", "-i", "eth0", "local"]
```

### 3.2 C2 비콘 탐지 스크립트 (06번 문서 4절을 Zeek 스크립트로 직접 구현하는 옵션)
Zeek 자체 스크립팅 언어로 비콘 탐지를 1차로 걸러내고, 나머지는 SIEM Detection Engine이 conn.log
분석으로 2차 확인(이중화):
```zeek
# siem/zeek/beacon-detect.zeek (선택적, SIEM 쪽 06번 문서 로직과 병행)
event connection_state_remove(c: connection) {
    # 동일 (orig_h, resp_h) 쌍의 연결 간격을 누적, 표준편차/평균 임계 초과 시 notice 발행
}
```
**권장**: Zeek 스크립트보다는 06번 문서에 이미 설계한 SIEM Detection Engine의 시퀀스/임계
로직을 그대로 쓰는 게 유지보수 관점에서 낫다(로직이 한 곳에만 있음). Zeek 스크립트는
"현장에서 더 빠르게 1차 필터링하고 싶을 때"의 선택지 정도로 남겨둔다.

### 3.3 SIEM 연동
- `parsers/zeek.py`(22번 문서 2절)가 conn/dns/http/ssl 로그를 처리하도록 이미 설계됨.
- `file_tailer.py`가 `/usr/local/zeek/logs/current/*.log`를 tail.

---

## 4. Wazuh 연동 (낮은 우선순위, 참고용)

시간이 남거나 자체 EDR을 나중에 Wazuh로 교체/보완하고 싶을 때:

```yaml
  wazuh_manager:
    image: wazuh/wazuh-manager:4.9.0
    networks: [range_control]
    ports: ["1514:1514/udp", "55000:55000"]

  gs_wazuh_agent:
    image: wazuh/wazuh-agent:4.9.0
    network_mode: "service:ground_station"
    environment:
      - WAZUH_MANAGER=wazuh_manager
```
- Wazuh Manager가 생성하는 알림을 `parsers/wazuh.py`(신규, JSON 포맷 파싱)로 SIEM에 흡수하거나,
  아예 Wazuh의 알림을 `blue_detection_success` 이벤트로 직접 Live Fire에 연결(06번 문서 7절과
  동일 패턴)할 수도 있다.
- **자체 EDR과의 역할 분담 제안**: 자체 EDR은 훈련 특화 로직(kill/isolate 액션, 화이트리스트
  안전장치)에 집중하고, Wazuh는 순수 탐지 커버리지 확장용으로만 쓰는 게 중복을 최소화한다.

---

## 5. pfSense 연동

pfSense는 VM(가상 방화벽 OS)이라 Docker 컨테이너로 못 띄운다. 두 가지 선택지:

- **(A) 실제 pfSense VM**: GCP에 별도 VM으로 pfSense를 올리고, DMZ↔트윈 네트워크 경계에 배치.
  syslog를 SIEM의 `ingestion/syslog_server.py`(UDP 514)로 remote syslog 전송 설정.
- **(B) 시뮬레이션(권장, MVP)**: pfSense 없이 `parsers/pfsense.py`가 받을 filterlog CSV 포맷을
  그대로 흉내내는 경량 스크립트(`siem/simulators/pfsense_sim.py`)가 트윈 network 접근 로그 기반
  으로 pass/block 이벤트를 합성해 syslog로 전송. 실제 방화벽 없이도 SIEM 파싱/탐지 로직을
  검증할 수 있다.

**권장**: MVP는 (B)로 시작, 실제 배포 규모가 커지면 (A)로 전환.

---

## 6. 마일스톤

| 마일스톤 | 내용 | 완료 판정 | 상태 |
|---|---|---|---|
| M-Net.1 | ground_station에 Suricata 사이드카(1~2절) | `eve.json`에 실제 트윈 트래픽 alert 발생 | ✅ docker-compose 구성 완료(`network_mode: service:ground_station`), 커스텀 시그니처 5종 작성 |
| M-Net.2 | 나머지 2개 트윈에도 동일 적용 + Zeek 추가 | conn/dns 로그가 SIEM `/search`에서 조회됨 | ✅ 3개 트윈 전부 Suricata+Zeek 사이드카 구성(총 6개), SIEM이 자산별 서브디렉토리(`/var/log/siem/{asset}/`)로 자동 asset 태깅하도록 연동 완료 |
| M-Net.3 | pfSense 시뮬레이터(5절 B안) | filterlog 포맷 이벤트가 SIEM에 파싱됨 | ✅ SIEM의 syslog UDP 수신 + pfsense 파서로 이미 지원(M5.2/M5.3에서 실제 소켓 통신 검증 완료) |
| M-Net.4 (선택) | Wazuh(4절) | 자체 EDR과 역할 분담 문서화 후 도입 여부 결정 | ⬜ 낮은 우선순위 유지(자체 EDR과 기능 중복) |

**구현 요약**: docker-compose에 트윈당 Suricata+Zeek 사이드카 2개씩 총 6개 추가.
`network_mode: "service:<트윈>"`으로 네트워크 네임스페이스를 공유해 미러링 없이 트윈의
실제 트래픽을 그대로 본다. 각 사이드카는 `/var/log/siem/{asset}/` 서브디렉토리에 로그를
남기고(Suricata는 `eve.json`, Zeek는 `conn.log` 등 기본 파일명 그대로 — 서브디렉토리로
자산이 구분되므로 파일명 충돌 없음), SIEM의 `api/main.py`가 이 경로를 자동 tail하며
파싱된 이벤트에 `asset` 필드를 사이드카가 붙어있는 트윈 이름으로 직접 태깅한다(IP→asset
역매핑이 필요 없어짐 — netns 공유 방식의 부가 이점).

## 7. 리소스 영향 (서버 사양 재확인)

Suricata/Zeek 사이드카 6개(트윈 3 × 2)가 실제로 docker-compose에 추가되어 21번 문서의
`e2-standard-8`로는 확실히 빠듯하다. **`e2-standard-16`(16 vCPU/64GB)로 상향을 권장**한다.
