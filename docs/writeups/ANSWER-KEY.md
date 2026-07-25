# 답지 (Answer Key) — 전체 챌린지 풀이 요약

> ⚠️ **교관/운영진 전용.** 참가자에게 배포 금지. 팀별 HMAC 동적 플래그라 값은 팀마다 다릅니다.

> 총 69개 챌린지. 각 항목: 목표 + 의도된 해법 개요. 상세는 각 챌린지 폴더의 `writeup.md` 참조.


## 🌐 Web

### WEB-000 — 노출된 디버그 설정  `easy` · red 50pt · service
- **목표**: /api/debug/config 접근해 노출된 JWT 시크릿 확보

### WEB-001 — 네트워크 진단 명령 주입  `medium` · red 150pt · service
- **목표**: /api/net/ping?host= 에 명령을 주입해 /app/flag.txt 읽기

### WEB-002 — 위조된 지휘권 - JWT Forgery  `medium` · red 150pt · service
- **목표**: admin 권한이 필요한 POST /api/mission/approve 를 위조 토큰으로 호출해 승인 코드 획득

### WEB-003 — 열람 권한 없음 - Mission Plan IDOR  `medium` · red 120pt · service
- **목표**: 본인 소유가 아닌 기밀 임무계획(TOP SECRET)에 IDOR로 접근해 승인 코드를 획득

### WEB-004 — 파일 다운로드 경로 순회  `medium` · red 120pt · service
- **목표**: /api/files/download?name=../flag.txt 로 경로 순회해 플래그 획득

### WEB-007 — 그림인 척 - Upload Filter Bypass  `medium` · red 150pt · service
- **목표**: 이미지 전용이라는 업로드 필터를 우회해 서버측 스크립트 확장자(.py 등) 파일을 업로드하고 승인 코드를 획득

### WEB-005 — 복원의 대가 - Historian Deserialization RCE  `hard` · red 250pt · service
- **목표**: POST /api/historian/import 에 악성 직렬화 페이로드를 보내 원격 코드 실행으로 플래그 파일을 읽어라

### WEB-009 — WAF 우회 + 블라인드 SQL 인젝션  `insane` · red 300pt · service
- **목표**: WAF를 우회한 블라인드 불리언 SQLi로 secrets.token(flag) 추출


## 📡 Network

### NET-000 — 평문 프로토콜 스니핑  `easy` · red 50pt · artifact
- **목표**: capture_log.jsonl에서 평문 텔넷 로그인 자격증명 추출

### NET-004 — ARP 스푸핑 탐지 - 중간자 공격 추적  `easy` · red 50pt · artifact
- **목표**: 한 IP를 주장하는 두 MAC을 찾아 attacker_mac / spoofed_ip / attack_technique 제출

### NET-001 — DNS 터널링 분석 - 은닉 채널 유출 복원  `medium` · red 60pt · artifact
- **목표**: C2 도메인과 hex 인코딩되어 유출된 비밀, 사용된 ATT&CK 기법을 제출

### NET-002 — 경계를 넘어 - Lateral Pivot  `medium` · red 150pt · artifact
- **목표**: network_map.json의 방화벽 규칙을 지키며 DMZ -> internal_db 경로 도출

### NET-003 — C2 비콘 간격 분석  `medium` · red 55pt · artifact
- **목표**: 규칙적 비콘을 식별해 c2_ip / beacon_interval_sec / implant_id 제출

### NET-005 — 포트 노킹 시퀀스 복원  `medium` · red 50pt · artifact
- **목표**: 보호 포트 접속 직전의 노킹 시퀀스를 찾아 attacker_ip / knock_sequence / protected_port 제출

### NET-006 — TCP 세그먼트 재조립 - 분할 유출 복원  `medium` · red 50pt · artifact
- **목표**: 공격자 흐름을 seq로 재조립해 attacker_ip / reassembled_secret / attack_technique 제출

### NET-007 — 다중 홉 피벗 체인 상관 추적  `hard` · red 180pt · artifact
- **목표**: 피벗 체인 복원 → 진입 IP 식별 → 최종 홉 토큰을 진입 IP로 XOR 복호 → flag
- **해법**: 의도된 해법 1. **진입 시드**: src가 외부 대역(203.0.113.x)인 플로우를 진입점으로 잡는다. 2. **홉 그래프 상관 확장**: 현재 홉의 dst를 src로 갖고, 시각이 수십 ms 뒤이며(0<Δt<0.2s),    바이트가 거의 보존된(±80) 다음 플로우를 그리디로 이어 붙여 DC(10.4.0.10) 도달까지 체인을 복원.    → 시각이 벌어진 미끼/무관 트래픽은 상관 조건에서 탈락. 3. **토큰 복호**: 최종 홉(dst=DC) note(base64)를 디코드 → 진입 IP로 반복 XOR → `flag{pivot_chain_<hmac12>}`.

### NET-009 — OT 사보타주 트레이스 재구성 (Modbus)  `insane` · red 300pt · artifact
- **목표**: rogue_ip / covert_register / flag 를 재구성해 제출


## 🔬 Forensics

### FOR-000 — 평문 자격증명 카빙  `easy` · red 50pt · artifact
- **목표**: backup_config.txt에서 서비스 계정과 비밀번호를 찾아 제출

### FOR-001 — 명령 이력 포렌식 - 데이터 유출 추적  `easy` · red 50pt · artifact
- **목표**: 유출 명령을 찾아 exfil_host와 디코드된 비밀, 사용된 ATT&CK 기법을 제출

### FOR-004 — 이메일 헤더 포렌식 - 피싱 발신지 추적  `easy` · red 50pt · artifact
- **목표**: Received 체인을 분석해 originating_ip / spoofed_from / verification_token 제출

### FOR-005 — 메모리 덤프 문자열 분석 - 자격증명 복구  `easy` · red 50pt · artifact
- **목표**: 메모리 문자열에서 leaked_credential / source_process 복원

### FOR-006 — 지속성 흔적 분석 - 악성 스케줄 작업  `easy` · red 50pt · artifact
- **목표**: 악성 cron 항목을 찾아 malicious_schedule / c2_host / implant_token 제출

### FOR-002 — 침묵하는 지상국 - 침해 재구성  `medium` · red 200pt · artifact
- **목표**: capture_log.jsonl을 분석해 4개 항목 특정

### FOR-003 — 세션 하이재킹 흔적 - 접근 로그 조사  `medium` · red 55pt · artifact
- **목표**: 여러 IP에서 재사용된 세션을 찾아 attacker_ip/session_id/sensitive_action 제출

### FOR-007 — 인메모리 인젝션 탐지 - 프로세스 할로잉  `hard` · red 180pt · artifact
- **목표**: 할로잉된 프로세스 식별 → private+RX 영역의 은닉 스테이저 추출 → XOR 복호로 flag
- **해법**: 의도된 해법 1. **이상 영역 correlate**: 모든 프로세스의 영역을 훑어 `type=private` 이면서 `protect=RX`인    영역(W^X 위반, 익명 실행 메모리 = 주입 코드)을 가진 프로세스를 찾는다. 정상은 실행권한이    image 타입에만 붙는다. 2. **스테이저 추출**: 그 영역의 `data`(base64)를 디코드 → `XORKEY=<k>\nPAYLOAD=<hex>`. 3. **복호**: PAYLOAD(hex)를 XORKEY로 반복 XOR → `flag{process_hollowing_<hmac12>}`.

### FOR-009 — 안티포렌식 다단계 (타임스톰프 → 은닉채널 → 복호)  `insane` · red 300pt · artifact
- **목표**: 타임스톰프 파일 → 은닉채널 CHID → XOR 복호로 flag{...} 도출


## ⚙️ Reversing

### REV-000 — 가려진 신호 - XOR Decode  `easy` · red 100pt · artifact
- **목표**: 제공된 encoded.bin에서 단일바이트 XOR 키를 찾아 플래그 복원

### REV-001 — 난독화된 라이선스 체크  `medium` · red 150pt · service
- **목표**: checker.py의 검증 알고리즘을 분석해 팀 전용 유효 시리얼 도출

### REV-002 — 반복키 XOR 복원  `medium` · red 120pt · artifact
- **목표**: encoded.bin을 디코드해 flag{...} 복원

### REV-003 — 다단계 인코딩 복원  `medium` · red 130pt · artifact
- **목표**: encoded.txt의 3계층을 해제해 flag{...} 복원

### REV-006 — 비트 회전 사이퍼 복호화  `medium` · red 130pt · artifact
- **목표**: R/K를 복원해 flag{...} 복원

### REV-004 — 스택 VM 리버싱  `hard` · red 140pt · artifact
- **목표**: VM 바이트코드를 실행해 flag{...} 복원

### REV-005 — LCG 스트림 사이퍼 복호화  `hard` · red 130pt · artifact
- **목표**: seed + LCG 키스트림을 재현해 flag{...} 복원

### REV-009 — 커스텀 VM 난독화 (핸들러 테이블)  `insane` · red 300pt · artifact
- **목표**: 핸들러 테이블을 복원하고 VM을 구현해 flag{...} 도출


## 🏭 ICS/OT

### ICS-001 — OPC UA 익명 태그 열람 - Anonymous Read  `easy` · red 70pt · service
- **목표**: 노드 브라우즈로 진단 노드(ns=4;s=Diag.Maint_*)를 찾아 익명 읽기 → 플래그
- **해법**: 의도된 해법 1. `GET /opcua/browse` → 주소공간 열거, 진단 노드 `ns=4;s=Diag.Maint_<hmac8>` 발견. 2. `GET /opcua/read?node=<진단노드>` → 익명 세션으로 읽어 `flag{opcua_anon_read_<hmac12>}` 획득.

### ICS-000 — 안전 인터록 우회 - Modbus Safety Interlock  `medium` · red 120pt · service
- **목표**: 노출된 SAFETY_KEY로 SAFETY_INTERLOCK(40001)=0 쓰기 → 서버 플래그 획득
- **해법**: 의도된 해법 1. `GET /modbus/registers` → 40100(SAFETY_KEY) 값 추출(정보 노출 취약점). 2. `POST /modbus/write {addr:40001, value:0, key:<SAFETY_KEY>}` → 인터록 해제 → 서버가    `flag{modbus_interlock_bypass_<hmac12>}` 발급.

### ICS-002 — Modbus 사보타주 분석 - 안전 레지스터 무단 쓰기  `medium` · red 120pt · artifact
- **목표**: 안전 레지스터 무단 write의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `modbus_traffic.jsonl` 파싱 → func∈{5,6,16}(write)이고 addr=40001(안전 레지스터)이며 src≠HMI(10.20.0.5)인    레코드를 찾는다 = 무단 마스터. 2. 그 src가 공격자 IP. 레코드 note(base64)를 공격자 IP로 반복 XOR → `flag{modbus_sabotage_<hmac12>}`.

### ICS-003 — DNP3 무단 제어 명령 탐지 - Unsolicited Control  `medium` · red 120pt · artifact
- **목표**: 보호 제어점 무단 OPERATE의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `dnp3_log.jsonl` 파싱 → func∈{4,5}(OPERATE/DIRECT_OPERATE)이고 point=7(보호 차단기)이며    src≠정상 마스터(10.30.0.4)인 레코드 = 무단 마스터. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{dnp3_unsolicited_control_<hmac12>}`.

### ICS-004 — IEC 104 ASDU 조작 추적 - Command Injection  `medium` · red 120pt · artifact
- **목표**: 보호 IOA 무단 제어 ASDU의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `iec104_log.jsonl` 파싱 → asdu_type∈{45..51}(제어)이고 ioa=7(보호 차단기)이며    src≠정상 마스터(10.40.0.3)인 레코드 = 무단 제어국. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{iec104_command_injection_<hmac12>}`.

### ICS-005 — Profinet DCP 스푸핑 분석 - Station Identity Spoof  `medium` · red 120pt · artifact
- **목표**: 스테이션 신원 스푸핑(DCP-Set)의 공격자 MAC 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `profinet_dcp.jsonl` 파싱 → station_name=plc-line-a 이고 dcp_service에 "Set" 포함이며    src_mac≠정상 MAC(00:0e:cf:11:22:33)인 레코드 = 신원 스푸핑. 2. 그 src_mac이 공격자 MAC. note(base64)를 공격자 MAC으로 XOR → `flag{profinet_dcp_spoof_<hmac12>}`.

### ICS-007 — HART 명령 주입 분석 - Transmitter Range Tamper  `medium` · red 120pt · artifact
- **목표**: 안전 트랜스미터 무단 HART write의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `hart_traffic.jsonl` 파싱 → hart_cmd∈{34,35,45,46}(write)이고 tag=PT-101(안전 트랜스미터)이며    src≠정상 AMS(10.60.0.5)인 레코드 = 무단 마스터. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{hart_command_injection_<hmac12>}`.

### ICS-008 — BACnet 무단 WriteProperty 분석 - Priority Override  `medium` · red 120pt · artifact
- **목표**: 냉방 객체에 대한 무단 BACnet WriteProperty의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `bacnet_traffic.jsonl` 파싱 → bacnet_service=15(WriteProperty)이고 object_type=analog-output    (CRAC 냉방 setpoint)이며 src≠정상 BMS(10.70.0.10)인 레코드 = 무단 장치. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{bacnet_priority_override_<hmac12>}`.

### ICS-012 — MQTT Sparkplug B 무단 액추에이터 명령 분석 - DCMD Injection  `medium` · red 120pt · artifact
- **목표**: 펌프 액추에이터 MQTT DCMD의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `mqtt_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.90.0.5) 아님 = 무단 프레임. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.

### ICS-006 — IEC 61850 GOOSE 위조 분석 - Spoofed Trip  `hard` · red 130pt · artifact
- **목표**: 스푸핑된 트립 GOOSE의 공격자 MAC 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `goose_messages.jsonl` 파싱 → gocbRef=보호 트립 gcb 이고 dataset에 "true"(CB_Trip)이며    src_mac≠정상 IED(00:21:c1:aa:bb:cc)인 레코드 = 스푸핑된 트립 GOOSE(비정상 stNum 급증 동반). 2. 그 src_mac이 공격자 MAC. note(base64)를 공격자 MAC으로 XOR → `flag{iec61850_goose_spoof_<hmac12>}`.

### ICS-009 — Foundation Fieldbus 블록 MODE 조작 분석 - PID OOS Sabotage  `hard` · red 140pt · artifact
- **목표**: PID 블록 MODE_BLK O/S write의 공격자 FF 링크주소 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `ff_h1_traffic.jsonl` 파싱 → block=FIC-201(안전 PID)이고 param=MODE_BLK, op=write, value=OOS이며    src_addr∉{0x10 LAS, 0x11 DCS}인 프레임 = 무단 호스트. 2. 그 src_addr가 공격자 FF 링크주소. note(base64)를 공격자 주소로 XOR    → `flag{ff_mode_blk_oos_sabotage_<hmac12>}`.

### ICS-010 — EtherNet/IP CIP 무단 제어 분석 - Safety Assembly Tamper  `hard` · red 140pt · artifact
- **목표**: 안전 어셈블리 CIP SetAttribute write의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `enip_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.80.0.5) 아님 = 무단 프레임. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.

### ICS-011 — S7comm 안전 DB 무단 쓰기 분석 - Safety DB Write  `hard` · red 140pt · artifact
- **목표**: 안전 DB(62) S7 WRITE_VAR의 공격자 IP 식별 → note 토큰 XOR 복호 → flag
- **해법**: 의도된 해법 1. `s7_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.85.0.5) 아님 = 무단 프레임. 2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.


## 🛡️ Detection(Blue)

### DET-000 — 첫 브루트포스 룰  `easy` · blue 60pt · detection
- **목표**: 동일 src의 401 연속 10회/60초를 잡는 threshold 룰 작성(우리 Detection Engine 문법)

### DET-002 — 웹 로그에서 SQL 인젝션 탐지  `easy` · blue 80pt · detection
- **목표**: raw.uri에 대한 match 규칙 작성(UNION SELECT 시그니처)

### DET-001 — 잡음 속의 스캔 - Threshold Tuning  `medium` · blue 100pt · detection
- **목표**: distinct(dst.port) 임계 룰 작성 + 임계값 튜닝

### DET-003 — 웹쉘 킬체인 탐지 - 업로드 후 실행 시퀀스  `medium` · blue 90pt · detection
- **목표**: src.ip 기준 sequence 규칙 작성(.php 업로드 → .php 실행)

### DET-005 — Log4Shell(JNDI) 인젝션 탐지  `medium` · blue 80pt · detection
- **목표**: 여러 필드에 대한 ${jndi: match 규칙 작성

### DET-006 — DNS DGA 탐지 - 대량 도메인 조회  `medium` · blue 90pt · detection
- **목표**: src.ip 기준 distinct(raw.query) 임계 규칙 작성 + 임계 튜닝

### DET-007 — BACnet 무단 WriteProperty(냉방 오버라이드) 탐지  `medium` · blue 80pt · detection
- **목표**: bacnet_service=15 AND object_type=analog-output 동시 매칭 규칙 작성
- **해법**: 의도된 규칙 `bacnet_service=15`(WriteProperty) **AND** `object_type=analog-output`(냉방 제어) 을 AND 결합한 match 규칙. attack_log(냉방 write 2건)에 알림, normal_log(read/조명 write)에는 무오탐.

### DET-010 — EtherNet/IP CIP 안전 어셈블리 무단 SetAttribute 탐지  `medium` · blue 80pt · detection
- **목표**: cip_service=16(SetAttributeSingle) AND cip_class=4 AND cip_instance=101 동시 매칭
- **해법**: 의도된 규칙 cip_service=16(SetAttributeSingle) AND cip_class=4 AND cip_instance=101 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

### DET-011 — S7comm 안전 DB(62) 무단 WRITE_VAR 탐지  `medium` · blue 80pt · detection
- **목표**: s7_function=WRITE_VAR AND area=DB AND db_number=62 동시 매칭
- **해법**: 의도된 규칙 s7_function=WRITE_VAR AND area=DB AND db_number=62 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

### DET-012 — MQTT Sparkplug B 무단 액추에이터 DCMD 탐지  `medium` · blue 80pt · detection
- **목표**: message_type=DCMD AND metric~Pump/Control 동시 매칭
- **해법**: 의도된 규칙 message_type=DCMD AND metric~Pump/Control 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

### DET-004 — C2 비콘 주기성 탐지  `hard` · blue 90pt · detection
- **목표**: (src,dst) 주기성 규칙 작성 + 정상 폴링 목적지 allowlist 튜닝

### DET-008 — Foundation Fieldbus MODE_BLK O/S(제어루프 정지) 탐지  `hard` · blue 90pt · detection
- **목표**: param=MODE_BLK AND op=write AND value=OOS 동시 매칭 규칙 작성
- **해법**: 의도된 규칙 `param=MODE_BLK` **AND** `op=write` **AND** `value=OOS` 세 조건을 AND 결합한 match 규칙. attack_log(MODE_BLK=OOS write 2건)에 알림, normal_log(SP write / MODE_BLK=AUTO·MAN 전환 / MODE_BLK read)에는 무오탐. O/S 값이 정지(사보타주)와 정상 모드전환을 가르는 핵심 판별자.

### DET-009 — APT Low-and-Slow 비콘 헌팅 (노이즈 90%)  `insane` · blue 200pt · detection
- **목표**: low-and-slow 비콘용 periodicity 규칙 작성(window 확장 + 관측수/지터 튜닝 + 다중 allowlist)


## 🤖 AI Security

### AI-000 — 특징공간 회피 - Feature-Space Evasion  `easy` · red 60pt · service
- **목표**: 제공된 악성 샘플의 특징벡터를 조작해 malicious_score < 0.5로 만들기

### AI-002 — 프롬프트 인젝션 흔적 분석  `easy` · red 60pt · artifact
- **목표**: 인젝션 턴과 노출된 키를 찾아 leaked_secret / injection_technique 제출

### AI-005 — 모델 추출 API 남용 탐지  `easy` · red 50pt · artifact
- **목표**: 쿼리 수가 압도적인 클라이언트를 찾아 abusive_client / leaked_api_key / query_count 제출

### AI-001 — 그림자 모델 - Model Extraction  `medium` · red 150pt · service
- **목표**: 쿼리 예산 500회 이내로 대리모델을 학습시켜 원본과 90% 이상 일치하는 결정 경계 확보

### AI-003 — 데이터 포이즈닝 흔적 분석 - 백도어 트리거  `medium` · red 55pt · artifact
- **목표**: 포이즈닝 샘플을 찾아 injected_source / trigger_token / poisoned_label 제출

### AI-004 — RAG 간접 프롬프트 인젝션 흔적  `medium` · red 55pt · artifact
- **목표**: 검색 문서 중 인젝션 지시를 담은 문서를 찾아 poisoned_doc_source / leaked_secret / injection_type 제출

### AI-006 — 훈련 데이터 memorization 유출  `medium` · red 55pt · artifact
- **목표**: completion에 학습 비밀이 노출된 항목을 찾아 trigger_prompt / leaked_secret / attack_technique 제출

### AI-007 — 예산 제약 적대적 회피 - PGD Evasion  `hard` · red 220pt · service
- **목표**: 예산 ||x - x0||_inf <= epsilon 안에서 benign 오분류를 만들어 서버 플래그 획득
- **해법**: 의도된 해법 1. `/model`에서 W1,b1,W2,b2를, `/source`에서 x0·epsilon을 받아 MLP를 numpy로 재구성. 2. malware 로짓 − benign 로짓의 입력 그래디언트를 ReLU 마스크를 반영해 계산. 3. `x ← x − lr·sign(grad)` 스텝마다 **x0±epsilon 볼**과 **[0,1] 박스**로 사영(PGD). 4. benign으로 넘어가면 `/classify`에 제출 → 서버가 `flag{pgd_evasion_<hmac12>}` 발급.

### AI-009 — 적대적 회피 인시던트 재구성 (전이공격 분석)  `insane` · red 300pt · artifact
- **목표**: 회피 쿼리 id / 섭동 특징 인덱스 / flag 재구성
