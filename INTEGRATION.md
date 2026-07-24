# 통합 배포 가이드 (cyber-range + cyber-range-contracts)

지금까지 코드가 두 위치에 나뉘어 있다:
- `cyber-range/` — 트윈 3종, Event Collector, Scoring Engine (v1.1 업그레이드 완료)
- `cyber-range-contracts/` — 계약, scenario_engine, patch_console, noc_monitor, **config_service**, **edr**

실제 배포 시에는 17번 문서(저장소 구조)대로 하나의 모노레포로 합치는 것을 권장하지만,
지금 당장 로컬에서 전체를 띄워보려면 아래 방법으로 두 디렉토리를 나란히 두고 실행한다.

## 디렉토리 배치
```
cyber-range-workspace/
├─ cyber-range/            # 압축 해제
└─ cyber-range-contracts/  # 압축 해제
```

## 통합 docker-compose (신규 서비스 연결)

`cyber-range/docker-compose.yml`에 아래 서비스를 추가한다(각 빌드 컨텍스트가 다른 디렉토리를
가리키는 점에 주의):

```yaml
  config_service:
    build:
      context: ../cyber-range-contracts
      dockerfile: services/config_service/Dockerfile
    container_name: config_service
    ports:
      - "8030:8030"
    environment:
      - INSTRUCTOR_TOKEN=${INSTRUCTOR_TOKEN:-dev-instructor-token}
    networks:
      - range_control

  edr_backend:
    build:
      context: ../cyber-range-contracts
      dockerfile: services/edr/Dockerfile
    container_name: edr_backend
    ports:
      - "8080:8080"
    environment:
      - CONFIG_SERVICE_URL=http://config_service:8030
      - INSTRUCTOR_TOKEN=${INSTRUCTOR_TOKEN:-dev-instructor-token}
    depends_on:
      - config_service
    networks:
      - range_control
```

그리고 각 트윈 서비스(`ground_station` 등)의 `environment`에 다음을 추가한다:
```yaml
      - CONFIG_SERVICE_URL=http://config_service:8030
      - EDR_BACKEND_URL=http://edr_backend:8080
```

## 실행 순서

```bash
cd cyber-range
docker compose up --build
```

기동 후:
1. `curl http://localhost:8030/config/patches?asset=ground_station` — 전부 비어있음(초기 상태, 아직
   아무도 토글 안 함 → 트윈은 환경변수 폴백으로 기존처럼 vulnerable 동작).
2. `curl -X POST http://localhost:8030/instructor/patch/toggle -H "Authorization: Bearer dev-instructor-token" -H "Content-Type: application/json" -d '{"asset":"ground_station","vuln_id":"GS-001","patched":true,"reason":"test"}'`
   — 5초 이내에 트윈이 폴링해 실제로 patched 동작으로 전환됨(재기동 없음).
3. `curl http://localhost:8080/edr/hosts` — ground_station이 online으로 잡히는지 확인(psutil 설치
   여부에 따라 process_count가 0일 수 있음 — 컨테이너 권한에 따라 제한될 수 있으므로 실제 배포 시
   `pid: host` 네임스페이스 공유 여부를 검토).

## 알려진 제약 (다음 단계에서 정리 필요)

- **디렉토리 통합 미완**: 지금은 두 리포로 나뉘어 있어 위처럼 상대경로 context를 써야 한다.
  17번 문서 구조대로 `services/`, `shared/` 등을 하나의 리포로 합치는 리팩터링이 필요.
- **psutil 컨테이너 권한**: 컨테이너 내부 프로세스만 보이므로(호스트 전체 아님) Falcon처럼
  호스트 전체를 보는 건 아니고 "이 컨테이너 안"으로 범위가 제한된다 — 훈련 목적엔 충분하지만
  문서화가 필요한 차이점.
- **Kill Process는 실제 종료까지 구현·검증 완료**: EDR Agent가 kill_commands 큐를 폴링해
  `psutil.Process.terminate()`(SIGTERM) → 3초 내 미종료 시 `.kill()`(SIGKILL)로 실제 종료한다.
  실제 자식 프로세스와 SIGTERM 무시 프로세스 양쪽 시나리오로 종료/승격 경로를 실행 검증했다.
