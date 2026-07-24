# infra/hardening — 컨테이너 하드닝 가이드

## 리소스/권한 하드닝 (docker-compose.hardening.yml)

`cap_drop: ALL` + `read_only` + `no-new-privileges` + `pids_limit`/`ulimits` +
`mem_limit`/`cpus`를 적용. 커맨드인젝션(PP-003)·역직렬화(PP-004)를 가진
`power_plant`가 가장 강한 제약을 받는다.

적용:
```bash
docker compose -f docker-compose.yml -f infra/hardening/docker-compose.hardening.yml up --build
```

## seccomp 커스텀 프로파일 생성 (직접 작성하지 말 것)

seccomp JSON은 수백 개 syscall 항목을 가진 파일이라 손으로 작성하면 오타 하나로
컨테이너가 아예 뜨지 않는다. 아래 **검증된 절차**로만 생성한다.

1. Docker 공식 기본 프로파일을 받는다(신뢰된 출처):
   ```bash
   curl -o default-seccomp.json \
     https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json
   ```
2. 이 훈련 환경에서 불필요하고 위험도가 높은 syscall만 `syscalls` 배열에서 제거한다
   (예: `ptrace`, `mount`, `umount2`, `reboot`, `swapon`, `init_module`, `delete_module`,
   `kexec_load`, `unshare`(컨테이너 탈출 관련 네임스페이스 조작)).
   **제거만 하고 추가는 하지 않는다** — 알 수 없는 syscall을 허용하면 오히려 위험.
3. `docker run --rm --security-opt seccomp=./default-seccomp.json <image> echo ok`
   로 정상 기동을 먼저 확인한 뒤 저장.
4. 최종 파일을 `infra/hardening/seccomp-restrictive.json`으로 저장하고,
   `docker-compose.hardening.yml`의 주석 처리된 줄을 활성화한다.

**검증 없이 배포 금지**: 위 3번 스모크 테스트를 통과하지 못한 프로파일은 사용하지 않는다.

## 리소스 상한 근거

- `mem_limit: 512m` — 트윈은 소형 FastAPI 앱이라 512MB면 충분. 초과 시 OOM kill로
  DoS성 공격이 호스트 전체를 못 건드리게.
- `pids_limit: 64` (power_plant) — 커맨드 인젝션으로 fork bomb류 시도가 있어도
  프로세스 수 상한으로 피해 최소화.
- `cpus: 0.5` — 팀별/문제별 동시 배포 시 한 컨테이너가 CPU를 독식하지 못하게.

## 다른 챌린지(challenges/) 적용

`hardened` safety profile이 지정된 문제(AI/Pwn/OT/역직렬화류)는 이 오버레이와
동일한 원칙(cap_drop ALL, read_only, 리소스 상한)을 각 문제의
`deploy/docker-compose.yaml`에 개별 적용한다. 11번 출제표준의 C-QA `safety_scan`
단계가 이 적용 여부를 확인한다.
