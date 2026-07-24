# DET-003 방어 노트 (Blue)

## 목표
웹쉘 킬체인 — 같은 출발지가 `.php`를 업로드한 뒤 그 `.php`를 실행하는 **순서**를 탐지한다.
단일 이벤트 매칭으로는 잡기 어렵고(업로드만/실행만은 정상일 수 있음), 두 단계의 연결이 핵심이다.

## 정답 규칙(개념)
`src.ip`를 그룹 키로 하는 sequence 규칙:
```yaml
kind: sequence
sequence_group_by: "src.ip"
sequence_within_sec: 300
sequence_steps:
  - raw.file: "~.php"    # 1) .php 업로드
  - raw.uri:  "~.php"    # 2) 같은 IP가 .php 실행
```
- 정상 이미지 업로드(`.jpg`)는 step1에 걸리지 않고, 업로드 이력 없는 `.php` 요청은 step1이
  선행되지 않아 시퀀스가 완성되지 않는다 → 오탐 없음.

## 실무 확장
- 업로드 디렉토리 실행 권한 제거, 확장자/콘텐츠 검증, WAF의 업로드 정책과 결합.
- 시퀀스에 "짧은 시간 창" + "동일 파일명 상관"을 더하면 정밀도가 높아진다.
