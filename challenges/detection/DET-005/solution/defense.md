# DET-005 방어 노트 (Blue)

## 목표
Log4Shell(CVE-2021-44228) 공격 페이로드 `${jndi:ldap://...}`를 탐지한다. 페이로드는
User-Agent, URI, 기타 헤더 등 로그로 남는 여러 필드로 들어올 수 있다.

## 정답 규칙(개념)
여러 필드 각각에 대해 `${jndi:` 부분 매칭 규칙을 둔다.
```yaml
- kind: match
  match: { raw.user_agent: "~${jndi:" }
- kind: match
  match: { raw.uri: "~${jndi:" }
```
- 'jndi'/'${' 단독은 정상 문자열에도 나오므로, 공격 특유의 `${jndi:` **연속 토큰**을 노려 오탐을 줄인다.

## 실무 확장
- 실제 페이로드는 난독화(`${${lower:j}ndi:}`, base64 등) 우회가 많아 정규화 후 탐지가 필요하다.
- 근본 대응은 취약 log4j 업그레이드/`log4j2.formatMsgNoLookups=true` + egress 차단(콜백 방지).
