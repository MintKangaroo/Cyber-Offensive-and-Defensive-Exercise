# DET-002 방어 노트 (Blue)

## 목표
웹 접근 로그에서 UNION 기반 SQL 인젝션을 탐지하되, 'union'/'select' 단어가 우연히 들어간
정상 검색어에는 오탐을 내지 않는 규칙을 만든다.

## 정답 규칙(개념)
`raw.uri` 필드에 대해 공격 특유의 연속 토큰 `UNION SELECT`(대문자, 공백 포함)를 부분 매칭한다.
단순히 `union` 또는 `select` 단독을 매칭하면 `"how to select a union credit card"` 같은 정상
검색어에서 오탐이 난다 — 그래서 두 키워드가 **붙어있는** SQLi 특유의 패턴을 노린다.

```yaml
- id: DET-002
  kind: match
  source_type: twin
  match:
    raw.uri: "~UNION SELECT"
```

## 실무 확장
- 대소문자/인코딩 우회(`uNiOn`, `%20`, 주석 삽입)까지 잡으려면 정규화(normalization) 후 정규식
  탐지가 필요하다. 이 문제는 튜닝의 출발점(정확한 시그니처 vs 과탐)을 익히는 데 목적이 있다.
- 근본 대응은 파라미터 바인딩(Prepared Statement)과 WAF 규칙이다.
