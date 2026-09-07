# WEB-014 방어 — XXE 차단

## 취약점
리포트 XML 파서가 외부 엔티티(external entity)를 해석해(resolve_entities/load_dtd), DTD 에
`<!ENTITY xxe SYSTEM "file:///app/flag.txt">` 를 심으면 서버 로컬 파일이 응답으로 반영된다(XXE).

## 패치 (`PATCH_WEB_014=true`)
- 파서에서 엔티티 해석·DTD 로드·네트워크를 끈다: `resolve_entities=False, load_dtd=False, no_network=True`.
- 가능하면 `defusedxml` 사용. XML 대신 JSON 스키마로 전환하면 근본 차단.

## 탐지 관점(blue)
- 업로드 XML 에 DOCTYPE/ENTITY/SYSTEM·file:// 스킴이 포함된 요청 경보.
