# FOR-002 Writeup

**공격 체인**: 포트스캔 → SQLi(UNION) → 응답 본문에 base64로 은닉된 데이터 유출.
**분석 포인트**: syn_scan 패킷들의 공통 src_ip, http_request의 URL 패턴(UNION 키워드로
ATT&CK 기술 특정), http_response의 base64 필드 디코딩.
**교훈**: 실제 포렌식에서도 "누가, 어디를, 무엇으로, 어떻게"를 각각 다른 로그 소스에서
교차 확인해야 한다 — 하나의 로그만 보면 전체 그림이 안 보인다.
