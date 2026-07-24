# Zeek local.zeek (트윈 사이드카용)
# 기본 로그(conn/dns/http/ssl/notice)만 활성화. 06번 문서 4절의 C2 비콘 로직은
# SIEM Detection Engine(periodicity kind)에서 처리하므로 여기서는 표준 로그만 남긴다.

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

redef LogAscii::use_json = F;   # SIEM 파서(zeek.py)는 탭 구분 ascii 포맷을 전제로 함
