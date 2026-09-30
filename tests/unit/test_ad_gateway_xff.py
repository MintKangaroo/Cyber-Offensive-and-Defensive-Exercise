"""S-9 회귀: A/D 타깃 게이트웨이가 X-Forwarded-For 를 주입하는지 검증.

원 결함(audit/99_final.md S-9): infra/match/ad_target_gateway.conf 가 Host 헤더만 설정하고
X-Forwarded-For 를 붙이지 않아, 팀 취약 서비스의 SIEM access 로그에서 모든 공격 출발지 IP 가
게이트웨이 IP 하나로 뭉개졌다 → 팀 귀속(어느 팀이 공격했는지) 불가.

이 테스트는 게이트웨이가 프록시하는 모든 location 이 X-Forwarded-For 를 실제 클라이언트
주소로 설정하는지를 nginx conf 정적 파싱으로 고정한다(도커 불필요).
"""
import re
from pathlib import Path

CONF = Path(__file__).resolve().parents[2] / "infra" / "match" / "ad_target_gateway.conf"


def _proxy_locations(text: str) -> list[str]:
    # proxy_pass 를 포함한 location 블록(= 실제 업스트림으로 트래픽을 넘기는 지점)만 추린다.
    return [ln for ln in text.splitlines() if "proxy_pass" in ln]


def test_every_proxy_location_sets_xff():
    text = CONF.read_text(encoding="utf-8")
    locations = _proxy_locations(text)
    assert locations, "게이트웨이 conf 에서 proxy_pass location 을 찾지 못했다"
    # 팀 서비스 9종(notes/vault/grid × 3팀) 모두 프록시되어야 한다.
    assert len(locations) == 9, f"예상 9개 팀 서비스 location, 실제 {len(locations)}개"
    for ln in locations:
        assert "X-Forwarded-For" in ln, f"XFF 미주입 location: {ln.strip()}"
        # 실제 원격 주소를 실어야 한다(게이트웨이 자신 IP 가 아니라).
        assert re.search(r"X-Forwarded-For\s+\$(remote_addr|proxy_add_x_forwarded_for)", ln), (
            f"XFF 가 실 클라이언트 주소가 아님: {ln.strip()}"
        )


def test_management_port_still_not_proxied():
    # 회귀 방지: XFF 추가가 관리 포트(9001) 노출로 이어지지 않았는지 확인.
    # 코멘트 언급은 무시하고, 실제 listen/proxy_pass 지시자만 검사한다.
    text = CONF.read_text(encoding="utf-8")
    directives = [ln.strip() for ln in text.splitlines() if not ln.strip().startswith("#")]
    for ln in directives:
        assert "listen 9001" not in ln, f"관리 포트 9001 을 listen 하면 안 된다: {ln}"
        assert ":9001" not in ln, f"관리 포트 9001 로 프록시하면 안 된다: {ln}"
