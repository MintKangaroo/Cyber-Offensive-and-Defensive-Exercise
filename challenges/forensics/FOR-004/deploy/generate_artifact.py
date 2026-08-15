"""FOR-004 아티팩트 생성기 - 피싱 이메일의 원본 헤더(email_headers.txt).

From은 임원을 사칭하지만 Received 체인의 최초 홉(맨 아래)이 공격자의 실제 발신 IP를 드러낸다.
피싱 링크에는 팀별 동적 verification token이 실려 있다. 조사자는 Received 체인을 읽고
발신 IP·사칭 발신자·링크의 토큰을 복원해야 한다.
"""
import hashlib
import hmac
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
ORIGIN_IP = "198.51.100.77"
SPOOFED_FROM = "ceo@bigcorp.example"


def dynamic_token(team_id: str) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"FOR-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]


def build_headers(team_id: str) -> str:
    token = dynamic_token(team_id)
    # Received 체인: 위(최근 홉) -> 아래(최초 발신). 최초 발신 홉이 공격자 IP.
    return "\n".join([
        'Return-Path: <attacker@evil-mailer.example>',
        f'From: "CEO" <{SPOOFED_FROM}>',
        'Reply-To: finance-verify@evil-mailer.example',
        'Subject: [URGENT] Wire transfer approval needed',
        'Received: from mx.bigcorp.example (mx.bigcorp.example [203.0.113.10])',
        '        by inbox.bigcorp.example with ESMTP; Tue, 2 Jul 2024 09:12:44 +0000',
        'Received: from relay.cheap-smtp.example (relay.cheap-smtp.example [192.0.2.55])',
        '        by mx.bigcorp.example with ESMTP; Tue, 2 Jul 2024 09:12:40 +0000',
        f'Received: from unknown (evilhost [{ORIGIN_IP}])',
        '        by relay.cheap-smtp.example with SMTP; Tue, 2 Jul 2024 09:12:35 +0000',
        f'X-Phishing-Link: http://bigcorp-secure.example/verify?t={token}',
        '',
        'Please review the attached wire instructions immediately.',
        '',
    ])


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        f.write(build_headers(team_id))


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("email_headers.txt", team_id)
    print(f"생성 완료: email_headers.txt (team={team_id})")
