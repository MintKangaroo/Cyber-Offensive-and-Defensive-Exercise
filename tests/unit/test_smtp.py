"""
실제 SMTP 서버(P1-2 슬라이스) 세션 상태머신 계약 고정.
defense_network 가 진짜 SMTP 를 말하고 '오픈 릴레이(DN-004)' 취약점을 갖게 한다 —
실제 메일 클라이언트(smtplib)가 인증 없이 외부 도메인으로 릴레이하면 취약.
"""
from shared.net.smtp_server import SmtpSession


def _sess(allow_relay=True, local=("corp.local",), seen=None):
    return SmtpSession("mail.corp.local", allow_relay=allow_relay,
                       local_domains=set(local),
                       on_message=(seen.append if seen is not None else None))


def test_greeting_and_helo():
    s = _sess()
    assert s.greeting().startswith("220")
    resp, close = s.handle_line("EHLO attacker")
    assert resp.startswith("250") and close is False


def test_full_local_delivery_flow():
    seen = []
    s = _sess(seen=seen)
    s.handle_line("HELO x")
    assert s.handle_line("MAIL FROM:<a@corp.local>")[0].startswith("250")
    assert s.handle_line("RCPT TO:<b@corp.local>")[0].startswith("250")
    assert s.handle_line("DATA")[0].startswith("354")
    s.handle_line("Subject: hi")
    s.handle_line("")
    s.handle_line("body line")
    resp, _ = s.handle_line(".")
    assert resp.startswith("250")            # queued
    assert len(seen) == 1 and seen[0]["recipients"] == ["b@corp.local"]


def test_open_relay_accepts_external_when_unpatched():
    # 취약(allow_relay=True): 인증 없이 외부 도메인 릴레이 허용 = DN-004
    s = _sess(allow_relay=True)
    s.handle_line("HELO x")
    s.handle_line("MAIL FROM:<spammer@evil.com>")
    resp, _ = s.handle_line("RCPT TO:<victim@external.org>")
    assert resp.startswith("250") and s.is_relay is True


def test_relay_denied_when_patched():
    # 패치(allow_relay=False): 외부 릴레이 거부(550)
    s = _sess(allow_relay=False)
    s.handle_line("HELO x")
    s.handle_line("MAIL FROM:<spammer@evil.com>")
    resp, _ = s.handle_line("RCPT TO:<victim@external.org>")
    assert resp.startswith("550")


def test_local_delivery_allowed_even_when_patched():
    s = _sess(allow_relay=False)
    s.handle_line("HELO x")
    s.handle_line("MAIL FROM:<a@corp.local>")
    assert s.handle_line("RCPT TO:<b@corp.local>")[0].startswith("250")


def test_rcpt_before_mail_is_error():
    s = _sess()
    s.handle_line("HELO x")
    assert s.handle_line("RCPT TO:<b@corp.local>")[0].startswith("503")


def test_quit_closes():
    s = _sess()
    resp, close = s.handle_line("QUIT")
    assert resp.startswith("221") and close is True


def test_unknown_command():
    s = _sess()
    s.handle_line("HELO x")
    assert s.handle_line("WHATISTHIS")[0].startswith("500")
