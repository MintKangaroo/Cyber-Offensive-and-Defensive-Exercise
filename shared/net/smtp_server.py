"""
실제 SMTP 서버(P1-2 슬라이스) — 세션 상태머신 + asyncio 서버
=============================================================
defense_network 트윈을 진짜 SMTP 를 말하는 메일 서버로 만든다. 실제 클라이언트(smtplib,
swaks, telnet)가 그대로 붙는다. 취약점: **오픈 릴레이(DN-004)** — 인증 없이 외부 도메인으로
메일을 릴레이(스팸/피싱 발판). 패치되면 외부 릴레이를 550 으로 거부.

`SmtpSession` 은 소켓과 무관한 라인 단위 상태머신이라 단위 테스트가 쉽다. `serve()` 가 TCP 로
노출한다. 메일 접수 시 on_message 콜백 → 트윈이 이벤트 발행·SIEM 로그.
"""
from __future__ import annotations

import asyncio
import re
from typing import Callable, Optional

_ADDR = re.compile(r"<?([^<>@\s]+@[^<>@\s]+)>?")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


class SmtpSession:
    def __init__(self, hostname: str, allow_relay: bool = True,
                 local_domains: Optional[set[str]] = None,
                 on_message: Optional[Callable[[dict], None]] = None):
        self.hostname = hostname
        self.allow_relay = allow_relay
        self.local_domains = local_domains or set()
        self.on_message = on_message
        self.helo: Optional[str] = None
        self.sender: Optional[str] = None
        self.recipients: list[str] = []
        self.in_data = False
        self._data: list[str] = []
        self.is_relay = False   # 이 트랜잭션에 외부 릴레이 수신자가 있었는가(취약 신호)

    def greeting(self) -> str:
        return f"220 {self.hostname} ESMTP ready"

    def _reset(self):
        self.sender = None
        self.recipients = []
        self.in_data = False
        self._data = []

    def handle_line(self, line: str) -> tuple[str, bool]:
        """한 줄 처리 → (응답문자열, 연결종료여부)."""
        if self.in_data:
            if line == ".":
                self.in_data = False
                msg = {"sender": self.sender, "recipients": list(self.recipients),
                       "data": "\n".join(self._data), "relay": self.is_relay}
                if self.on_message:
                    try:
                        self.on_message(msg)
                    except Exception:
                        pass
                self._reset()
                return "250 2.0.0 Ok: queued", False
            self._data.append(line)
            return "", False   # DATA 모드에서는 각 라인에 응답하지 않음

        parts = line.strip().split(None, 1)
        cmd = (parts[0].upper() if parts else "")
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("HELO", "EHLO"):
            self.helo = arg or "unknown"
            return f"250 {self.hostname} greets {self.helo}", False
        if cmd == "MAIL":
            m = _ADDR.search(arg)
            if not m:
                return "501 5.5.4 Syntax: MAIL FROM:<address>", False
            self.sender = m.group(1)
            self.recipients = []
            self.is_relay = False
            return "250 2.1.0 Ok", False
        if cmd == "RCPT":
            if not self.sender:
                return "503 5.5.1 Error: need MAIL command", False
            m = _ADDR.search(arg)
            if not m:
                return "501 5.5.4 Syntax: RCPT TO:<address>", False
            rcpt = m.group(1)
            external = _domain(rcpt) not in self.local_domains
            if external and not self.allow_relay:
                return "550 5.7.1 Relaying denied", False
            if external:
                self.is_relay = True   # 취약: 인증 없이 외부 릴레이 수락
            self.recipients.append(rcpt)
            return "250 2.1.5 Ok", False
        if cmd == "DATA":
            if not self.recipients:
                return "503 5.5.1 Error: need RCPT command", False
            self.in_data = True
            return "354 End data with <CR><LF>.<CR><LF>", False
        if cmd == "RSET":
            self._reset()
            return "250 2.0.0 Ok", False
        if cmd == "NOOP":
            return "250 2.0.0 Ok", False
        if cmd == "QUIT":
            return f"221 2.0.0 {self.hostname} closing connection", True
        return "500 5.5.2 Error: command not recognized", False


async def _handle_client(factory, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sess: SmtpSession = factory()
    writer.write((sess.greeting() + "\r\n").encode())
    await writer.drain()
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            resp, close = sess.handle_line(line)
            if resp:
                writer.write((resp + "\r\n").encode())
                await writer.drain()
            if close:
                break
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(factory: Callable[[], SmtpSession], host: str = "0.0.0.0",
                port: int = 25) -> asyncio.AbstractServer:
    """SMTP 서버 기동(비차단). factory() 가 커넥션마다 새 SmtpSession 을 만든다."""
    return await asyncio.start_server(lambda r, w: _handle_client(factory, r, w), host, port)
