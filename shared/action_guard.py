"""Explicit confirmation and durable intent/outcome for dangerous range actions."""

from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from pathlib import Path

from fastapi import HTTPException


def dangerous(method: str, path: str) -> bool:
    return (
        method == "POST"
        and (
            path.endswith("/admin/reset")
            or path.startswith("/ranges/")
            and path.endswith(("/reset", "/verify-baseline"))
            or path
            in {
                "/instructor/killswitch",
                "/instructor/killswitch/release",
                "/safety/emergency-stop",
                "/safety/emergency-stop/release",
                "/scenario/activate",
                "/scenario/deactivate",
            }
        )
    ) or (method == "DELETE" and path.startswith("/matches/"))


def record(entry: dict):
    folder = Path(os.environ.get("DATA_DIR", "/tmp"))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "security-actions.jsonl"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as out:
            fcntl.flock(out, fcntl.LOCK_EX)
            out.write(json.dumps(entry, ensure_ascii=False) + "\n")
            out.flush()
            os.fsync(out.fileno())
    except OSError as exc:
        raise HTTPException(
            503,
            "Safety audit storage is unavailable; inspect the action status before retrying",
        ) from exc


async def guarded(app, scope, receive, send, identity):
    raw = bytearray()
    while True:
        message = await receive()
        if message["type"] != "http.request":
            raise HTTPException(400, "Action body was interrupted")
        raw.extend(message.get("body", b""))
        if len(raw) > 65536:
            raise HTTPException(413, "Action body exceeds 64 KiB")
        if not message.get("more_body", False):
            break
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(400, "Action body must be JSON") from None
    if (
        not isinstance(body, dict)
        or body.get("confirm") is not True
        or not isinstance(body.get("reason"), str)
        or not 3 <= len(body["reason"].strip()) <= 2000
    ):
        raise HTTPException(
            400, "Explicit confirm=true and a reason of 3–2000 characters are required"
        )
    entry = {
        "id": str(uuid.uuid4()),
        "actor": identity.actor,
        "role": identity.role,
        "path": scope["path"],
        "reason": body["reason"].strip(),
    }
    record({**entry, "status": "requested", "timestamp": time.time()})
    first = True
    completed = False

    async def replay_receive():
        nonlocal first
        if first:
            first = False
            return {"type": "http.request", "body": bytes(raw), "more_body": False}
        return await receive()

    async def audited_send(message):
        nonlocal completed
        if message["type"] == "http.response.start":
            record(
                {
                    **entry,
                    "status": "completed" if message["status"] < 400 else "failed",
                    "http_status": message["status"],
                    "timestamp": time.time(),
                }
            )
            completed = True
        await send(message)

    try:
        await app(scope, replay_receive, audited_send)
    except Exception:
        if not completed:
            record({**entry, "status": "interrupted", "timestamp": time.time()})
        raise
