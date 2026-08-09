from __future__ import annotations

import hashlib
import socket
import struct
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.pcap_privacy import (
    PcapPrivacyError,
    apply_recipient_watermark,
    sanitize_pcap,
)

from .conftest import bootstrap
from .test_security import SECRET, token


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_tcp_pcap(
    payload: bytes,
    *,
    timestamp: float | None = None,
    source: str = "192.0.2.10",
    destination: str = "198.51.100.20",
) -> bytes:
    source_ip = socket.inet_aton(source)
    destination_ip = socket.inet_aton(destination)
    tcp = bytearray(struct.pack(
        "!HHIIBBHHH", 40123, 8080, 1, 1, 0x50, 0x18, 4096, 0, 0
    ))
    tcp.extend(payload)
    pseudo = source_ip + destination_ip + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", tcp, 16, checksum(pseudo + tcp))
    ip = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 7, 0x4000,
        64, 6, 0, source_ip, destination_ip,
    ))
    struct.pack_into("!H", ip, 10, checksum(ip))
    frame = (
        bytes.fromhex("00112233445566778899aabb0800")
        + bytes(ip) + bytes(tcp)
    )
    stamp = time.time() if timestamp is None else timestamp
    seconds = int(stamp)
    micros = int((stamp - seconds) * 1_000_000)
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack(
        "<HHiIII", 2, 4, 0, 0, 65_535, 1
    )
    return global_header + struct.pack(
        "<IIII", seconds, micros, len(frame), len(frame)
    ) + frame


def test_binary_sanitizer_redacts_and_repairs_checksums():
    raw = ethernet_tcp_pcap(
        b"POST / HTTP/1.1\r\nAuthorization: Bearer secret-token\r\n\r\n"
        b"flag=FLAG{abcdefghijklmnopqrstuvwxyzABCDEF}&host=192.0.2.10"
    )
    result = sanitize_pcap(raw, secret="anon-secret", scope="match-1")

    assert len(result.data) == len(raw)
    assert result.packet_count == 1
    assert result.redaction_count >= 3
    assert result.address_count == 2
    assert b"secret-token" not in result.data
    assert b"FLAG{" not in result.data
    assert b"192.0.2.10" not in result.data
    assert bytes.fromhex("66778899aabb") not in result.data

    frame = result.data[24 + 16:]
    ip = frame[14:34]
    tcp = frame[34:]
    assert checksum(ip) == 0
    pseudo = ip[12:16] + ip[16:20] + struct.pack("!BBH", 0, 6, len(tcp))
    assert checksum(pseudo + tcp) == 0


def test_binary_sanitizer_redacts_json_secrets_and_unrelated_text_addresses():
    raw = ethernet_tcp_pcap(
        b'{"password":"hunter2","peer":"203.0.113.77"}'
    )
    result = sanitize_pcap(raw, secret="anon-secret", scope="match-1")
    assert b"hunter2" not in result.data
    assert b"203.0.113.77" not in result.data
    assert len(result.data) == len(raw)


def test_binary_sanitizer_is_deterministic_and_scope_separated():
    raw = ethernet_tcp_pcap(b"GET /health HTTP/1.1\r\n\r\n")
    first = sanitize_pcap(raw, secret="anon-secret", scope="match-1")
    replay = sanitize_pcap(raw, secret="anon-secret", scope="match-1")
    other = sanitize_pcap(raw, secret="anon-secret", scope="match-2")
    assert first.data == replay.data
    assert first.data != other.data


def test_recipient_watermark_is_structural_and_team_specific():
    sanitized = sanitize_pcap(
        ethernet_tcp_pcap(b"payload"), secret="anon-secret", scope="match-1"
    ).data
    team_one, mark_one = apply_recipient_watermark(
        sanitized, secret="watermark-secret", artifact_id="capture-1",
        recipient_id="team-1",
    )
    team_two, mark_two = apply_recipient_watermark(
        sanitized, secret="watermark-secret", artifact_id="capture-1",
        recipient_id="team-2",
    )
    assert mark_one != mark_two
    assert team_one[:12] == team_two[:12]
    assert team_one[16:] == team_two[16:]
    assert team_one[12:16].hex() == mark_one


@pytest.mark.parametrize("value", [
    b"",
    b"\x0a\x0d\x0d\x0a" + b"X" * 40,
    b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 999),
])
def test_sanitizer_fails_closed_on_unsupported_capture(value: bytes):
    with pytest.raises(PcapPrivacyError):
        sanitize_pcap(value, secret="anon-secret", scope="match-1")


def auth_headers(role: str, team_id: str = "", match_id: str = "") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(role, team_id, match_id)}"}


def upload_headers() -> dict[str, str]:
    return {
        **auth_headers("operator"),
        "Content-Type": "application/vnd.tcpdump.pcap",
        "X-Operation-Reason": "delayed post-round team evidence",
    }


def test_operator_ingest_and_delayed_competitor_download(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    raw = ethernet_tcp_pcap(
        b"token=FLAG{abcdefghijklmnopqrstuvwxyzABCDEF}",
        timestamp=time.time() - ad.settings.pcap_release_delay_seconds - 5,
    )
    uploaded = client.post(
        "/api/attack-defense/operator/matches/match-1/captures",
        headers=upload_headers(), content=raw,
    )
    assert uploaded.status_code == 201
    capture = uploaded.json()
    assert capture["available"] is True
    assert capture["redaction_count"] >= 1

    first_headers = auth_headers("competitor", "team-1", "match-1")
    listed = client.get(
        "/api/attack-defense/matches/match-1/captures", headers=first_headers
    )
    assert listed.status_code == 200
    assert listed.json()["captures"][0]["privacy"].startswith("addresses-pseudonymized")
    assert "raw_sha256" not in listed.text

    download_path = (
        f"/api/attack-defense/matches/match-1/captures/{capture['id']}/download"
    )
    first = client.get(download_path, headers=first_headers)
    second = client.get(
        download_path,
        headers=auth_headers("competitor", "team-2", "match-1"),
    )
    assert first.status_code == second.status_code == 200
    assert first.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert first.headers["x-capture-watermark"] != second.headers["x-capture-watermark"]
    assert first.content != second.content
    # Recipient views differ in address pseudonyms, not only the four-byte
    # watermark field.
    assert first.content[16:] != second.content[16:]
    assert b"FLAG{" not in first.content
    assert first.headers["x-capture-sha256"] == hashlib.sha256(first.content).hexdigest()

    conn = ad.db.connect()
    releases = conn.execute(
        "SELECT COUNT(*) FROM capture_releases WHERE capture_id=?", (capture["id"],)
    ).fetchone()[0]
    events = [dict(row) for row in conn.execute(
        "SELECT * FROM audit_events WHERE event_type LIKE 'capture_%'"
    )]
    conn.close()
    assert releases == 2
    assert len(events) == 3
    assert "FLAG{" not in str(events)
    stored = list(ad.captures.storage.glob("*.pcap"))
    assert len(stored) == 1
    assert stored[0].read_bytes() != raw
    assert b"FLAG{" not in stored[0].read_bytes()
    metrics = client.get("/metrics").text
    assert "attack_defense_capture_ingest_total 1" in metrics
    assert "attack_defense_capture_download_total 2" in metrics


def test_capture_is_withheld_until_server_release_time(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    uploaded = client.post(
        "/api/attack-defense/operator/matches/match-1/captures",
        headers=upload_headers(), content=ethernet_tcp_pcap(b"benign"),
    )
    assert uploaded.status_code == 201
    capture = uploaded.json()
    assert capture["status"] == "withheld"
    response = client.get(
        f"/api/attack-defense/matches/match-1/captures/{capture['id']}/download",
        headers=auth_headers("competitor", "team-1", "match-1"),
    )
    assert response.status_code == 425
    assert int(response.headers["retry-after"]) > 0


def test_capture_ingest_requires_operator_and_valid_media_type(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    path = "/api/attack-defense/operator/matches/match-1/captures"
    competitor = client.post(
        path,
        headers={
            **auth_headers("competitor", "team-1", "match-1"),
            "Content-Type": "application/vnd.tcpdump.pcap",
            "X-Operation-Reason": "attempted unauthorized ingest",
        },
        content=ethernet_tcp_pcap(b"benign"),
    )
    assert competitor.status_code == 403
    wrong_type = client.post(
        path,
        headers={**upload_headers(), "Content-Type": "application/json"},
        content=b"{}",
    )
    assert wrong_type.status_code == 415


def test_capture_access_is_match_scoped_and_ingest_is_idempotent(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    ad.repo.create_match("Other", 5, 3, {}, "match-2", "attack_defense")
    ad.repo.add_team("match-2", "other-01", "Other", "other-team")
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    raw = ethernet_tcp_pcap(
        b"benign", timestamp=time.time() - ad.settings.pcap_release_delay_seconds - 5
    )
    first = client.post(
        "/api/attack-defense/operator/matches/match-1/captures",
        headers=upload_headers(), content=raw,
    )
    replay = client.post(
        "/api/attack-defense/operator/matches/match-1/captures",
        headers=upload_headers(), content=raw,
    )
    assert first.status_code == replay.status_code == 201
    assert first.json()["id"] == replay.json()["id"]
    conn = ad.db.connect()
    assert conn.execute("SELECT COUNT(*) FROM capture_artifacts").fetchone()[0] == 1
    conn.close()
    denied = client.get(
        f"/api/attack-defense/matches/match-1/captures/{first.json()['id']}/download",
        headers=auth_headers("competitor", "other-team", "match-2"),
    )
    assert denied.status_code == 403


def test_capture_download_rate_limit_is_persistent(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    ad.settings = replace(ad.settings, pcap_max_downloads_per_minute=2)
    client = TestClient(create_app(ad))
    raw = ethernet_tcp_pcap(
        b"benign", timestamp=time.time() - ad.settings.pcap_release_delay_seconds - 5
    )
    uploaded = client.post(
        "/api/attack-defense/operator/matches/match-1/captures",
        headers=upload_headers(), content=raw,
    ).json()
    path = f"/api/attack-defense/matches/match-1/captures/{uploaded['id']}/download"
    headers = auth_headers("competitor", "team-1", "match-1")
    assert client.get(path, headers=headers).status_code == 200
    assert client.get(path, headers=headers).status_code == 200
    limited = client.get(path, headers=headers)
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_future_timestamp_oversize_and_integrity_fail_closed(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    ad.settings = replace(ad.settings, pcap_max_upload_mb=1)
    client = TestClient(create_app(ad))
    path = "/api/attack-defense/operator/matches/match-1/captures"

    future = client.post(
        path, headers=upload_headers(),
        content=ethernet_tcp_pcap(
            b"benign", timestamp=time.time() + ad.settings.pcap_max_future_skew_seconds + 30
        ),
    )
    assert future.status_code == 400
    assert future.json()["detail"] == "capture failed privacy validation"

    oversized = client.post(
        path, headers=upload_headers(), content=b"X" * (1024 * 1024 + 1)
    )
    assert oversized.status_code == 413

    valid = client.post(
        path, headers=upload_headers(),
        content=ethernet_tcp_pcap(
            b"benign", timestamp=time.time() - ad.settings.pcap_release_delay_seconds - 5
        ),
    ).json()
    stored = next(ad.captures.storage.glob("*.pcap"))
    stored.write_bytes(b"tampered")
    failed = client.get(
        f"/api/attack-defense/matches/match-1/captures/{valid['id']}/download",
        headers=auth_headers("competitor", "team-1", "match-1"),
    )
    assert failed.status_code == 503
    assert failed.json()["detail"] == "capture is temporarily unavailable"


def test_observer_cannot_list_or_download_team_capture(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    observer = auth_headers("observer", "", "match-1")
    assert client.get(
        "/api/attack-defense/matches/match-1/captures", headers=observer
    ).status_code == 403
