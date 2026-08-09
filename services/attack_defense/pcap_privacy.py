from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .flag_service import FlagService
from .repositories import AttackDefenseRepository
from .utils import json_load, stable_id


SANITIZER_VERSION = "pcap-v1"
SUPPORTED_LINK_TYPES = {1, 101, 113}  # Ethernet, raw IP, Linux cooked v1
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_GENERIC_FLAG_RE = re.compile(rb"FLAG\{[A-Za-z0-9_-]{3,128}\}")
_SENSITIVE_RE = re.compile(
    rb"(?i)(?:authorization|token|password|secret|api[_-]?key|cookie)"
    rb"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?([^\s&;,\"'\r\n}]+)"
)
_IPV4_TEXT_RE = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6_TEXT_RE = re.compile(
    rb"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)


class PcapPrivacyError(ValueError):
    """The capture cannot be released safely."""


class CaptureNotReleased(PcapPrivacyError):
    def __init__(self, retry_after: int):
        super().__init__("capture is not available yet")
        self.retry_after = max(1, retry_after)


class CaptureIntegrityError(PcapPrivacyError):
    pass


@dataclass(frozen=True)
class PcapSanitizationResult:
    data: bytes
    raw_sha256: str
    sanitized_sha256: str
    packet_count: int
    redaction_count: int
    address_count: int
    captured_from: float
    captured_until: float
    link_type: int


@dataclass(frozen=True)
class CaptureDownload:
    data: bytes
    filename: str
    watermark: str
    sha256: str


def _pcap_header(data: bytes) -> tuple[str, int, int]:
    if len(data) < 24:
        raise PcapPrivacyError("truncated pcap global header")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapPrivacyError("pcapng is not supported by the MVP sanitizer")
    layout = _PCAP_MAGICS.get(data[:4])
    if not layout:
        raise PcapPrivacyError("unsupported pcap magic")
    endian, precision = layout
    major, minor, _, _, snaplen, network = struct.unpack(
        f"{endian}HHiIII", data[4:24]
    )
    link_type = network & 0xFFFF
    if (major, minor) != (2, 4) or snaplen <= 0:
        raise PcapPrivacyError("unsupported pcap header")
    if link_type not in SUPPORTED_LINK_TYPES:
        raise PcapPrivacyError(f"unsupported pcap link type: {link_type}")
    return endian, precision, link_type


def _digest(secret: str, *parts: bytes | str) -> bytes:
    message = b"\x00".join(
        part if isinstance(part, bytes) else part.encode("utf-8") for part in parts
    )
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def _pseudo_ipv4(address: bytes, secret: str, scope: str) -> bytes:
    # 10/8 is used only inside the analysis-only sanitized artifact. All
    # observed IPv4 endpoints are rewritten, so it cannot collide with a raw
    # address retained elsewhere in the same artifact.
    return b"\x0a" + _digest(secret, SANITIZER_VERSION, scope, b"ipv4", address)[:3]


def _pseudo_ipv6(address: bytes, secret: str, scope: str) -> bytes:
    # RFC 4193 local prefix marks the address as synthetic while leaving 120
    # HMAC-derived bits for stable, low-collision flow correlation.
    return b"\xfd" + _digest(secret, SANITIZER_VERSION, scope, b"ipv6", address)[:15]


def _pseudo_mac(address: bytes, secret: str, scope: str) -> bytes:
    if len(address) != 6 or address == b"\xff" * 6 or address[0] & 1:
        return address
    value = bytearray(_digest(secret, SANITIZER_VERSION, scope, b"mac", address)[:6])
    value[0] = (value[0] | 0x02) & 0xFE  # locally administered unicast
    return bytes(value)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mask_range(buffer: bytearray, start: int, end: int) -> None:
    buffer[start:end] = b"X" * max(0, end - start)


def _scrub_payload(
    packet: bytearray,
    start: int,
    end: int,
    sensitive_values: Iterable[bytes],
    address_literals: Iterable[bytes],
) -> int:
    if start >= end:
        return 0
    payload = bytearray(packet[start:end])
    redactions = 0

    for value in sorted({v for v in sensitive_values if v}, key=len, reverse=True):
        position = 0
        while True:
            found = payload.find(value, position)
            if found < 0:
                break
            _mask_range(payload, found, found + len(value))
            redactions += 1
            position = found + len(value)

    for match in reversed(list(_GENERIC_FLAG_RE.finditer(payload))):
        _mask_range(payload, match.start(), match.end())
        redactions += 1

    # Only the captured value is removed; header names remain useful for
    # protocol analysis and detector development.
    for match in reversed(list(_SENSITIVE_RE.finditer(payload))):
        _mask_range(payload, match.start(1), match.end(1))
        redactions += 1

    for pattern in (_IPV4_TEXT_RE, _IPV6_TEXT_RE):
        for match in reversed(list(pattern.finditer(payload))):
            value = payload[match.start():match.end()]
            replacement = bytes(
                char if char in {ord("."), ord(":")} else ord("X") for char in value
            )
            payload[match.start():match.end()] = replacement
            redactions += 1

    for literal in sorted({v for v in address_literals if v}, key=len, reverse=True):
        position = 0
        while True:
            found = payload.find(literal, position)
            if found < 0:
                break
            replacement = bytes(
                char if char in {ord("."), ord(":")} else ord("X") for char in literal
            )
            payload[found:found + len(literal)] = replacement
            redactions += 1
            position = found + len(literal)

    packet[start:end] = payload
    return redactions


def _transport_payload_offset(packet: bytearray, offset: int, end: int, protocol: int) -> int:
    if protocol == 6 and offset + 20 <= end:  # TCP
        length = (packet[offset + 12] >> 4) * 4
        return min(end, offset + max(20, length))
    if protocol in {17, 1, 58} and offset + 8 <= end:  # UDP / ICMP / ICMPv6
        return offset + 8
    return offset


def _rewrite_transport_checksum(
    packet: bytearray,
    offset: int,
    end: int,
    protocol: int,
    source: bytes,
    destination: bytes,
    ipv6: bool,
    original_udp_zero: bool = False,
) -> None:
    length = end - offset
    if protocol == 6 and length >= 20:
        checksum_offset = offset + 16
    elif protocol == 17 and length >= 8:
        if original_udp_zero and not ipv6:
            return
        checksum_offset = offset + 6
    elif protocol == 1 and not ipv6 and length >= 8:
        checksum_offset = offset + 2
        packet[checksum_offset:checksum_offset + 2] = b"\x00\x00"
        struct.pack_into("!H", packet, checksum_offset, _checksum(bytes(packet[offset:end])))
        return
    elif protocol == 58 and ipv6 and length >= 8:
        checksum_offset = offset + 2
    else:
        return

    packet[checksum_offset:checksum_offset + 2] = b"\x00\x00"
    if ipv6:
        pseudo = source + destination + struct.pack("!I3xB", length, protocol)
    else:
        pseudo = source + destination + struct.pack("!BBH", 0, protocol, length)
    value = _checksum(pseudo + bytes(packet[offset:end]))
    if protocol == 17 and value == 0:
        value = 0xFFFF
    struct.pack_into("!H", packet, checksum_offset, value)


def _sanitize_ipv4(
    packet: bytearray,
    offset: int,
    sensitive_values: Iterable[bytes],
    secret: str,
    scope: str,
    addresses: set[bytes],
) -> int:
    if offset + 20 > len(packet) or packet[offset] >> 4 != 4:
        raise PcapPrivacyError("truncated IPv4 packet")
    header_length = (packet[offset] & 0x0F) * 4
    if header_length < 20 or offset + header_length > len(packet):
        raise PcapPrivacyError("invalid IPv4 header length")
    total_length = struct.unpack_from("!H", packet, offset + 2)[0]
    if total_length < header_length:
        raise PcapPrivacyError("invalid IPv4 total length")
    end = min(len(packet), offset + total_length)
    complete = offset + total_length <= len(packet)
    source = bytes(packet[offset + 12:offset + 16])
    destination = bytes(packet[offset + 16:offset + 20])
    addresses.update((source, destination))
    source_text = str(ipaddress.ip_address(source)).encode("ascii")
    destination_text = str(ipaddress.ip_address(destination)).encode("ascii")
    new_source = _pseudo_ipv4(source, secret, scope)
    new_destination = _pseudo_ipv4(destination, secret, scope)
    packet[offset + 12:offset + 16] = new_source
    packet[offset + 16:offset + 20] = new_destination

    protocol = packet[offset + 9]
    transport = offset + header_length
    payload = _transport_payload_offset(packet, transport, end, protocol)
    redactions = _scrub_payload(
        packet, payload, end, sensitive_values, (source_text, destination_text)
    )

    fragment = struct.unpack_from("!H", packet, offset + 6)[0]
    fragmented = bool(fragment & 0x3FFF)
    original_udp_zero = (
        protocol == 17 and transport + 8 <= end
        and packet[transport + 6:transport + 8] == b"\x00\x00"
    )
    if complete and not fragmented:
        _rewrite_transport_checksum(
            packet, transport, end, protocol, new_source, new_destination,
            ipv6=False, original_udp_zero=original_udp_zero,
        )
    packet[offset + 10:offset + 12] = b"\x00\x00"
    struct.pack_into(
        "!H", packet, offset + 10,
        _checksum(bytes(packet[offset:offset + header_length])),
    )
    return redactions


def _ipv6_transport(packet: bytearray, offset: int, end: int) -> tuple[int, int, bool]:
    protocol = packet[offset + 6]
    cursor = offset + 40
    fragmented = False
    while protocol in {0, 43, 44, 51, 60}:
        if cursor + 2 > end:
            raise PcapPrivacyError("truncated IPv6 extension header")
        next_protocol = packet[cursor]
        if protocol == 44:
            length = 8
            fragmented = True
        elif protocol == 51:
            length = (packet[cursor + 1] + 2) * 4
        else:
            length = (packet[cursor + 1] + 1) * 8
        if length <= 0 or cursor + length > end:
            raise PcapPrivacyError("invalid IPv6 extension header")
        cursor += length
        protocol = next_protocol
    return cursor, protocol, fragmented


def _sanitize_ipv6(
    packet: bytearray,
    offset: int,
    sensitive_values: Iterable[bytes],
    secret: str,
    scope: str,
    addresses: set[bytes],
) -> int:
    if offset + 40 > len(packet) or packet[offset] >> 4 != 6:
        raise PcapPrivacyError("truncated IPv6 packet")
    payload_length = struct.unpack_from("!H", packet, offset + 4)[0]
    if payload_length == 0 and len(packet) > offset + 40:
        raise PcapPrivacyError("IPv6 jumbograms are not supported")
    total_length = 40 + payload_length
    end = min(len(packet), offset + total_length)
    complete = offset + total_length <= len(packet)
    source = bytes(packet[offset + 8:offset + 24])
    destination = bytes(packet[offset + 24:offset + 40])
    addresses.update((source, destination))
    source_text = str(ipaddress.ip_address(source)).encode("ascii")
    destination_text = str(ipaddress.ip_address(destination)).encode("ascii")
    new_source = _pseudo_ipv6(source, secret, scope)
    new_destination = _pseudo_ipv6(destination, secret, scope)
    packet[offset + 8:offset + 24] = new_source
    packet[offset + 24:offset + 40] = new_destination

    transport, protocol, fragmented = _ipv6_transport(packet, offset, end)
    payload = _transport_payload_offset(packet, transport, end, protocol)
    redactions = _scrub_payload(
        packet, payload, end, sensitive_values, (source_text, destination_text)
    )
    if complete and not fragmented:
        _rewrite_transport_checksum(
            packet, transport, end, protocol, new_source, new_destination,
            ipv6=True,
        )
    return redactions


def _sanitize_arp(
    packet: bytearray, offset: int, secret: str, scope: str, addresses: set[bytes]
) -> None:
    if offset + 8 > len(packet):
        raise PcapPrivacyError("truncated ARP header")
    hardware_type, protocol_type, hardware_len, protocol_len = struct.unpack_from(
        "!HHBB", packet, offset
    )
    if (hardware_type, protocol_type, hardware_len, protocol_len) != (1, 0x0800, 6, 4):
        return
    if offset + 28 > len(packet):
        raise PcapPrivacyError("truncated Ethernet/IPv4 ARP packet")
    for mac_offset in (offset + 8, offset + 18):
        packet[mac_offset:mac_offset + 6] = _pseudo_mac(
            bytes(packet[mac_offset:mac_offset + 6]), secret, scope
        )
    for ip_offset in (offset + 14, offset + 24):
        address = bytes(packet[ip_offset:ip_offset + 4])
        addresses.add(address)
        packet[ip_offset:ip_offset + 4] = _pseudo_ipv4(address, secret, scope)


def _sanitize_packet(
    raw: bytes,
    link_type: int,
    sensitive_values: Iterable[bytes],
    secret: str,
    scope: str,
    addresses: set[bytes],
) -> tuple[bytes, int]:
    packet = bytearray(raw)
    protocol = 0
    network_offset = 0

    if link_type == 1:
        if len(packet) < 14:
            raise PcapPrivacyError("truncated Ethernet frame")
        packet[0:6] = _pseudo_mac(bytes(packet[0:6]), secret, scope)
        packet[6:12] = _pseudo_mac(bytes(packet[6:12]), secret, scope)
        protocol = struct.unpack_from("!H", packet, 12)[0]
        network_offset = 14
        while protocol in {0x8100, 0x88A8}:
            if network_offset + 4 > len(packet):
                raise PcapPrivacyError("truncated VLAN header")
            protocol = struct.unpack_from("!H", packet, network_offset + 2)[0]
            network_offset += 4
    elif link_type == 101:
        if not packet:
            raise PcapPrivacyError("empty raw IP packet")
        version = packet[0] >> 4
        if version not in {4, 6}:
            raise PcapPrivacyError("unsupported raw IP version")
        protocol = 0x0800 if version == 4 else 0x86DD
    elif link_type == 113:
        if len(packet) < 16:
            raise PcapPrivacyError("truncated Linux cooked frame")
        address_length = min(struct.unpack_from("!H", packet, 4)[0], 8)
        if address_length == 6:
            packet[6:12] = _pseudo_mac(bytes(packet[6:12]), secret, scope)
        protocol = struct.unpack_from("!H", packet, 14)[0]
        network_offset = 16

    if protocol == 0x0800:
        redactions = _sanitize_ipv4(
            packet, network_offset, sensitive_values, secret, scope, addresses
        )
    elif protocol == 0x86DD:
        redactions = _sanitize_ipv6(
            packet, network_offset, sensitive_values, secret, scope, addresses
        )
    elif protocol == 0x0806 and link_type == 1:
        _sanitize_arp(packet, network_offset, secret, scope, addresses)
        redactions = _scrub_payload(
            packet, network_offset, len(packet), sensitive_values, ()
        )
    else:
        # Unknown L3 payloads are retained for forensic usefulness but still
        # receive token/credential scrubbing. Unsupported link types are
        # rejected at the global header boundary instead of passing through.
        redactions = _scrub_payload(
            packet, network_offset, len(packet), sensitive_values, ()
        )
    return bytes(packet), redactions


def sanitize_pcap(
    data: bytes,
    *,
    secret: str,
    scope: str,
    sensitive_values: Iterable[str | bytes] = (),
    maximum_packets: int = 1_000_000,
) -> PcapSanitizationResult:
    """Return an analysis-only classic-PCAP artifact with private data removed.

    Packet lengths and record boundaries are preserved. Checksums are repaired
    for complete, unfragmented IPv4/IPv6 TCP, UDP and ICMP packets. Fragmented
    or snaplen-truncated packets remain suitable for analysis but are not
    guaranteed to be replayable after address rewriting.
    """
    endian, precision, link_type = _pcap_header(data)
    raw_sha = hashlib.sha256(data).hexdigest()
    values = tuple(
        value.encode("utf-8") if isinstance(value, str) else value
        for value in sensitive_values
        if value
    )
    output = bytearray(data[:24])
    # thiszone and sigfigs can fingerprint the capture host. sigfigs is also
    # reserved for the recipient-specific release watermark.
    output[8:16] = b"\x00" * 8
    cursor = 24
    packet_count = 0
    redactions = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    addresses: set[bytes] = set()

    while cursor < len(data):
        if len(data) - cursor < 16:
            raise PcapPrivacyError("truncated pcap packet header")
        seconds, fraction, included, original = struct.unpack_from(
            f"{endian}IIII", data, cursor
        )
        cursor += 16
        if included > original or included > 16 * 1024 * 1024:
            raise PcapPrivacyError("invalid pcap packet length")
        if cursor + included > len(data):
            raise PcapPrivacyError("truncated pcap packet data")
        if fraction >= precision:
            raise PcapPrivacyError("invalid pcap packet timestamp")
        packet_count += 1
        if packet_count > maximum_packets:
            raise PcapPrivacyError("pcap packet count exceeds policy")
        timestamp = float(seconds) + (float(fraction) / precision)
        first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
        last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
        packet, packet_redactions = _sanitize_packet(
            data[cursor:cursor + included], link_type, values, secret, scope, addresses
        )
        output.extend(struct.pack(f"{endian}IIII", seconds, fraction, len(packet), original))
        output.extend(packet)
        redactions += packet_redactions
        cursor += included

    if packet_count == 0 or first_timestamp is None or last_timestamp is None:
        raise PcapPrivacyError("pcap contains no packets")
    sanitized = bytes(output)
    return PcapSanitizationResult(
        data=sanitized,
        raw_sha256=raw_sha,
        sanitized_sha256=hashlib.sha256(sanitized).hexdigest(),
        packet_count=packet_count,
        redaction_count=redactions,
        address_count=len(addresses),
        captured_from=first_timestamp,
        captured_until=last_timestamp,
        link_type=link_type,
    )


def apply_recipient_watermark(
    data: bytes, *, secret: str, artifact_id: str, recipient_id: str
) -> tuple[bytes, str]:
    _pcap_header(data)
    tag = _digest(
        secret, SANITIZER_VERSION, b"watermark", artifact_id, recipient_id,
        hashlib.sha256(data).digest(),
    )[:4]
    marked = bytearray(data)
    marked[12:16] = tag
    return bytes(marked), tag.hex()


class CaptureService:
    """Persistence and authorization-neutral lifecycle for sanitized captures."""

    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        flags: FlagService,
        settings: AttackDefenseSettings,
        evidence: EvidenceRecorder,
    ):
        self.db = db
        self.repo = repo
        self.flags = flags
        self.settings = settings
        self.evidence = evidence
        self.storage = Path(
            settings.pcap_storage_dir or settings.database_path.parent / "captures"
        )
        self.storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.storage.chmod(0o700)
        except OSError:
            pass

    def ingest(
        self,
        match_id: str,
        raw_capture: bytes,
        actor: str,
        reason: str,
        *,
        round_id: str | None = None,
        service_id: str | None = None,
    ) -> dict[str, Any]:
        match = self.repo.get_match(match_id)
        if not match:
            raise KeyError(match_id)
        if round_id:
            round_row = self.repo.get_round(round_id)
            if not round_row or round_row["match_id"] != match_id:
                raise PcapPrivacyError("round does not belong to match")
        if service_id:
            service = self.repo.get_service(service_id)
            if not service or service["match_id"] != match_id:
                raise PcapPrivacyError("service does not belong to match")

        conn = self.db.connect()
        flag_rows = [dict(row) for row in conn.execute(
            "SELECT * FROM flags WHERE match_id=?", (match_id,)
        )]
        conn.close()
        # Deterministic HMAC flags can be reconstructed for in-memory
        # scrubbing without storing or logging their plaintext values.
        sensitive_values = tuple(self.flags.reconstruct(row) for row in flag_rows)
        result = sanitize_pcap(
            raw_capture,
            secret=self.settings.pcap_anonymization_secret,
            scope=match_id,
            sensitive_values=sensitive_values,
            maximum_packets=self.settings.pcap_max_packets,
        )

        with self.db.transaction() as conn:
            now = self.db.server_time(conn)
        if result.captured_until > now + self.settings.pcap_max_future_skew_seconds:
            raise PcapPrivacyError("capture timestamp is too far in the future")
        config = json_load(match["config"])
        configured_delay = int(config.get(
            "pcap_release_delay_seconds", self.settings.pcap_release_delay_seconds
        ))
        delay = max(0, min(configured_delay, 30 * 24 * 3600))
        release_at = result.captured_until + delay
        artifact_id = stable_id(
            "capture", SANITIZER_VERSION, match_id, round_id, service_id,
            result.raw_sha256, result.sanitized_sha256,
        )
        relative_path = f"{artifact_id}.pcap"
        self._write_atomic(relative_path, result.data)

        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT OR IGNORE INTO capture_artifacts(
                   id,match_id,round_id,service_id,status,sanitizer_version,
                   raw_sha256,sanitized_sha256,source_size_bytes,sanitized_size_bytes,
                   packet_count,redaction_count,address_count,link_type,captured_from,
                   captured_until,release_at,storage_name,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    artifact_id, match_id, round_id, service_id, "ready",
                    SANITIZER_VERSION, result.raw_sha256, result.sanitized_sha256,
                    len(raw_capture), len(result.data), result.packet_count,
                    result.redaction_count, result.address_count, result.link_type,
                    result.captured_from, result.captured_until, release_at,
                    relative_path, actor, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM capture_artifacts WHERE id=?", (artifact_id,)
            ).fetchone()
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="capture_ingest", result="sanitized",
                    match_id=match_id, round_id=round_id, service_id=service_id,
                    metadata={
                        "capture_id": artifact_id,
                        "raw_sha256": result.raw_sha256,
                        "sanitized_sha256": result.sanitized_sha256,
                        "packet_count": result.packet_count,
                        "redaction_count": result.redaction_count,
                        "release_delay_seconds": delay,
                        "reason": reason,
                    },
                    event_id=stable_id("audit", "capture-ingest", artifact_id),
                ),
                conn,
            )
        return self.public_metadata(dict(row), operator=True, now=now)

    def list(self, match_id: str, *, operator: bool) -> list[dict[str, Any]]:
        with self.db.transaction() as conn:
            now = self.db.server_time(conn)
            rows = [dict(row) for row in conn.execute(
                """SELECT c.*,r.sequence AS round_sequence,s.slug AS service_slug
                   FROM capture_artifacts c
                   LEFT JOIN rounds r ON r.id=c.round_id
                   LEFT JOIN game_services s ON s.id=c.service_id
                   WHERE c.match_id=? ORDER BY c.captured_until DESC,c.created_at DESC""",
                (match_id,),
            )]
        return [self.public_metadata(row, operator=operator, now=now) for row in rows]

    def public_metadata(
        self, row: dict[str, Any], *, operator: bool, now: float
    ) -> dict[str, Any]:
        available = row["status"] == "ready" and float(row["release_at"]) <= now
        value: dict[str, Any] = {
            "id": row["id"], "match_id": row["match_id"],
            "round_id": row.get("round_id"),
            "round": row.get("round_sequence"),
            "service_id": row.get("service_id"),
            "service": row.get("service_slug"),
            "status": "available" if available else "withheld",
            "available": available,
            "captured_from": row["captured_from"],
            "captured_until": row["captured_until"],
            "release_at": row["release_at"],
            "packet_count": row["packet_count"],
            "size_bytes": row["sanitized_size_bytes"],
            "format": "pcap",
            "privacy": "addresses-pseudonymized; credentials-and-flags-redacted",
        }
        if operator:
            value.update({
                "raw_sha256": row["raw_sha256"],
                "sanitized_sha256": row["sanitized_sha256"],
                "source_size_bytes": row["source_size_bytes"],
                "redaction_count": row["redaction_count"],
                "address_count": row["address_count"],
                "link_type": row["link_type"],
                "sanitizer_version": row["sanitizer_version"],
                "created_by": row["created_by"],
                "created_at": row["created_at"],
            })
        return value

    def download(
        self, match_id: str, capture_id: str, recipient_team_id: str, actor: str
    ) -> CaptureDownload:
        with self.db.transaction() as conn:
            now = self.db.server_time(conn)
            row = conn.execute(
                "SELECT * FROM capture_artifacts WHERE id=? AND match_id=?",
                (capture_id, match_id),
            ).fetchone()
        if not row:
            raise KeyError(capture_id)
        artifact = dict(row)
        if artifact["status"] != "ready" or float(artifact["release_at"]) > now:
            raise CaptureNotReleased(int(float(artifact["release_at"]) - now) + 1)
        data = self._read_verified(artifact)
        try:
            recipient_view = sanitize_pcap(
                data,
                secret=self.settings.pcap_watermark_secret,
                scope=f"{match_id}:recipient:{recipient_team_id}",
                maximum_packets=self.settings.pcap_max_packets,
            ).data
        except PcapPrivacyError as exc:
            raise CaptureIntegrityError(
                "stored capture could not be prepared for recipient"
            ) from exc
        marked, watermark = apply_recipient_watermark(
            recipient_view, secret=self.settings.pcap_watermark_secret,
            artifact_id=capture_id, recipient_id=recipient_team_id,
        )
        digest = hashlib.sha256(marked).hexdigest()
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO capture_releases(
                   capture_id,recipient_team_id,watermark,first_downloaded_at,
                   last_downloaded_at,download_count)
                   VALUES(?,?,?,?,?,1)
                   ON CONFLICT(capture_id,recipient_team_id) DO UPDATE SET
                   last_downloaded_at=excluded.last_downloaded_at,
                   download_count=capture_releases.download_count+1""",
                (capture_id, recipient_team_id, watermark, now, now),
            )
            count = conn.execute(
                """SELECT download_count FROM capture_releases
                   WHERE capture_id=? AND recipient_team_id=?""",
                (capture_id, recipient_team_id),
            ).fetchone()[0]
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="capture_download", result="released",
                    team_id=recipient_team_id, match_id=match_id,
                    round_id=artifact.get("round_id"), service_id=artifact.get("service_id"),
                    metadata={
                        "capture_id": capture_id, "watermark": watermark,
                        "download_sha256": digest, "download_count": count,
                    },
                    event_id=stable_id(
                        "audit", "capture-download", capture_id,
                        recipient_team_id, count,
                    ),
                ),
                conn,
            )
        return CaptureDownload(
            data=marked, filename=f"capture-{capture_id}.pcap",
            watermark=watermark, sha256=digest,
        )

    def _write_atomic(self, relative_path: str, data: bytes) -> None:
        target = self.storage / relative_path
        if target.exists():
            return
        temporary = self.storage / f".{relative_path}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _read_verified(self, artifact: dict[str, Any]) -> bytes:
        name = str(artifact["storage_name"])
        if Path(name).name != name:
            raise CaptureIntegrityError("invalid capture storage reference")
        path = self.storage / name
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CaptureIntegrityError("sanitized capture is unavailable") from exc
        if not hmac.compare_digest(
            hashlib.sha256(data).hexdigest(), str(artifact["sanitized_sha256"])
        ):
            raise CaptureIntegrityError("sanitized capture integrity check failed")
        return data
