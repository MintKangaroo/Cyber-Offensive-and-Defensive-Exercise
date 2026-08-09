# Attack/Defense PCAP Privacy and Delayed Delivery

## Purpose

The capture pipeline gives competitors useful packet evidence without exposing
live flags, credentials, raw team addresses, or management-plane identifiers.
It is an analysis channel, not a packet replay or automatic exploit feed.

```text
approved capture source
  -> operator upload with audit reason
  -> in-memory validation and sanitization
  -> raw bytes discarded
  -> sanitized artifact stored in /data/captures
  -> server-time release gate
  -> recipient-specific watermark
  -> authenticated competitor download
```

The API does not capture traffic itself and never receives a Docker socket or
host network namespace. A production packet sensor or CNI flow exporter must
deliver approved captures through the operator ingest boundary.

## Privacy transformations

The `pcap-v1` sanitizer supports classic PCAP with Ethernet, raw-IP, and Linux
cooked-v1 link types. It performs the following deterministic transformations:

- all observed IPv4 and IPv6 endpoints are mapped to match-scoped HMAC
  pseudonyms for storage, then re-keyed to recipient-specific pseudonyms at
  download time;
- unicast Ethernet addresses are changed to locally administered HMAC
  pseudonyms, while broadcast/multicast semantics are preserved;
- ARP Ethernet/IPv4 addresses are rewritten;
- current and historical Match flags, generic `FLAG{...}` values, bearer
  tokens, cookies, passwords, API keys, and textual IP literals are overwritten
  without changing packet length;
- checksums are repaired for complete, unfragmented IPv4/IPv6 TCP, UDP, ICMP,
  and ICMPv6 packets;
- capture-host timezone/significant-figure fingerprint fields are cleared;
- the raw SHA-256 is retained only as operator metadata; raw bytes are never
  written to artifact storage;
- each team download receives a distinct address space plus a deterministic
  32-bit HMAC watermark in the classic-PCAP `sigfigs` field and a matching
  response header.

The watermark is leak-attribution evidence, not DRM. A recipient can remove it,
so high-stakes events should combine it with authenticated download logs and
external evidence handling.

## Configuration

| Variable | Default | Meaning |
|---|---:|---|
| `PCAP_RELEASE_DELAY_SECONDS` | `900` | Delay after the last packet timestamp |
| `PCAP_MAX_UPLOAD_MB` | `32` | Maximum operator upload size |
| `PCAP_MAX_PACKETS` | `250000` | Maximum records parsed per artifact |
| `PCAP_MAX_DOWNLOADS_PER_MINUTE` | `10` | Persistent per-team download limit |
| `PCAP_MAX_FUTURE_SKEW_SECONDS` | `300` | Allowed future capture timestamp skew |
| `PCAP_STORAGE_DIR` | `<A/D data>/captures` | Sanitized artifact directory |
| `PCAP_ANONYMIZATION_SECRET` | development value | Match-scoped address pseudonym key |
| `PCAP_WATERMARK_SECRET` | development value | Recipient watermark key |

The two secrets must be non-empty and different. Rotate them between events,
not during an active event: rotation changes pseudonyms and download marks.
A Match can override `pcap_release_delay_seconds` in its configuration; the
server clamps it to a maximum of 30 days.

## Operator workflow

Upload an approved classic-PCAP artifact. The timestamp used for release is
derived from the packet records rather than a caller-supplied time.

```bash
export INSTRUCTOR_TOKEN=dev-instructor-token

python3 -m services.attack_defense.cli ad capture-upload \
  ad-demo ./round-042.pcap \
  --reason "round 42 post-round evidence"

python3 -m services.attack_defense.cli ad capture-list ad-demo
```

Optional `--round-id` and `--service-id` values must belong to the Match. The
same capture uploaded again is idempotent and returns the same artifact ID.

Equivalent API call:

```bash
curl --fail-with-body \
  -X POST http://localhost:8100/api/attack-defense/operator/matches/ad-demo/captures \
  -H "Authorization: Bearer ${INSTRUCTOR_TOKEN}" \
  -H 'Content-Type: application/vnd.tcpdump.pcap' \
  -H 'X-Operation-Reason: round 42 post-round evidence' \
  --data-binary @round-042.pcap
```

## Competitor workflow

The Live Fire **Captures** screen shows `WITHHELD` until server time reaches the
release time. Available files can be downloaded from the screen, or with the
CLI after exporting a signed competitor access token:

```bash
export ATTACK_DEFENSE_COMPETITOR_TOKEN='<access_token>'

python3 -m services.attack_defense.cli ad capture-download \
  ad-demo '<capture-id>' ./evidence/round-042.pcap
```

The download response uses `Cache-Control: private, no-store` and supplies
`X-Capture-SHA256` plus `X-Capture-Watermark`. Before release the API returns
HTTP `425 Too Early`; cross-Match membership and observer access are rejected.

## Evidence and metrics

`capture_ingest` and `capture_download` are append-only audit event types. Their
metadata contains IDs, hashes, counts, operator reason, recipient team, and
watermark—but never packet payloads or plaintext flags. Per-recipient first and
last download time plus download count are persisted in `capture_releases`.

Prometheus exports:

- `attack_defense_capture_ingest_total`
- `attack_defense_capture_download_total`
- `attack_defense_capture_sanitizer_rejected_total`

No capture hash, path, team, recipient, watermark, or correlation ID is used as
a metric label.

## MVP limits and next work

- PCAPNG, radiotap, Linux cooked-v2, reassembly, and encrypted payload
  inspection are not implemented. Unsupported formats fail closed.
- Fragmented or snaplen-truncated packets are useful for analysis after address
  rewriting but are not guaranteed to be replayable.
- Automatic TAP/CNI capture, sensor signing, object-store encryption, retention
  deletion, legal hold, and WORM export remain production work.
- The watermark is deliberately lightweight and removable.
- TLS and an authenticated gateway are mandatory outside a local demo.
