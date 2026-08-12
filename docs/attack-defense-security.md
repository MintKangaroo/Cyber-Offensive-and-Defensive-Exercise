# Attack/Defense Security Review

## Implemented controls

- Signed JWT membership and role checks; no body-supplied competitor identity.
- Participant endpoints fail closed when auth is unconfigured unless the
  explicit insecure development switch is enabled.
- Flag payload length/format limits, opaque HMAC tokens, keyed lookup hashes,
  constant-time comparison, configurable active-round window and self/cross
  match rejection.
- SQLite `BEGIN IMMEDIATE` or PostgreSQL transactions plus a unique
  `(attacker_team_id, flag_id)` constraint for race-safe duplicate handling.
- Persistent flag and patch rate limits; PostgreSQL counters are atomic and
  shared by every API replica.
- PostgreSQL HA uses whole-tick session advisory locks, database wall-clock
  deadlines, portable monotonic SSE cursors, SKIP LOCKED runtime claims and
  completion fencing tokens.
- No flag plaintext in application/audit events, metrics, errors or UI payloads.
- Management calls use timestamped HMAC signatures and one-use nonces.
- Functional checker uses randomized accounts/content, shuffled checks,
  bounded timeout/retry, and a separate `checker_system_error` class.
- Patch tags resolve to digests. `latest`, foreign registry/team namespace,
  excessive size, lineage mismatch, dangerous runtime labels, obvious secret
  dumping and checker-bypass markers are rejected.
- Compose services drop all capabilities, set no-new-privileges, use read-only
  roots, bounded memory/CPU/PIDs and named volumes. No privileged, host
  namespace, host mount, or Docker socket is used.
- Application services cannot control Docker. A trusted host runner claims one
  persisted job at a time.
- The optional Kubernetes runner uses an explicit context outside the API,
  validates a fixed-kind manifest bundle, sends secrets only over stdin, pins
  images by digest and waits for Deployment readiness. Team and sandbox
  namespaces enforce restricted Pod Security, default-deny traffic, quotas,
  no service-account token, non-root/read-only containers and dropped
  capabilities.
- Operator actions require authorization and reasons and create audit evidence.
- Prometheus labels contain only bounded state; no flag, user, correlation ID,
  raw image reference or endpoint.
- PCAP evidence is sanitized in memory; raw bytes are not persisted. Match-wide
  HMAC pseudonyms replace IP/MAC addresses, recipient downloads are re-keyed to
  separate address spaces, plaintext flags and credentials are length-preserving
  redacted, and only delayed authenticated downloads are available to competitors.
- PCAP ingest is operator-only, size/packet/format/timestamp bounded and requires
  an audit reason. Downloads are Match-membership scoped, persistently rate
  limited, integrity checked, recipient-watermarked and `no-store`.

## PCAP privacy limitations

The MVP parser intentionally fails closed on PCAPNG and unsupported link types.
It cannot inspect encrypted application payloads. Fragmented or truncated
packets cannot always have transport checksums repaired, and the 32-bit
watermark can be removed. Production requires a signed capture sensor,
encrypted object storage, retention/legal-hold policy, immutable access logs,
and a reviewed packet-redaction pipeline. See
[PCAP Privacy and Delayed Delivery](attack-defense-pcap.md).

## Docker Compose limitations

Compose bridge networks cannot enforce directional egress, per-team identity,
bandwidth limits, or tournament-grade connection quotas. Services sharing the
management bridge could attempt reverse connections. Host-published game ports
also rely on host firewall policy for source controls.

The optional Kubernetes runtime implements namespace-scoped default deny and
explicit game/management ingress. Production still needs a reviewed CNI,
gateway rate/connection limits and DoS telemetry. Use
`infra/attack_defense/kubernetes/control-planes.yaml`; the legacy
single-namespace `network-policies.yaml` is documentation only.

## Kubernetes limitations

Kubernetes Secret encryption/RBAC, an API/control-plane chart, ingress, CNI,
registry and RWX storage provisioning are environment responsibilities. A
NetworkPolicy-capable CNI is mandatory; creating policy objects alone does not
prove enforcement. Digest pinning is not image signature or provenance
verification. Namespace/PVC/obsolete Secret garbage collection remains manual.
See [Kubernetes Runtime](attack-defense-kubernetes.md).

## Patch trust limitations

An OCI manifest cannot prove an image is benign, vulnerability-free, or free
from sophisticated checker fingerprinting. Before production add:

- authenticated private registry and short-lived credentials;
- signature/provenance verification (for example Sigstore);
- SBOM, malware and vulnerability scanning;
- isolated microVM/gVisor/Kata sandbox with no control-plane route;
- immutable base lineage attestation rather than a label alone;
- syscall, CPU, memory, file and network behavior monitoring;
- multiple hidden checker variants and randomized schedules.

## Production prerequisites

- Replace development secrets and reject known default values at production
  startup.
- Terminate TLS at an authenticated gateway and set explicit origins.
- Use an externally HA PostgreSQL primary/standby deployment with TLS,
  certificate verification, backups/PITR and monitored replication lag; the
  single-container Compose profile is not database HA.
- Add connection pooling and external object storage for multi-host sanitized
  capture delivery.
- Forward immutable audit logs to write-once storage/SIEM.
- Separate API, checker, injector and patch workers into distinct identities.
- Test backup restore and ledger reconciliation before each event.

## KOTH disclosure and integrity

- KOTH configuration is restricted to operators, requires a reason, and is
  accepted only while a Match is `draft` or `paused`.
- Only a valid, injected, opponent flag can acquire a hill. Self-flags,
  malformed, inactive, cross-Match and duplicate submissions never create or
  renew a lease.
- Acquisition and Attack scoring share one database transaction and Match lock,
  preventing ownership without the corresponding accepted submission.
- Participant and observer state contains the public owner, target team,
  service and remaining round count only. Tokens, hashes, source flag IDs,
  endpoints and checker evidence are operator-only.
- Reconfiguration rotates the hill activation epoch, so historical leases
  cannot silently reactivate.
- KOTH score requires the functional flag and benign workflow checks; a broken
  service cannot earn hill points solely by retaining a stale lease.

KOTH does not attempt to prove exploit diversity or attribute network traffic.
Production events should combine it with the existing submission anomaly,
rate-limit, audit and network telemetry controls.

## Stealth disclosure and evidence integrity

- Stealth configuration is operator-only, reason-required and restricted to a
  draft or paused symmetric Match.
- Accepted flag semantics and the public flag response are unchanged. Internal
  incident creation shares the same transaction, so a rejected or duplicate
  submission cannot create an alert or Stealth score.
- Participant reports require signed membership, an idempotency key, an active
  policy/round, valid own-Match service, lowercase SHA-256 and shared rate-limit
  capacity.
- The response never returns match/no-match. Audit stores that result only for
  operators, preventing evidence submission from becoming an attack oracle.
- Participant alerts are delayed beyond the detection deadline and remove the
  attacker, submission, endpoint, checker and report-match fields. Observer
  output additionally removes team attribution.
- Public scoreboard and KOTH state cannot be newer than the Stealth disclosure
  floor; immediate sensitive SSE events are suppressed for non-operators.
- Reconfiguration rotates the activation epoch. Old incidents remain immutable
  audit evidence but cannot silently reappear or score.

An indicator hash proves only that a caller supplied a digest. Production must
sign evidence at collection time, bind it to an immutable SIEM/EDR record and
provide an adjudication process for disputes and false positives.

## Tournament identity boundary

LiveCTF entry identity is stable, but Match credentials are deliberately not.
A signed `tournament_id` claim permits only the participant bracket projection;
it is insufficient for flags, patches or service state. Every fixture uses new
Match-local team/service IDs and must receive new credentials and secrets.
Public bracket output strips identity subjects, Match IDs, loser mapping,
operator reasons and runtime configuration. Operators must never reuse a
fixture volume, management secret or JWT in a later stage.

The static Compose demo cannot guarantee per-fixture tournament isolation.
Production LiveCTF play requires Kubernetes namespaces/network policy or an
equivalently isolated reviewed runtime. Automatic credential rotation,
signed team check-in and no-show controls remain production work.

## Broadcast projection boundary

The production graphics route never uses an operator or competitor token. Its
versioned public snapshot is assembled server-side from the delayed public
scoreboard, aggregate-only service status and public tournament bracket. It
does not include SSE events because even a sanitized event sequence can reveal
operational timing that is unnecessary for standings graphics. Endpoint,
runtime, checker, flag, patch, evidence, identity and referee fields are not
selected.

The endpoint sends `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
and `X-Robots-Tag: noindex, nofollow`. These headers do not replace network
policy: expose the route through the public reverse proxy only, block operator
routes from broadcast hosts, and never paste an operator token into OBS. The
visible delay marker is part of the graphic and should not be cropped. See
[Broadcast Graphics Overlay](attack-defense-broadcast.md).
