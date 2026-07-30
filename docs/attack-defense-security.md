# Attack/Defense Security Review

## Implemented controls

- Signed JWT membership and role checks; no body-supplied competitor identity.
- Participant endpoints fail closed when auth is unconfigured unless the
  explicit insecure development switch is enabled.
- Flag payload length/format limits, opaque HMAC tokens, keyed lookup hashes,
  constant-time comparison, configurable active-round window and self/cross
  match rejection.
- `BEGIN IMMEDIATE` plus a unique `(attacker_team_id, flag_id)` constraint for
  race-safe duplicate handling.
- Persistent flag and patch rate limits.
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
- Operator actions require authorization and reasons and create audit evidence.
- Prometheus labels contain only bounded state; no flag, user, correlation ID,
  raw image reference or endpoint.

## Docker Compose limitations

Compose bridge networks cannot enforce directional egress, per-team identity,
bandwidth limits, or tournament-grade connection quotas. Services sharing the
management bridge could attempt reverse connections. Host-published game ports
also rely on host firewall policy for source controls.

Production must use Kubernetes/Nomad plus CNI policy, separate checker and API
workloads, deny-by-default egress, rate/connection limits and DoS telemetry.
`infra/attack_defense/network-policies.yaml` is a starting example, not a
complete deployment.

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
- Replace SQLite with PostgreSQL and advisory locks for multi-host HA.
- Use Redis or gateway-level distributed rate limiting.
- Forward immutable audit logs to write-once storage/SIEM.
- Separate API, checker, injector and patch workers into distinct identities.
- Test backup restore and ledger reconciliation before each event.
