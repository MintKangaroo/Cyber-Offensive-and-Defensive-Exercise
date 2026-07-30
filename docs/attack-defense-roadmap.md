# Attack/Defense Roadmap

The MVP deliberately leaves these next tasks in this order:

1. **PCAP anonymization and delayed delivery** — per-team address/token
   rewriting, flag scrubbing, release delay and watermarking.
   **Status: privacy primitives + operator API delivered.** `pcap_privacy.py`
   implements flag/token scrubbing, salt-based opaque team aliasing, release
   delay gating (`PCAP_RELEASE_DELAY_SECONDS`) and per-recipient watermarking,
   exposed via operator route `POST /api/attack-defense/captures/sanitize`
   (audited, reason-required). Remaining: the traffic **capture pipeline**
   (tap → structured flow records) and per-recipient delivery/storage.
2. **Kubernetes runtime** — namespaces, NetworkPolicy, resource quotas,
   readiness-gated rollout, immutable secrets and signed images.
3. **Highly available game engine** — PostgreSQL advisory locks, replicated
   workers, durable distributed rate limits and clock discipline.
4. **KOTH** — ownership leases and separate scoring strategy.
5. **Stealth Mode** — disclosure policy, delayed alerts and detection-aware
   scoring without changing base flag semantics.
6. **LiveCTF tournament** — bracket/match scheduler and tournament identities.
7. **Broadcast overlay** — production graphics output after privacy and delayed
   disclosure review.

Additional production work: microVM patch sandbox, image provenance/SBOM,
multi-variant hidden checkers, capacity testing above 12 teams, immutable audit
export, and automated disaster recovery exercises.
