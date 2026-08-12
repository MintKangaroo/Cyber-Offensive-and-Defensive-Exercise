# Attack/Defense Roadmap

The MVP deliberately leaves these next tasks in this order:

1. **PCAP anonymization and delayed delivery — MVP complete** — classic-PCAP
   address pseudonymization, flag/credential scrubbing, raw-byte discard,
   server-time release gating, recipient watermarking, audit, CLI/API and Live
   Fire delivery are implemented. Production TAP/CNI ingestion, PCAPNG,
   encrypted object storage and retention/legal-hold policy remain.
2. **Kubernetes runtime — MVP complete** — deterministic team/sandbox
   namespaces, validated deny-by-default NetworkPolicy, quotas/limits,
   restricted Pod Security, immutable derived management secrets,
   digest-pinned readiness-gated rollout, audited reconciliation and rollback
   worker are implemented. Production control-plane chart, CNI/gateway limits,
   Secret encryption/RBAC, RWX provisioning, admission policy and signed image
   provenance remain.
3. **Highly available game engine — MVP complete** — optional shared
   PostgreSQL persistence, whole-tick session advisory locks, replicated
   workers, database-clock rate limits, readiness/skew gate, portable audit SSE
   sequence, SKIP LOCKED runtime claims and completion fencing are implemented.
   Production PostgreSQL HA/PITR, connection pooling, multi-node capture object
   storage, TLS ingress and infrastructure failure drills remain.
4. **KOTH — MVP complete** — opt-in flag-backed ownership leases for symmetric
   team/service hills, atomic capture/transfer, functionality-gated round
   scoring, deterministic recalculation, operator/public API, CLI, metrics and
   Live Fire ownership board are implemented. Shared neutral hills,
   continuous-time accrual and persistence-agent proof remain.
5. **Stealth Mode — MVP complete** — opt-in delayed incident disclosure,
   pre-disclosure hashed defender evidence, non-oracular report responses,
   independent Stealth Attack/Detection ledger categories, scoreboard/KOTH
   visibility floor, operator/participant/observer API, CLI, metrics and Live
   Fire board are implemented. Signed external evidence, semantic SIEM rule
   evaluation and automatic false-positive adjudication remain.
6. **LiveCTF tournament — MVP complete** — deterministic 2/4/8/16-team
   single-elimination bracket, stable tournament entries, isolated fixture
   Match/team/service materialization, restart reconciliation, scoreboard and
   referee tie-break advancement, operator/participant/public API, CLI,
   metrics, audit and role-safe Live Fire bracket are implemented. Automatic
   time slots, byes/pools/double elimination, credential rotation and dynamic
   Compose projects remain.
7. **Broadcast overlay — MVP complete** — standalone OBS/browser-source
   scorebar, standings and LiveCTF bracket layouts, alpha/solid/chroma
   backgrounds, server-time countdown, bounded refresh, stale state and a
   versioned public-only snapshot API are implemented. The projection reuses
   the delayed scoreboard floor and aggregate service/public tournament views,
   excludes events and sensitive operational fields, and is covered by
   privacy plus 1920×1080 RGBA visual tests. NDI/SDI fill-and-key, sponsor CMS,
   animated transitions and a multi-Match director console remain.

Additional production work: microVM patch sandbox, image provenance/SBOM,
multi-variant hidden checkers, capacity testing above 12 teams, immutable audit
export, and automated disaster recovery exercises.
