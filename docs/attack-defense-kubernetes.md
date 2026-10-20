# Attack/Defense Kubernetes Runtime

## Scope

The Kubernetes adapter is a trusted host-side runtime for symmetric team
services and patch sandboxes. The Attack/Defense API never receives a
kubeconfig, service-account token or Docker socket. It persists desired state
and runtime jobs; an operator invokes the CLI with an explicit context.

This is an optional runtime. `exercise` and the default Compose
`attack_defense`/`hybrid_live_fire` paths are unchanged.

## Security model

For every live team the adapter creates a namespace with:

- Pod Security Admission `restricted` enforce/audit/warn labels;
- a default-deny ingress and egress NetworkPolicy;
- only game-plane ingress to the public service port;
- only labelled management workloads to game and management ports;
- ResourceQuota, LimitRange, a service account with token automount disabled;
- digest-pinned images, non-root UID/GID, RuntimeDefault seccomp, read-only root
  filesystem, all capabilities dropped and privilege escalation disabled;
- readiness/startup/liveness probes, resource requests/limits and a ClusterIP
  Service;
- a per-service immutable management Secret derived from the configured master
  without storing plaintext in the Attack/Defense database.

Each patch candidate gets a separate namespace, `emptyDir` storage and no game
ingress. The candidate becomes live only after the sandbox checker succeeds.
Live replacement uses a rolling Deployment with `maxUnavailable: 0`,
`maxSurge: 1`, waits for rollout readiness and preserves the previous digest
for rollback.

The manifest validator rejects hostPath, privileged containers, host
network/PID/IPC, plaintext management environment values, mutable tags,
non-ClusterIP Services, missing default-deny policy, missing limits and unsafe
rollout strategy before invoking `kubectl`.

## Prerequisites

1. Kubernetes with a CNI that enforces `networking.k8s.io/v1` NetworkPolicy.
2. A registry reachable by every node. Base and patch images must be available
   by digest in `KUBERNETES_IMAGE_REGISTRY`.
3. A storage class supporting `ReadWriteMany`. Atomic surge rollout is rejected
   for a `ReadWriteOnce` PVC in this MVP.
4. `kubectl` on the trusted operator host and an explicitly named context.
5. API/checker/flag-injector workloads connected to the `ad-management` plane
   and able to resolve/reach cluster `.svc` addresses. The repository does not
   install a production ingress, database or API control-plane chart.
6. Labels on management pods:
   `ad.cyber-range/component=api|checker|flag-injector`.

Apply the prerequisite plane policy after reviewing namespace names, ports and
DNS labels for the target CNI:

```bash
kubectl --context "$KUBERNETES_CONTEXT" apply \
  -f infra/attack_defense/kubernetes/control-planes.yaml
```

## Configuration

Copy `.env.example` and set at minimum:

```dotenv
GAME_RUNTIME=kubernetes
KUBERNETES_CONTEXT=range-production
KUBERNETES_KUBECONFIG=/secure/operator/range.kubeconfig
KUBERNETES_IMAGE_REGISTRY=registry.range.internal:5000
KUBERNETES_STORAGE_CLASS=cephfs
KUBERNETES_PVC_ACCESS_MODE=ReadWriteMany
ATTACK_DEFENSE_MANAGEMENT_TOKEN=<unique-high-entropy-master>
```

The kubeconfig is read only by the host CLI. Do not mount it into the API
container. The management master must match the API/checker configuration but
must not appear in manifests, logs or shell arguments; only derived
namespace-local values are sent to the Kubernetes Secret API over stdin.

## Reconcile live services

First preview all resources. Dry-run performs local build and policy validation
and does not claim runtime jobs or update API state:

```bash
python3 -m services.attack_defense.cli ad runtime-reconcile ad-demo \
  --runtime kubernetes \
  --kube-context "$KUBERNETES_CONTEXT"
```

After reviewing the context and output, apply and wait for every Deployment:

```bash
python3 -m services.attack_defense.cli ad runtime-reconcile ad-demo \
  --runtime kubernetes \
  --kube-context "$KUBERNETES_CONTEXT" \
  --apply-kubernetes \
  --reason "initial tournament service deployment"
```

Successful results update runtime ID, endpoints, digest and status through the
operator-only audited `runtime-result` API.

## Patch worker

Run once per pending sandbox/deploy/restart/rollback job, or schedule it as a
locked host service:

```bash
python3 -m services.attack_defense.cli ad runtime-work \
  --runtime kubernetes \
  --kube-context "$KUBERNETES_CONTEXT" \
  --apply-kubernetes \
  --runner-id k8s-runner-01
```

`runtime-work` refuses to claim a Kubernetes job without
`--apply-kubernetes`. A failed rollout is reported to the durable job handler,
which keeps the old live revision or queues rollback according to the patch
state machine.

## Recovery and teardown

Re-running `runtime-reconcile` is idempotent: names are deterministic and
server-side apply uses the configured field manager. Use `runtime-work` after a
worker restart; stale running jobs become reclaimable after the configured
timeout.

No broad namespace deletion command is provided. Capture evidence, score and
audit state first, resolve exact `ad-...` namespaces with `kubectl get ns`, and
follow the event retention policy. `stop()` scales only the selected
Deployment to zero.

## Verified local run (kind)

The hardened manifests have been run end-to-end on a real single-node
[`kind`](https://kind.sigs.k8s.io/) cluster (k8s v1.31) — pods actually reach
`Running`, not just admitted. This is the reproducible procedure; it exercises
the real `KubernetesRuntime.deploy()` path (not the `gen_ad_teams.py --k8s`
template, which pins a placeholder digest for structural validation only).

1. **Registry reachable by digest.** `kind` nodes cannot see the host Docker
   image store, so the digest-pin contract needs a registry both the host (push)
   and the nodes (pull) can reach. Run a local `registry:2`, create the cluster
   with a containerd `config_path`, and add a `hosts.toml` mapping
   `localhost:5001 → http://kind-registry:5000` on each node (the upstream
   kind "local registry" recipe). Build the three demo-service images, push them,
   and capture their real `RepoDigests`.
2. **RWX storage is mandatory** (prerequisite #3). The default kind storage
   class `standard` (`rancher.io/local-path`) is `ReadWriteOnce` only, so a live
   team PVC stays `Pending` with
   `ProvisioningFailed: ... Only support ReadWriteOnce access mode` and the pod
   never schedules. This is expected: the surge rollout (`maxSurge: 1`) briefly
   co-mounts `/data`, so the contract requires `ReadWriteMany`. Install an
   RWX provider (e.g. the sig-storage NFS-ganesha external provisioner, which
   serves an in-cluster `nfs` StorageClass) rather than relaxing the contract.
3. **Deploy** with `KubernetesRuntimeConfig(image_registry=<registry>,
   allowed_registry=<registry>, storage_class="nfs", dry_run=False,
   context="kind-...")` and call `runtime.deploy(instance)` per team×service,
   with each `instance["image_reference"]` set to the pushed `repo@sha256:...`.

**Observed result** (2 teams × 3 services = 6 pods): every Deployment rolled out
to `1/1 Running`; each PVC `Bound` as `RWX` on the `nfs` class; images pulled by
digest from the local registry; per-namespace `default-deny-all` +
game/management-ingress NetworkPolicies, `ResourceQuota` (live `pods: 3/12`) and
`LimitRange` admitted; `/health` on the game port (9000) served through a
port-forward. Note that kind's default CNI (`kindnet`) admits but does **not
enforce** NetworkPolicy — policy *enforcement* still needs a policy-capable CNI
(prerequisite #1), so this run verifies pod runtime and manifest acceptance, not
network isolation.

## Current limitations

- The adapter does not install the API/control-plane workload, ingress, HA
  database, registry, CNI or RWX storage provider.
- Image digest and registry are enforced, but signature/provenance/SBOM
  verification and admission policy require an external policy controller.
- Namespace/PVC/obsolete Secret garbage collection is manual and intentionally
  conservative.
- NetworkPolicy does not provide bandwidth quotas, L7 filtering or packet
  capture; configure those in the selected CNI/gateway.
- The SQLite game engine remains single-host. Kubernetes service placement does
  not make the game engine highly available.
- Secrets are Kubernetes Secret objects; production requires encryption at
  rest and narrow RBAC for Secret reads.
