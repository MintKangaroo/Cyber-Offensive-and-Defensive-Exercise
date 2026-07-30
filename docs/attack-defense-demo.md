# Local Attack/Defense Demo

## Start

```bash
cd cyber-range-platform
make attack-defense-demo
```

This starts the API, local registry and six hardened instances:

| Team | Vulnerable Notes | File Vault |
|---|---:|---:|
| Team 01 | `http://localhost:9101` | `http://localhost:9201` |
| Team 02 | `http://localhost:9102` | `http://localhost:9202` |
| Team 03 | `http://localhost:9103` | `http://localhost:9203` |

Demo accounts:

| User | Password | Team |
|---|---|---|
| `instructor` | `demo-operator-change-me` | operator |
| `team01` | `demo-team-01-change-me` | Team 01 |
| `team02` | `demo-team-02-change-me` | Team 02 |
| `team03` | `demo-team-03-change-me` | Team 03 |

These defaults are local-only and must be changed before any shared deployment.

Open the Live Fire UI:

```bash
cd dashboards/livefire
npm install
npm run dev
```

Select Attack/Defense mode and sign in. The UI defaults to observer-safe data
when no token is present.

## API token and CLI

```bash
curl -s http://localhost:8051/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"team01","password":"demo-team-01-change-me"}'

export ATTACK_DEFENSE_COMPETITOR_TOKEN='<access_token>'
python3 -m services.attack_defense.cli ad round-status ad-demo
python3 -m services.attack_defense.cli ad flag-submit ad-demo 'FLAG{...}'
```

The demo does not ship or automatically execute an exploit. Vulnerability
behavior and expected patches are documented inside each service directory.

## Patch example

Resolve the approved base ID, then build and push a team-namespaced image with
a non-`latest` tag and lineage declaration:

```bash
BASE_DIGEST="$(docker image inspect --format='{{.Id}}' cyber-range/ad-vulnerable-notes:base)"
docker build -t localhost:5000/team-01/vulnerable-notes:patch-001 \
  --build-arg "CYBER_RANGE_BASE_DIGEST=${BASE_DIGEST}" \
  --build-arg PATCH_IDOR=true \
  -f services/attack_defense/demo_services/vulnerable_notes/Dockerfile .
docker push localhost:5000/team-01/vulnerable-notes:patch-001
```

The API allowlist defaults to `registry.local:5000`, so use that reference in
the submission. Policy inspection starts after the `202` response. Then run
`make attack-defense-runtime-work` for each queued sandbox/deploy operation.
The trusted runner maps the control-plane registry alias to the host registry
without exposing the Docker socket to the API.

## Tests

```bash
make attack-defense-test
cd dashboards/livefire && npm test && npm run build
```
