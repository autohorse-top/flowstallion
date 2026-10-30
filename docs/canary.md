# K8s Release Strategies (CD)

FlowStallion's CD engine drives Kubernetes releases with a pluggable
**release strategy** (`pkg/cd.Strategy`). Both strategies share the same
state machine and controller:

| Strategy | `strategy` value | Alt object name | Alt replicas | Traffic switch |
|----------|------------------|-----------------|--------------|----------------|
| Isolated canary (default) | `canary` | `<name>-canary` | 1 | stable Service selector → `release=canary` |
| Blue-green | `blue_green` | `<name>-alt` | same as stable (N) | stable Service selector → `release=blue_green` |

Strategy interface (`pkg/cd/strategy.go`): `ID()`, `AltName(base)`,
`AltReplicas(full)`; unknown/empty values always fall back to `canary`.
Manifest rendering (`RenderReleaseManifests` / `RenderSwitchService`) and
the controller (each state-machine phase) resolve the strategy per
release from the `strategy` column persisted on the release row, so
canary and blue-green releases can coexist in the same cluster.

## Topology (canary strategy)

```
                  ┌────────────────────────────┐
                  │  stable Service `demoapp`  │
                  └────────────────────────────┘
       selector: release=stable              release=canary
                  │                            │
       ┌──────────▼──────────┐      ┌──────────▼──────────┐
       │ Deployment `demoapp`│      │ Deployment `demoapp- │
       │  (N replicas, v1)   │      │  canary` (1 rep, v2) │
       └─────────────────────┘      └──────────┬──────────┘
                                               │
                              ┌────────────────▼──────────┐
                              │ canary Service `demoapp-   │
                              │ canary` (probing only)     │
                              └────────────────────────────┘
```

- **promote** (two-phase; the intermediate `promoting` state guarantees
  idempotent replay, m-5):
  1. switch the stable Service selector to `release=canary` (instant
     traffic cutover);
  2. scale the canary Deployment to N and delete the stable Deployment.
     If either step keeps failing 3 times in a row → `failed`; if the
     selector has already been cut to canary (F-1), the controller
     best-effort re-applies the stable Service to cut the selector back
     to `release=stable` before failing, so the cluster is never left
     half-promoted. A mid-flight crash is replayed from `promoting` on
     the next tick.
- **rollback**: delete the canary Deployment + canary Service; stable was
  never touched, so traffic is unaffected.

### Blue-green topology (blue_green strategy)

The alt Deployment `<name>-alt` is deployed first with **full N
replicas** (ready before traffic cut), and the probe Service
`<name>-alt` is used for health probing only. Promote is the same
two-phase flow: cut the stable Service selector to `release=blue_green`,
then scale the alt to N (idempotent; it is already N) and delete the
stable Deployment; rollback deletes `<name>-alt` and its Service;
stable is untouched throughout.

## State Machine (`pkg/cd`)

```
pending → applying → canary_ready → observing → promoting → promoted
                    ↘ failed / rolled_back (any non-terminal state can enter these)
```

Both strategies share this state machine; "canary" in the table below
stands for **the strategy's alternate object** (canary strategy:
`<name>-canary`, 1 replica; blue_green strategy: `<name>-alt`, N
replicas).

| State | Drive condition |
|-------|-----------------|
| `pending` | enqueued on creation; next tick `kubectl apply`s all manifests (Namespace/Deployment×2/Service×2). 3 consecutive apply failures → `failed` (no canary to roll back yet) |
| `applying` | `get deploy <name>-canary` shows readyReplicas ≥ 1 → record the `canary_start` timestamp and reset the baseline; 3 consecutive probe failures → rollback. **applying timeout (B-1)**: stamp `applying_since` on entering applying; if the canary is still not ready after `ApplyTimeout` (default 5 minutes) → rollback (a crash-looping image must not occupy the (name, namespace) slot forever); if the stamp is missing (process crashed before stamping / old DB row), the first tick backfills it |
| `canary_ready` | immediately transitions to `observing` |
| `observing` | every tick: ① re-check canary readiness (not ready after warmup → counts toward probe-failure count; 3 consecutive to trigger rollback, F-2; not ready within warmup is only logged) ② scrape the app's built-in `/metrics` via `kubectl get --raw .../services/<name>-canary:<port>/proxy/metrics` (JSON: cumulative `requests`/`errors` counters + `scrapes` probe count) ③ **baseline-window error rate** (m-3): take the first successful scrape after canary_ready as the baseline (auto re-anchoring when pod restarts reset counters); compute the error rate from window deltas `Δrequests/Δerrors`; `Δerrors/Δrequests > threshold` and `Δrequests ≥ min_samples` → immediate rollback; ④ age ≥ `warmup_s + observe_s` and healthy → `promoting` |
| `promoting` | idempotent replay (m-5): first cut the stable Service selector to `release=canary`, then `scale` the canary to N and `delete` the stable Deployment; delete tolerates NotFound. 3 consecutive failures → if the selector was already cut to canary, first best-effort restore the stable Service (F-1), then → `failed`; success → `promoted` |
| terminal | `promoted` / `rolled_back` / `failed`; no further kubectl calls |

- Probe failures (kubectl error / unparseable JSON / API server returns
  cluster Status) only terminate the release after `3` consecutive
  occurrences: during `applying`/`observing` → rollback; during
  `pending` (apply) and `promoting` (scale/delete) → failed
  (traffic may already be switched; do not roll back, human
  intervention required). A single blip does not kill the release.
- Low-traffic protection: when the window expires but in-window samples
  have `Δrequests < min_samples`, it still promotes (a healthy canary
  should not be blocked forever for lack of traffic).
- **Error rate computed over the baseline window (m-3)**: the baseline is
  the first successful scrape after canary readiness; the error rate is
  computed from in-window deltas, so pre-release historical traffic does
  not dilute a bad version's error rate.
- **kubectl calls carry a 30s timeout** (m-2): a hung API server cannot
  stall the whole tick.
- **Image reference allowlist validation (M-1)**: `stable_image` /
  `canary_image` must match the Docker image reference regex; all
  manifests are rendered via `yaml.Marshal`, so user input cannot inject
  extra documents or keys.
- **Object-name conflict check (m-1)**: if the new release's name
  collides with any active release's object names in the same namespace
  (`X` / strategy-suffixed object `X-canary` or `X-alt`) → 409.
- **Promoted-residue name conflict (F-3)**: if the new release's name
  collides with any promoted release's object names in the same
  namespace (`<name>` / `<name>-canary` / `<name>-alt`) → 409, preventing
  `kubectl apply` from silently taking over a production
  Deployment/Service.

## API (scheduler process, default :8090)

```
POST /api/canaries          create a release (validates K8s naming + parameter ranges)
GET  /api/canaries          list
GET  /api/canaries/{id}     details + event stream (canary_events)
```

Create request body (omitted numeric fields take defaults; explicitly
passing invalid values → 400 + `problems` list):

```json
{
  "name": "demoapp",              // required, RFC-1123, <=63
  "namespace": "flowstallion-cd-demo",      // optional, default "flowstallion"
  "stable_image": "reg/app:v1",   // required
  "canary_image": "reg/app:v2",   // required (release target image; for blue_green this is the alt image)
  "strategy": "canary",           // optional, "canary" (default) | "blue_green"
  "replicas": 2,                  // default 2, range 1..100
  "port": 8080,                   // default 8080, range 1..65535
  "threshold": 0.3,               // default 0.3, range (0,1]
  "min_samples": 20,              // default 20, >=1
  "warmup_s": 10,                 // default 10, >0
  "observe_s": 20                 // default 20, >0
}
```

`stable_image` / `canary_image` must pass the Docker image reference
regex validation (M-1; rejects newlines / comment markers / spaces and
other injection vectors).

Concurrent creation of an active release with the same name → `409`
(dual protection: API precheck + database partial unique index
`idx_canary_active`, M-2). Object-name conflict (`X` vs an already
active `X-canary` / `X-alt`, suffix depends on strategy) → `409` (m-1).

## Events

Every state transition and every observation tick writes to
`canary_events` (`detail` is JSON): `apply` output, `waiting-ready`,
`ready`, `observe-start`, `observing` (with `age_s`/`requests`/`errors`/
`window_requests`/`window_errors`/`err_rate`/`version`), per-phase
`-probe-failed` events (with `probe` and `consecutive`),
`promote-start`, `promote`, `rollback` (with reason), `failed` (with
reason). `GET /api/canaries/{id}` returns at most the last 500 events.

## Demo (kind cluster)

```bash
# 1. Build the three demoapp images
docker build -f demo/Dockerfile.demoapp --build-arg VERSION=v1 --build-arg FAIL_RATE=0   -t flowstallion/demoapp:v1 .
docker build -f demo/Dockerfile.demoapp --build-arg VERSION=v2 --build-arg FAIL_RATE=0.8 -t flowstallion/demoapp:v2 .
docker build -f demo/Dockerfile.demoapp --build-arg VERSION=v3 --build-arg FAIL_RATE=0   -t flowstallion/demoapp:v3 .
kind load docker-image flowstallion/demoapp:v1 flowstallion/demoapp:v2 flowstallion/demoapp:v3 --name flowstallion

# 2. Start the scheduler (host process, standalone DB, :8090)
go build -o /tmp/flowstallion-cd/scheduler ./cmd/scheduler
FLOWSTALLION_DB=/tmp/flowstallion-cd/flowstallion.db FLOWSTALLION_ADDR=:8090 /tmp/flowstallion-cd/scheduler &

# 3. Scenario A: bad version v2 (80% failing) → automatic rollback
curl -s -X POST localhost:8090/api/canaries -H 'Content-Type: application/json' \
  -d '{"name":"demoapp","namespace":"flowstallion-cd-demo","stable_image":"flowstallion/demoapp:v1",
       "canary_image":"flowstallion/demoapp:v2","replicas":2,"port":8080,
       "threshold":0.3,"min_samples":5,"warmup_s":5,"observe_s":20}'
# Real traffic must hit the canary Service during the window (this demo
# uses notes/traffic_gen.sh via kubectl service-proxy to hit / and
# /version); error rate in the observation window exceeds the threshold
# → rolled_back

# 4. Scenario B: healthy version v3 → promote at window expiry
#    (same params, canary_image switched to flowstallion/demoapp:v3)
#    After promote: stable Service selector = release=canary,
#    canary Deployment scaled to N, stable Deployment deleted

# Verify final state
kubectl get deploy,svc,pods -n flowstallion-cd-demo
kubectl get svc demoapp -n flowstallion-cd-demo -o jsonpath='{.spec.selector}'
```

Demo scripts and evidence live in OpenDevTeam `.tasks/flowstallion/notes/`
(`traffic_gen.sh`, `canary1-rollback.json`, `canary2-promote.json`,
`canary1-k8s-state.txt`, `canary2-k8s-state.txt`,
`e2e-rerun2-scenarioA-rollback.json`, `e2e-rerun2-scenarioB-promote.json`,
`f3-live-409.json`).
