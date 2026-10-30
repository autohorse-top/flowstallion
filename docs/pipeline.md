# FlowStallion Pipeline Quick Reference (P7)

This document is a quick reference for the P7 pipeline capabilities:
triggers, docker_build, CD steps (k8s_canary / k8s_blue_green),
notifications, AI wiring, ops CLI, and log retention. For full design,
see the dedicated docs ([canary.md](canary.md), [finops.md](finops.md),
[security.md](security.md)).

## Triggers

`trigger` is a list of rules; multiple rules can coexist. Each rule has
`event` ∈ `manual | push | pull_request | schedule` and an optional
`branches` filter (each entry ≤ 200 chars).

```yaml
version: 1
pipeline:
  name: mypipe
  trigger:
    - event: manual
    - event: push
      branches: [main, release/*]
    - event: pull_request
    - event: schedule
      cron: "0 2 * * *"
  steps:
    - id: build
      image: alpine
      commands:
        - echo hi
```

- **manual**: `POST /api/pipelines/{name}/trigger` or
  `flowstallion trigger <name>`.
- **push / pull_request**: driven by SCM webhooks. All three endpoints
  share the same secret `FLOWSTALLION_WEBHOOK_SECRET` (503 fail-closed when
  unset) and the same response contract (`200 triggered:false` no match /
  `409` concurrency limit reached / `202 run_id` enqueued):
  - GitHub: `POST /api/webhooks/github`, `X-GitHub-Event` +
    `X-Hub-Signature-256` (HMAC-SHA256).
  - Gitea (P8, self-hosted): `POST /api/webhooks/gitea`,
    `X-Gitea-Event` (`ping`/`push`/`pull_request`); payload shape is
    identical to GitHub; auth prefers `X-Gitea-Signature`
    (HMAC-SHA256), falls back to plaintext `X-Gitea-Token` when absent;
    both missing → 403.
  - GitLab (P8, self-hosted): `POST /api/webhooks/gitlab`,
    `X-Gitlab-Event` (`Ping Event`/`Push Hook`/`Merge Request Hook`) +
    plaintext `X-Gitlab-Token`; `object_kind` is cross-checked against
    the event header to prevent mismatched hooks; Merge Request hooks are
    normalized to a `pull_request` trigger (`open`/`update`/`reopen`),
    and run metadata is taken from `iid` / `source_branch` /
    `target_branch` / `project.web_url` / `source_sha`.
  - `push` events: the run's `sha` comes from the push's `after`.
  - `pull_request` events (P7②): only `opened`/`synchronize`/`reopened`
    trigger; the run carries PR metadata `pr` / `base_ref` / `head_ref` /
    `repo_url`, with `sha` taken from the PR head. Note: `branches` in
    trigger rules matches the PR's **head (source) branch**, not the base
    (target) branch.
- **schedule**: five-field cron (`min hour day month weekday`); `@`
  macros and month/weekday names are not supported; length ≤ 64. The
  persisted watermark (`schedule_state` table) guarantees that after a
  shutdown spanning multiple cron slots, catch-up fires exactly once
  (catch-up once), never repeatedly.

## docker_build step (P7④)

Builds (optionally pushes) an image with the Docker daemon on the agent
host; it does not run inside a container:

```yaml
  steps:
    - id: build-image
      type: docker_build
      image: localhost:5000/app:{{sha}}      # target image; {{sha}}/{{branch}}/{{ts}} templates allowed
      dockerfile: Dockerfile                  # optional, default "Dockerfile"
      context: .                              # optional, default the agent's cwd
      push: true                              # optional, default false
```

- `commands` is **disabled** on docker_build steps (422).
- Template placeholders are limited to `{{sha}}` / `{{branch}}` /
  `{{ts}}`, expanded before dispatch; illegal branch characters are
  sanitized to `-`, empty values fall back to `unknown`.
- Step outputs (e.g. `image_ref`) are written back to the run's steps and
  readable via the run detail API and `flowstallion status`.

## CD steps: k8s_canary / k8s_blue_green (P7⑤)

A CD release as a DAG node, **executed on the scheduler** (not
dispatched to agents). Both release strategies share the same state
machine and step fields; only `type` differs:

| type | strategy | alt object name | alt replicas |
|------|----------|-----------------|--------------|
| `k8s_canary` (default) | isolated canary | `<deployment>-canary` | 1 |
| `k8s_blue_green` | blue-green | `<deployment>-alt` | same as stable (N) |

```yaml
  steps:
    - id: echo
      image: alpine
      commands:
        - echo built
    - id: deploy
      type: k8s_canary            # or k8s_blue_green
      needs: [echo]
      image: "localhost:5000/app:2.0"   # release target image; stable image and replica count N are auto-taken from the cluster's existing stable deployment
      k8s_context: e2e                   # optional; every kubectl call gets --context
      namespace: default
      deployment: goodapp
      canary:
        weight: 10                        # 1..100, default 10 (informational in v1, no traffic splitting)
        probe_failures: 3                 # 0 → pkg/cd default
        timeout: 300                      # seconds; 0 → default (applying-phase timeout)
```

- Object-name length precheck: `<deployment> + strategy suffix`
  (`-canary` 7 chars / `-alt` 4 chars) must not exceed the K8s
  63-char object-name limit; rejected at parse time (`deployment too
  long for <type>: ... + suffix = N chars, exceeds K8s 63-char
  object-name limit`).
- State machine (`pkg/cd`):
  `pending → applying → canary_ready → observing → promoting → promoted`,
  any non-terminal state can transition to `failed` / `rolled_back`.
  Topology: k8s_canary is a 1-replica canary Deployment `<name>-canary`
  + probe Service; k8s_blue_green is a full-N-replica alt Deployment
  `<name>-alt` + probe Service; promote cuts the stable Service
  selector and deletes the old Deployment — see
  [canary.md](canary.md) for details.
- Automatic rollback on failure: consecutive probe failures, observation
  window error rate above threshold, applying timeout, ctx cancellation.
- On step success (promoted), outputs `canary_release_id` /
  `canary_state` / `stable_image` / `canary_weight`; on failure
  (rolled_back etc.) → run failed.
- Manual rollback: `flowstallion canary <run-id> rollback [--reason ...]`, or
  `POST /api/canaries/{id}/rollback` (operator and above; terminal
  state → 409).
- Runtime env: `FLOWSTALLION_KUBECTL_BIN` (default `kubectl`).

## Notifications (P7⑦)

```yaml
pipeline:
  notifications:
    - type: webhook
      url: https://hooks.example.com/flowstallion
```

- Currently the `type` closed set contains only `webhook` (Slack
  incoming-webhook-compatible JSON POST); ≤ 10 entries, URL must be
  http(s) and ≤ 2048 chars.
- Trigger points: run terminal states (`success` / `failed` / `canceled`)
  and canary rollback (`rolled_back`).
- Payload fields: `pipeline` / `run_id` / `status` / `pr` / `url` (run
  page; omitted when empty) / `finished_at` (omitted when null).
- Fire-and-forget: send failures only log; never affect run state. The
  console base URL can be set via `FLOWSTALLION_WEB_BASE_URL` (derived from
  the listen address when unset).

## AI wiring (P7⑥)

After a PR-triggered run reaches a terminal state, the Python-side watch
loop (`python -m flowstallion_agent.watch`, enabled by default) writes back
two kinds of run-level analyses
(`POST /api/runs/{id}/analysis`, `X-Agent-Token`):

- **pr_review**: GitHub diff rule checks + optional LLM review; with
  `FLOWSTALLION_GITHUB_TOKEN` set, the verdict is additionally posted back
  as a GitHub PR review (high-severity rule hits force REQUEST_CHANGES).
- **test_selection**: changed files → affected-tests mapping, stored as
  an analysis for the pipeline to consume (see the README's
  `FLOWSTALLION_TEST_PATTERN` section for the convention).

Related env vars: `FLOWSTALLION_AGENT_TOKEN`, `FLOWSTALLION_GITHUB_TOKEN`
(optional), `FLOWSTALLION_GITHUB_API` (default api.github.com),
`FLOWSTALLION_REPO_ROOT` / `--repo-root`, `--no-ai` disables. See README
"PR AI wiring (P7⑥)" for details.

## Ops CLI (P7⑧)

```bash
flowstallion approve <run-id>                    # release a policy-parked (pending_approval) run
flowstallion reject  <run-id> [--reason ...]     # reject; reason is persisted on the run and shown in flowstallion status
flowstallion canary  <run-id>                    # read back the CD release bound to this run (strategy/state/metrics/last 20 events)
flowstallion canary  <run-id> rollback [--reason ...]   # manual rollback (operator)
flowstallion cost [--by pr|team] [--source llm|cloud]   # read the cost ledger locally (same semantics as /api/cost)
```

## Log retention (P7⑧)

```
FLOWSTALLION_LOG_RETENTION=30d      # delete log lines of runs older than 30 days
FLOWSTALLION_LOG_RETENTION=runs=500 # keep only logs of the newest 500 runs
```

- Applies to: the `logs` table (aged by the run's
  `COALESCE(started_at, created_at)`) and the `canary_events` table
  (by event timestamp / release recency).
- Unset = disabled; invalid value = warn at startup and ignore (does not
  block startup).
- When valid: one cleanup pass runs immediately at startup, then every
  5 minutes; a single failure only logs and does not stop the loop.
