# FlowStallion Test Documentation (Test Plan + Acceptance Goals)

> Applies to: the main branch after all of P0–P8 was delivered (tag
> `task/flowstallion-p8-done`, commit `5e879d0`).
> This document is for test engineers running end-to-end functional
> tests. Every acceptance point is an **executable verification**, and
> results are recorded under the "three-tier assertion discipline":
> **Verified** (with commands and output) / **Passed locally** (with
> environment notes) / **Unverified** (explicitly labeled; does not
> count as done).

---

## 0. Test Environment

| Item | Requirement | Notes |
|---|---|---|
| Platform | macOS arm64 (darwin) or Linux | a local dev machine is fine |
| Go | ≥ 1.22 (local: go1.27.3) | check with `go version` |
| Docker | Docker CLI + daemon (colima works on macOS) | containerized step execution depends on the docker daemon |
| Python | ≥ 3.10 (AI agent) | venv under `agent/` |
| kind (only for T-CD) | kind + kubectl | for canary E2E |
| GitHub (phase 2 only) | repo + `GITHUB_TOKEN` (with repo scope) | user-specific info; not needed for phase 1 |

### Startup (pick one)

**Option A — docker compose (recommended, one-click self-hosting)**

```bash
cd ~/Documents/FlowStallion
# Optional: configure environment variables in .env (gitignored, do not commit)
#   FLOWSTALLION_WEBHOOK_SECRET=<random>   # enables webhook endpoints; unset → 503 fail-closed
#   FLOWSTALLION_AUTH=on                  # enable auth (off by default, single-user open mode)
#   FLOWSTALLION_ADMIN_USERNAME / FLOWSTALLION_ADMIN_PASSWORD  # required when auth is on
#   FLOWSTALLION_AGENT_TOKEN              # required when auth is on (agent machine token)
#   FLOWSTALLION_SECRET_KEY               # required when pipeline secrets are needed
#   FLOWSTALLION_LLM_API_KEY / _BASE_URL / _MODEL   # optional, BYOLLM; unset → AI falls back to rule-based
docker compose up -d --build     # full stack on :8080
```

- Services: `scheduler` (REST API + SSE + web console, :8080),
  `agent` (connects to the docker daemon to execute container steps),
  `ai-agent` (Python poller for RCA/review).
- Health check: `curl -s http://localhost:8080/healthz` → 200.

**Option B — local source**

```bash
make setup    # Go deps + Python venv (idempotent)
make build    # build bin/ (flowstallion, scheduler, agent)
make run      # start the scheduler
```

> Under macOS/colima, the agent's docker-daemon connection needs the
> right socket path (handled inside compose; when running the agent
> bare locally, make sure `DOCKER_HOST` points at the colima socket).

---

## 1. Test Goals (Acceptance Milestones)

The 8 goals below are the **acceptance anchors** of this test round;
all passing = acceptance passed. Each goal lists pass criteria
(machine-judgeable observations).

| Goal | Name | Phase | Pass criteria (all must hold) |
|---|---|---|---|
| **T-1** | Self-hosted stack up | local | after `docker compose up -d --build`, all three services healthy; `GET /healthz` 200; web console home page 200 |
| **T-2** | Full pipeline path (manual) | local | `flowstallion create` + `flowstallion trigger` → run `success`; web console shows the run and step states; `flowstallion status`/`flowstallion logs` output is correct |
| **T-3** | SCM webhook triggers (Gitea + GitLab) | local | forged Gitea/GitLab payloads posted with the correct secret → 202 + new run (trigger=push or pull_request, metadata correct); wrong signature/token → 403; secret unset → 503; second trigger under a concurrency cap (concurrency:1) → 409 |
| **T-4** | PR triggers and PR metadata | local | Gitea/GitLab PR events → run carries `pr`/`source_ref`(head)/`base_ref`/`repo_url`/`sha` (PR head); `branches` rules match the head branch, not base |
| **T-5** | AI analysis loop | local | create a failing run → RCA analysis persisted + console RCA card (rule attribution `kind=rule` without an LLM key); after a PR run reaches terminal state, two analyses are created: `pr_review` + `test_selection` (without a token this degrades to persist-only, no error) |
| **T-6** | Policy gate L2 | local | triggering a pipeline declaring a prod-deploy-class step → `pending_approval` (steps not executed) → `flowstallion approve` → execution resumes; `flowstallion reject --reason` → rejected, subsequent steps skipped |
| **T-7** | Security scans + cost ledger | local | `flowstallion scan --run <id> --repo --tool trivy` (or gitleaks/semgrep) → results attached to the run, viewable in the console; `flowstallion cost --by pr` prints the ledger; the `/cost` page matches the API |
| **T-8** | Canary + rollback | local | on a kind cluster, run a pipeline with a `k8s_canary` step: probe failure → automatic rollback; success → promote; manual rollback via `flowstallion canary <run> rollback` works |
| **T-G1** | GitHub Actions CI fully green | GitHub | after pushing to the remote, both the `go-gate` and `python-gate` workflows are green (gofmt/vet/test -race + pytest/mypy) |
| **T-G2** | Real GitHub push integration | GitHub | configure a webhook for the scheduler on the GitHub repo (HMAC, secret equal to `FLOWSTALLION_WEBHOOK_SECRET`) → a push automatically creates a run (trigger=push, correct sha) |
| **T-G3** | Real PR + AI write-back to GitHub | GitHub | open a PR that triggers the pipeline → after the terminal state, `FLOWSTALLION_GITHUB_TOKEN` takes effect and a review appears on the PR (APPROVE/COMMENT/REQUEST_CHANGES), with rule high-severity findings forcing REQUEST_CHANGES |

**Goal dependencies**: T-1 → T-2 → (T-3/T-4 in parallel) → T-5/T-6/T-7
(parallelizable) → T-8; phase 2: T-G1 → T-G2 → T-G3.

---

## 2. Phase 1: Local Development Testing (offline, no GitHub dependency)

### 2.1 T-1 Stack-up smoke

```bash
docker compose up -d --build
docker compose ps                      # expect all three services (scheduler/agent/ai-agent) healthy
curl -sf http://localhost:8080/healthz && echo OK
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/   # expect 200
```

- Verdict: three services healthy + healthz 200 + home page 200 →
  **T-1 passed**.
- Record: `docker compose ps` output + the three curl status codes.

### 2.2 T-2 Manual full pipeline path

```bash
export FLOWSTALLION_SERVER=http://localhost:8080
# (If FLOWSTALLION_AUTH=on is enabled: first run flowstallion login -u <admin> -p <pass>)
flowstallion validate testdata/valid-pipeline.yaml
flowstallion create testdata/valid-pipeline.yaml        # or rename the pipeline to fit the environment
flowstallion trigger flowstallion-dsl-demo
flowstallion status                                     # find the latest run id
flowstallion status <run-id>                            # per-step state
flowstallion logs <run-id> --step test                  # expect log output
```

- Verdict: run terminal state `success`; the web console (:8080) shows
  the run's steps and logs; `flowstallion logs` output is non-empty.
- Note: in `valid-pipeline.yaml`, `build/test` uses the golang:1.22
  image and `scan` uses the trivy image — both need image pulls; on a
  restricted network, first verify the path with a simplified
  alpine-step pipeline, then run the full one.

### 2.3 T-3 / T-4 Webhook triggers (locally forged SCM payloads)

Prerequisite: set `FLOWSTALLION_WEBHOOK_SECRET=whsec-test-123` in `.env`
and rebuild with `docker compose up -d scheduler` (or locally
`FLOWSTALLION_WEBHOOK_SECRET=whsec-test-123 make run`).

Create two test pipelines first (both push-all and pr-all can be created
from `testdata/` or the console):

```bash
# --- Gitea push (HMAC signature) ---
BODY='{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"owner/demo-app"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "whsec-test-123" -r | awk '{print $NF}')
curl -s -X POST http://localhost:8080/api/webhooks/gitea \
  -H "Content-Type: application/json" -H "X-Gitea-Event: push" -H "X-Gitea-Signature: sha256=$SIG" \
  -d "$BODY"; echo            # expect 202 {"triggered":true,"run_id":N}

# Gitea push (plaintext token mode)
curl -s -X POST http://localhost:8080/api/webhooks/gitea \
  -H "Content-Type: application/json" -H "X-Gitea-Event: push" -H "X-Gitea-Token: whsec-test-123" \
  -d "$BODY"; echo

# Negative: wrong signature → 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/api/webhooks/gitea \
  -H "X-Gitea-Event: push" -H "X-Gitea-Signature: sha256=deadbeef" -d "$BODY"   # expect 403

# --- GitLab push (plaintext token) ---
GLBODY='{"object_kind":"push","ref":"refs/heads/main","after":"abc123","project":{"path_with_namespace":"group/demo-app"}}'
curl -s -X POST http://localhost:8080/api/webhooks/gitlab \
  -H "Content-Type: application/json" -H "X-Gitlab-Event: Push Hook" -H "X-Gitlab-Token: whsec-test-123" \
  -d "$GLBODY"; echo          # expect 202
```

**PR/MR metadata (T-4)**:

```bash
# Gitea PR (GitHub-shaped payload)
GPR='{"action":"opened","pull_request":{"number":42,"head":{"ref":"feature/x","sha":"deadbeef"},"base":{"ref":"main"}},"repository":{"full_name":"owner/demo-app","html_url":"https://gitea.local/owner/demo-app"}}'
SIG=$(printf '%s' "$GPR" | openssl dgst -sha256 -hmac "whsec-test-123" -r | awk '{print $NF}')
curl -s -X POST http://localhost:8080/api/webhooks/gitea \
  -H "X-Gitea-Event: pull_request" -H "X-Gitea-Signature: sha256=$SIG" -d "$GPR"; echo
# → 202; check GET /api/runs/<id> for pr=42, source_ref=head, base_ref=main, sha=deadbeef

# GitLab MR
GLMR='{"object_kind":"merge_request","object_attributes":{"iid":7,"action":"open","source_branch":"feature/y","target_branch":"main","source_sha":"cafebabe"},"project":{"path_with_namespace":"group/demo-app","web_url":"https://gitlab.local/group/demo-app"}}'
curl -s -X POST http://localhost:8080/api/webhooks/gitlab \
  -H "X-Gitlab-Event: Merge Request Hook" -H "X-Gitlab-Token: whsec-test-123" -d "$GLMR"; echo
```

**Edge cases and exceptions** (verdict table):

| Scenario | Expectation |
|---|---|
| any webhook called while `FLOWSTALLION_WEBHOOK_SECRET` is unset | 503 |
| wrong token (GitLab/Gitea) | 403 |
| Gitea with a wrong signature + a correct token both sent | 403 (signature takes priority, no fallback) |
| ref is `refs/tags/*` (push event) | 200 `triggered:false`, reason=non-branch ref |
| `after` = 40 zeros | 200 `triggered:false` (branch deletion) |
| repository name has no matching pipeline | 200 `triggered:false` (no pipeline for repository) |
| payload > 10MiB | 413 |
| bad JSON | 400 |
| GitLab `X-Gitlab-Event=Push Hook` but `object_kind=merge_request` | 200 `triggered:false` (object_kind mismatch) |
| `concurrency:1` pipeline triggered while one run is in flight | 409 |
| pipeline has no trigger rule for the event / branch mismatch (branches matches the head branch) | 200 `triggered:false` |

- Verdict: T-3 requires Gitea/GitLab positive cases 202 with correct run
  metadata and all negative cases hitting the table above; T-4 requires
  `pr/head_ref/base_ref/repo_url/sha` all correct on PR/MR run rows.
- Note: the negative cases above are already covered by Go table-driven
  tests (`webhook_gitea_test.go`/`webhook_gitlab_test.go`); the manual
  curls verify the HTTP boundary behavior is consistent.

### 2.4 T-5 AI analysis loop

```bash
# 1) Create a failure: make a pipeline with an exit 1 step and trigger it (or reuse a failing run)
# 2) Wait for the ai-agent poller (default 5s) to produce the analysis:
curl -s http://localhost:8080/api/runs/<run-id>    # check the RCA analysis in the response's analysis (primary) / analyses (full list) fields
# The console /run/<id> page should show the RCA card
# 3) After a PR run reaches terminal state:
curl -s http://localhost:8080/api/runs/<pr-run-id>  # check pr_review + test_selection in the analysis/analyses fields
```

- Verdict (minimum bar without an LLM key): the failing run has a
  rule-attribution analysis (`kind=rule`) visible in the console; the PR
  run has both analyses persisted, and the agent has no error logs.
- Enhanced verdict (with `FLOWSTALLION_LLM_API_KEY` set): analysis content
  includes LLM-generated sections; the cost ledger gains new records
  (see T-7).

### 2.5 T-6 Policy gate (L2 approval)

```bash
# Use docs/policy or the console to create a pipeline with a prod-deploy-class step (critical operation)
flowstallion trigger <pipeline>        # → run state pending_approval, steps not executed
flowstallion status <run-id>           # confirm no step is running
flowstallion approve <run-id>          # → execution resumes, ultimately success (or per actual step results)
# Another run:
flowstallion reject <run-id> --reason "test rejection"   # → run rejected, subsequent steps skipped
```

- Verdict: before approve, steps are not executed (all step states
  checkable as pending); after approve, execution continues; after
  reject, the run is rejected and steps skipped.
- 409 negative: calling approve/reject on a run that is not
  pending_approval → 409.

### 2.6 T-7 Security scans + cost ledger

```bash
# Scan (needs the corresponding tool available locally or in the container; trivy example)
flowstallion scan --run <run-id> --repo --tool trivy
curl -s http://localhost:8080/api/runs/<run-id>/scans      # expect report entries
# The console run detail page shows the scan results
# Cost
flowstallion cost --by pr
curl -s "http://localhost:8080/api/cost?by=pr"             # consistent with CLI output
```

- Verdict: scan results are attached to the specified run and visible in
  the console; the cost table contains run/PR-dimension records (if no
  LLM spend exists yet, verify the aggregation logic with the agent's
  `cost --sample --out` or cloud-cost sample entries, but label them as
  **sample data**).

### 2.7 T-8 Canary + rollback (needs kind)

```bash
kind create cluster --name flowstallion-test && kubectl config use-context kind/flowstallion-test
# Trigger the demo pipeline from docs/canary.md (k8s_canary step + demoapp image)
flowstallion trigger <canary-pipeline>
# Scenario A (auto rollback): the probe must fail (e.g. liveness 500) → observe the run rolling back automatically
# Scenario B (promote): healthy service → canary promoted, selector switched to canary
# Manual: flowstallion canary <run-id> rollback
kubectl get deploy,svc -n <ns> -w   # watch stable/canary counts and selector changes
```

- Verdict: after A's rollback, traffic is 100% back on stable and the
  canary is cleaned up; after B's promote, the stable selector points at
  the canary image; manual rollback works.
- Reference: `docs/canary.md` (P3 already includes a kind two-path
  field-test method).

### 2.8 Auxiliary items (not counted among the 8 goals, but worth a pass)

- `flowstallion validate` reports all expected errors on
  `testdata/broken-pipeline.yaml`.
- Log retention: after triggering with
  `FLOWSTALLION_LOG_RETENTION=runs=2`, old logs are cleaned up.
- Auth (optional enable): with `FLOWSTALLION_AUTH=on`, anonymous access to
  `/api/pipelines` → 401; a viewer calling trigger → 403; admin passes
  everything.
- Secrets: `flowstallion secret set/list/rm`; `${NAME}` injection in pipelines
  works; without `FLOWSTALLION_SECRET_KEY`, the secret API returns 503 and
  pipelines declaring secrets cannot be triggered (fail-closed).

---

## 3. Phase 2: GitHub Development Testing (needs a remote repo + GITHUB_TOKEN)

> Prerequisite: a GitHub repo (creating `flowstallion-e2e` is
> recommended); the local FlowStallion has a pipeline pointing at that
> repo; `GITHUB_TOKEN` (with repo scope) is **user-specific
> information**, obtained by the engineer from the environment and never
> written into any commit.

### 3.1 T-G1 Actions CI fully green

```bash
git remote add origin git@github.com:<user>/flowstallion.git   # or the e2e repo
git push -u origin main
```

- Verdict: `go-gate` and `python-gate` in `.github/workflows` are both
  green (gofmt/vet/`go test -race` + pytest/mypy).
- Note: this is the final evidence for "clean-machine reproducible
  build" (AGENTS.md §4); local gates passing while Actions fail =
  non-reproducible build, must be fixed to green.

### 3.2 T-G2 Real push integration

1. Set `FLOWSTALLION_WEBHOOK_SECRET=whsec-xxx` on the local (or compose)
   scheduler.
2. GitHub repo Settings → Webhooks → add
   `http://<reachable-address>:8080/api/webhooks/github`,
   Secret = the same secret, choose `push` (optionally
   `pull_request`).
3. Push a commit to `main`.

- Verdict: the pipeline automatically creates a run, `trigger=push`,
  `sha` is the commit just pushed; visible in the console.
- Note: the loopback address must be reachable via a tunnel/the public
  internet, or verified in reverse inside a GitHub Actions runner
  environment (when curling an internal address from Actions is not
  possible, use GitHub-official or Zapier/webhook.site-style tools to
  observe the payload shape, then complete trigger verification with
  phase-1 forged requests, and honestly label in the record which part is
  the real path and which is the local equivalent).

### 3.3 T-G3 Real PR + AI write-back

1. Set the agent env `FLOWSTALLION_GITHUB_TOKEN` (same-repo token) +
   `FLOWSTALLION_SERVER`.
2. Open a PR on GitHub (change any file) → the webhook triggers a PR run
   (with PR metadata).
3. After the run's terminal state, watch the GitHub PR page.

- Verdict: a FlowStallion review appears on the PR (one of
  APPROVE/COMMENT/REQUEST_CHANGES); if the diff contains a high-severity
  rule (e.g. a hardcoded key) → REQUEST_CHANGES is mandatory (rules take
  priority; the LLM cannot downgrade); the `test_selection` analysis is
  persisted and consistent with the changed-file mapping.
- Negative: when the token is missing, only persist without write-back,
  and the agent does not crash (degraded path).

---

## 4. Result Recording and Verdict Discipline

- One record line per goal, format:
  `Goal | Conclusion (passed/not met/partial) | Evidence (command+output or screenshot/log path) | Environment (OS/version/compose or source)`.
- **Three-tier assertion discipline** (AGENTS.md §7):
  - **Verified**: attach reproducible commands and output;
  - **Passed locally**: attach local environment notes (darwin arm64 /
    go version / docker/colima version);
  - **Unverified/speculation**: explicitly labeled, **does not count as
    done** (e.g. T-G3 before a real token is configured can only count
    as "degraded path verified").
- Goals that are not met: honestly label the reason and paths already
  tried; do not lower the bar (goal anchors are immutable); if a goal
  must change, the coordinator revises this document and leaves a trace.
- Bugs found: record them graded as
  `KILLER/MAJOR/MINOR/NIT`; after fixing, add a regression case and
  re-test.

## 5. References

- Pipeline DSL quick reference: `docs/pipeline.md`; security:
  `docs/security.md`; canary: `docs/canary.md`; FinOps:
  `docs/finops.md`.
- Full regression gate: `make test` (gofmt + vet + `go test -race ./...`
  + pytest + mypy).
- Sample pipelines: `testdata/valid-pipeline.yaml` (full features) /
  `testdata/broken-pipeline.yaml` (negative cases).
