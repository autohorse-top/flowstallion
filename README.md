# FlowStallion

**FlowStallion — an open-source autonomous SDLC platform: AI-agent-driven CI/CD, BYOLLM (bring your own model via any OpenAI-compatible API), self-hosted and local-first.**

An open-source, self-hostable alternative to managed CI/CD platforms (harness.io-style). Deterministic pipelines run in a Go kernel; model-driven intelligence lives in a Python agent. Your code, data, and model keys never leave your infrastructure.

## Features

> Feature milestones: (P1) CI core · (P2) AI agent · (P3) CD/GitOps · (P4) knowledge graph · (P5) security & FinOps · (P6) auth, secrets & hardening · (P7) pipeline extensions.
> P0–P8 are all shipped: dual-stack skeleton, CI gates, versioned CLI, `flowstallion.yaml` DSL, scheduler, runner, `flowstallion` CLI, web console, GitHub webhooks, one-command compose self-hosting, AI agent (LLM triage/review, policy-gated approvals), canary & blue-green deploys with rollback, Kuzu knowledge graph, security scanning (Trivy/Gitleaks/Semgrep), FinOps cost ledger + console, local AuthN/RBAC, encrypted pipeline secrets, plus P7: PR & cron triggers, `docker_build` and in-DAG `k8s_canary` / `k8s_blue_green` steps, PR AI wiring, webhook notifications, operator CLI (`approve/reject/canary/cost`), log retention, and P8: self-hosted SCM webhook adapters (Gitea/GitLab) for offline/air-gapped delivery.

- **Local-first, self-hosted** (P1) — one `docker compose` command brings up the full stack on your own hardware.
- **BYOLLM** (P2) — plug in any OpenAI-compatible endpoint: OpenAI, DeepSeek, Qwen, or local Ollama.
- **MCP-native tool access** (P2) — agents consume tools through the Model Context Protocol.
- **Dual-engine process isolation** (P0+) — Go drives scheduler / CLI / runner; Python drives the AI brain. Strict process boundary.
- **Risk-graded autonomy (L0–L2)** (P2; level model defined in P0) — from fully human-driven (L0) to critical-steps-only approval (L2), configurable per pipeline. L3 is a reserved label (Python-side enum only, not enforced by the Go core).
- **Policy-as-code guardrails** (P2) — hard red lines declared in pipeline policy, enforced by the built-in risk/autonomy engine (`pkg/policy`; OPA is not a current dependency).
- **Smart test selection** (P2) — run only the tests a change can actually affect.
- **SDLC knowledge graph (Kuzu)** (P4) — persistent graph over repos, pipelines, and incidents.
- **Cost attribution** (P5) — cloud + LLM token spend tracked down to the PR level.
- **Security scanning** (P5/P6) — Trivy (fs + image), Gitleaks and Semgrep results attached to runs and browsable in the console.
- **Cost console** (P6) — `/cost` page and `GET /api/cost` aggregate the shared JSONL ledger by PR or team (LLM and/or cloud).
- **AuthN + RBAC** (P6) — opt-in local login (PBKDF2) with `viewer`/`operator`/`admin` roles; agent traffic via machine token (`FLOWSTALLION_AUTH=on`).
- **Encrypted pipeline secrets** (P6) — AES-256-GCM vault in SQLite, `${NAME}` injection into step env, admin-only management (`flowstallion secret` / API).
- **PR & cron triggers** (P7) — `pull_request` webhook events carry PR metadata into the run; five-field `cron` schedules with persistent watermark and once-only catch-up after downtime.
- **`docker_build` steps** (P7) — build (and optionally push) images on the runner host, with `{{sha}}`/`{{branch}}`/`{{ts}}` image-ref templates; outputs (e.g. `image_ref`) read back via the run API and `flowstallion status`.
- **`k8s_canary` / `k8s_blue_green` steps in the DAG** (P7) — CD releases (isolated canary or blue-green) driven by the scheduler as a pipeline step; auto-promote / auto-rollback on probe failures, error-rate breach, or apply timeout; manual rollback via `flowstallion canary <run> rollback` or `POST /api/canaries/{id}/rollback`.
- **Webhook notifications** (P7) — `notifications: [{type: webhook, url}]` posts run terminal states (`success`/`failed`/`canceled`) and canary rollbacks; fire-and-forget, never blocks or fails the run.
- **Operator CLI** (P7) — `flowstallion approve/reject [--reason]`, `flowstallion canary <run> [rollback]`, `flowstallion cost --by pr|team [--source llm|cloud]` (local ledger read, same semantics as `/api/cost`).
- **Log retention** (P7) — `FLOWSTALLION_LOG_RETENTION=30d` or `runs=500` periodically purges old run logs and canary events.
- **Self-hosted SCM webhooks** (P8) — Gitea (`POST /api/webhooks/gitea`, `X-Gitea-Signature` HMAC or plain `X-Gitea-Token`) and GitLab (`POST /api/webhooks/gitlab`, plain `X-Gitlab-Token`; MR hooks normalised to `pull_request`) trigger pipelines from offline/air-gapped environments; same `FLOWSTALLION_WEBHOOK_SECRET` and response contract as the GitHub endpoint.
- **Audit log** (harness ③) — append-only `audit_events` stream (login/deny, pipeline/run/scan/canary/user/secret mutations, SCM webhook triggers) queryable via `GET /api/audit` (viewer+) and `flowstallion audit --limit/--actor/--action/--after`; never stores passwords or secret values; audit write failures never affect the main request. See [docs/audit.md](docs/audit.md).
- **Pipeline quick reference** (P7) — [docs/pipeline.md](docs/pipeline.md).
- **Apache-2.0, clean dependency chain** (P0) — permissive license, zero-runtime-dependency core.

## Quickstart

**P0–P8 are shipped.** Two ways to run:

### Option A — docker compose (recommended, one command)

```bash
docker compose up -d --build   # full stack on :8080 (see docker/README.md)
```

- Scheduler (REST API + SSE + web console) on port `8080`.
- Agent runner connects to the Docker daemon for containerized steps.
- SCM webhooks (optional): set `FLOWSTALLION_WEBHOOK_SECRET` in a gitignored `.env`, then point your SCM at `POST /api/webhooks/github` (HMAC-SHA256 verified), `POST /api/webhooks/gitea` (HMAC `X-Gitea-Signature` or plain `X-Gitea-Token`), or `POST /api/webhooks/gitlab` (plain `X-Gitlab-Token`) — same secret for all three; unset secret → 503 (fail-closed).
- Auth is off by default (open single-user mode, pre-P6 behavior). To enable: set `FLOWSTALLION_AUTH=on` plus `FLOWSTALLION_ADMIN_USERNAME` / `FLOWSTALLION_ADMIN_PASSWORD` (bootstrap admin) and `FLOWSTALLION_AGENT_TOKEN` (agent machine token). Pipeline secrets additionally need `FLOWSTALLION_SECRET_KEY`. See [docs/security.md](docs/security.md).

### Option B — local (source build)

```bash
make setup   # Go deps + Python venv (idempotent — safe to re-run)
make build   # compile Go binaries into bin/ (flowstallion, scheduler, agent)
make run     # build (cached if up to date) then launch the scheduler
make test    # go test + pytest + mypy
```

## Repository Layout

| Path | Purpose |
|------|---------|
| `cmd/` | Go executables: `flowstallion` (CLI), `scheduler`, `agent` (runner) |
| `pkg/` | Go core packages (`version`, `pipeline`, …) |
| `agent/` | Python AI agent package `flowstallion_agent` + tests |
| `docs/` | Architecture, pipeline, canary, security, FinOps & design notes |
| `docker/` | Containerization & one-command self-hosting (P1) |
| `.github/` | CI workflows (`go-gate` / `python-gate`) |

## Knowledge Graph (P4)

`agent/flowstallion_agent/graph.py` — Kuzu-backed SDLC graph store: 8 node tables (Commit, Pipeline, Run, Step, Image, Release, K8sObject, Event) and 9 relation tables, all writes are idempotent MERGE upserts (re-ingesting the same object is a no-op).

```bash
cd agent && .venv/bin/python -m flowstallion_agent.graph open data/kuzu/graph.db   # create + report all table counts
```

## FinOps cost ledger (P5)

LLM token spend and cloud resource cost are tracked down to the PR level. When
`FLOWSTALLION_COST_LEDGER` is set, every successful LLM triage appends its token
usage (prompt/completion/total + USD cost) as one JSONL line to the ledger,
tagged with `run_id`, `pr`, and `team`. Cloud line items can be appended the
same way. Unknown models are counted but priced at 0; unit prices can be
overridden via `FLOWSTALLION_LLM_PRICE_IN` / `FLOWSTALLION_LLM_PRICE_OUT`
(USD per 1M tokens).

```bash
cd agent && .venv/bin/python -m flowstallion_agent.cost --ledger ledger.jsonl --by-pr
```

Use `--sample --out ledger.jsonl` to seed a demo ledger, `--by-team` for team
aggregation, and `--json` for machine-readable output.

The scheduler also serves the same ledger from the web console (P6):
the `/cost` page aggregates records by PR or team via
`GET /api/cost?by=pr|team&source=llm|cloud` (viewer role or above). In
`docker compose`, scheduler and ai-agent share one ledger file on a named
volume (`flowstallion-cost`), so the console reads exactly what the agent appends.
See [docs/finops.md](docs/finops.md) for ledger semantics.

## PR AI wiring (P7)

When a PR-triggered run reaches a terminal state (`success` / `failed`), the
Python agent (`watch` loop, AI wiring enabled by default) automatically writes
two run-level analyses back to the scheduler via the agent-token endpoint
(`POST /api/runs/{id}/analysis`, header `X-Agent-Token`):

- **`pr_review`** — the PR diff is fetched from the GitHub API
  (`Accept: application/vnd.github.v3.diff`) and reviewed: rule checks
  (secret leaks, dangerous patterns) plus an optional LLM pass. The stored
  analysis carries the verdict and findings. When `FLOWSTALLION_GITHUB_TOKEN` is
  set, the same review is additionally posted to GitHub as a PR review
  (APPROVE / COMMENT / REQUEST_CHANGES). A high-severity rule finding always
  forces `REQUEST_CHANGES` and the LLM cannot downgrade it. Without a GitHub
  token the wiring degrades to analysis-only (no hard dependency).
- **`test_selection`** — the changed files from the same diff are mapped to
  the tests that cover them (Go: `*_test.go` in the same package; Python:
  sibling `tests/` dir or module-level `test_<module>.py`) and stored as an
  analysis whose `detail` JSON is
  `{"go_tests": [...], "python_tests": [...], "all_go": bool, "all_python": bool, "reasons": {...}}`.

Writes are idempotent per kind: the agent lists existing analyses before
posting, so re-passes never duplicate a stored `pr_review` or
`test_selection`.

```bash
# single pass, AI wiring on, test selection resolved against a local checkout
FLOWSTALLION_AGENT_TOKEN=... FLOWSTALLION_GITHUB_TOKEN=... \
  .venv/bin/python -m flowstallion_agent.watch --once --repo-root /path/to/repo
```

Environment: `FLOWSTALLION_AGENT_TOKEN` (agent machine token, required when the
scheduler runs with auth), `FLOWSTALLION_GITHUB_TOKEN` (optional, enables the
GitHub review post), `FLOWSTALLION_GITHUB_API` (optional, default
`https://api.github.com`), `FLOWSTALLION_REPO_ROOT` / `--repo-root` (checkout
dir used for test selection, default `.`), `--no-ai` to disable the wiring
phase.

### Consuming the recommended test list (`FLOWSTALLION_TEST_PATTERN`)

The `test_selection` analysis is a recommendation, not a policy change: the
pipeline itself still decides which tests run. The convention for consuming
it is the env var `FLOWSTALLION_TEST_PATTERN` in a test step — set it from the
latest `test_selection` analysis for the PR (its `go_tests` / `python_tests`
arrays), comma-separated, and have the step command honor it:

```yaml
steps:
  - id: test
    image: alpine
    commands:
      - |
        if [ -n "$FLOWSTALLION_TEST_PATTERN" ]; then
          go test $(tr ',' ' ' <<< "$FLOWSTALLION_TEST_PATTERN")
        else
          go test ./...
        fi
    env:
      FLOWSTALLION_TEST_PATTERN: "pkg/auth/foo_test.go,pkg/auth/bar_test.go"
```

The value may also be a directory (`pkg/auth/`); an empty/unset variable
falls back to the full suite.

## Roadmap

- **P0 — Skeleton (shipped).** Repo layout, dual-engine build, CI gates, versioned CLI.
- **P1 — CI core (shipped).** `flowstallion.yaml` DSL, scheduler, Docker-based runner, web console, GitHub webhooks, `docker compose` one-command self-hosting.
- **P2 — AI agent (shipped).** Failure root-cause analysis, PR review, smart test selection, policy-gated approvals. LLM provider layer (OpenAI-compatible, BYOLLM via env).
- **P3 — CD / GitOps (shipped).** Kubernetes canary deployment with automatic rollback.
- **P4 — Knowledge graph + AIOps (shipped).** Kuzu-backed SDLC graph, incident-pattern reasoning.
- **P5 — Security & FinOps plugins (shipped).** Trivy scanning, LLM/cloud cost ledger + aggregation CLI.
- **P6 — Auth, secrets & hardening (shipped).** Local AuthN/RBAC, encrypted pipeline secrets, multi-tool scanning (Gitleaks/Semgrep), cost console page. See [docs/security.md](docs/security.md).
- **P7 — Pipeline extensions (shipped).** PR & cron triggers, `docker_build` and in-DAG `k8s_canary` / `k8s_blue_green` steps, PR AI wiring (review + test selection), webhook notifications, operator CLI (`flowstallion approve/reject/canary/cost`), log retention. See [docs/pipeline.md](docs/pipeline.md).
- **P8 — Self-hosted SCM (shipped).** Gitea & GitLab webhook adapters (push + PR/MR) sharing the GitHub endpoint's dispatch tail, auth and response contract — pipelines can be triggered from offline/air-gapped environments without GitHub.
- **Audit log (harness ③, shipped).** Append-only `audit_events` audit stream over every mutation/auth/SCM decision point, exposed via `GET /api/audit` and the `flowstallion audit` CLI. See [docs/audit.md](docs/audit.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
