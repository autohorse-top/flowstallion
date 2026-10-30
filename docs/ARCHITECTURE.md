# FlowStallion Architecture

Dual-engine platform: a Go kernel owns the deterministic delivery pipeline,
a Python AI agent owns model-driven reasoning. The two never share memory;
they communicate across a process boundary.

## Engines

| Engine | Language | Responsibilities |
|--------|----------|------------------|
| Kernel | Go | scheduler, CLI (`flowstallion`), execution runner, web console |
| AI agent | Python | failure root-cause analysis, PR review, smart test selection |

The Python agent is BYOLLM: it speaks any OpenAI-compatible endpoint
(OpenAI / DeepSeek / Qwen / local Ollama) and reaches tools via MCP.
Autonomy levels L0–L2 and the built-in policy engine (`pkg/policy`; OPA is
not a current dependency) gate what the agent may act on.

## DSL (flowstallion.yaml)

Pipelines are declared in a YAML file. Parsing + full structural validation
live in `pkg/pipeline` (`ParseYAML`); the CLI validates files with
`flowstallion validate <file>`. The DSL layer is strictly declarative — no command in
the document is ever executed at parse time. Validation is aggregated: every
problem is reported at once, each with a field path (e.g.
`pipeline.steps[1].id: ...`).

Schema summary:

```yaml
version: 1                      # required, must be 1
pipeline:                       # required object
  name: my-pipeline             # required, <=128, ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$
  trigger:                      # optional list
    - event: push               # required per item: push | pull_request | schedule | manual
      branches: [main, release/*]  # optional; each <=256 chars
      cron: "0 2 * * *"          # only allowed (and required) when event=schedule; <=64
    - event: manual
  concurrency: 3                # optional int, 1..100
  env: { GOFLAGS: "-mod=vendor" }  # optional map[string]string
  secrets: [GH_TOKEN]           # optional; each <=128, ^[a-zA-Z0-9_.-]+$
  steps:                        # required, non-empty
    - id: build                 # required, unique, <=64, ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$
      image: golang:1.22        # required, closed-set image reference
      commands: [go build ./...]  # required; each non-empty, <=4096 chars
      needs: [checkout]         # optional step ids; must exist and form a DAG (no cycles)
      env: { CGO_ENABLED: "0" } # optional map[string]string
      timeout: 3600             # optional seconds, 1..604800, default 1800
```

Notes:

- `needs` references must exist in the same pipeline and must form a DAG;
  cycles (including self loops `a -> a`) are rejected.
- Image references and commands are closed-set character-checked (no
  newlines / shell metacharacters) — security baseline, see AGENTS.md §6.
- All bounds (name 128, id 64, branch 256, cron 64, secret 128, concurrency
  1..100, timeout 1..604800) are enforced at parse time.

Example (excerpt from `testdata/valid-pipeline.yaml`):

```yaml
version: 1
pipeline:
  name: flowstallion-dsl-demo
  trigger:
    - event: push
      branches: [main, release/*]
    - event: schedule
      cron: "0 2 * * *"
  concurrency: 3
  secrets: [GH_TOKEN]
  steps:
    - id: checkout
      image: alpine
      commands: [echo fetching source]
    - id: build
      image: golang:1.22
      needs: [checkout]
      commands: [go build ./...]
      timeout: 3600
```

## Process boundary

```
+----------------------------------------------------+
|                     Go kernel                      |
|  scheduler     CLI (flowstallion)     web console            |
|  runner (executes pipeline steps in containers)    |
+-------------------------+--------------------------+
                        |  HTTP/JSON (requests/results)
                        |  event stream (pipeline lifecycle)
+------------------------v---------------------------+
|                    Python AI agent                 |
|  root-cause  |  PR review  |  smart test selection |
|  BYOLLM (OpenAI-compatible)  ·  MCP tools         |
+----------------------------------------------------+
```

- **HTTP/JSON** — agent requests (analyze failure, review PR) and results.
- **Event stream** — pipeline/job lifecycle events the agent observes.

## Storage (per milestone)

- **P1** — SQLite (pure-Go driver `modernc.org/sqlite`, no CGO): single-node pipeline state and results.
  `pkg/store` exposes the tables: `pipelines` (name + raw YAML), `runs` (status lifecycle
  queued→running→success/failed/canceled with started/finished timestamps), `run_steps`
  (per-step status/image), `logs` (append-only, row id is the monotonic per-step sequence used
  as the SSE cursor), `agents` (registration + heartbeat). WAL mode, single-connection pool,
  fully parameterised SQL.
- **P3** — Postgres: durable queue, multi-node, CD state.
- **P4** — Kuzu graph DB: SDLC knowledge graph (repos, pipelines, incidents) for AIOps.
