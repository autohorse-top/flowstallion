# Security Scanning and FinOps (P5)

FlowStallion's P5 layer: makes **security scan results** and **AI/cloud cost
attribution** queryable first-class citizens. Scan reports attach to
specific runs; token and cloud costs aggregate into statements by PR /
team.

## Stack Boundary

- Go: scan execution and storage (`pkg/security` Trivy process wrapper +
  report parsing, the `run_scans` table in `pkg/store`, REST API
  `POST/GET /api/runs/{id}/scans`, the `flowstallion scan` CLI); cost ledger
  reading and console (P6④: `pkg/finops` line-by-line parsing +
  aggregation, `GET /api/cost`, the web `/cost` page).
- Python: cost attribution. `agent/flowstallion_agent/cost.py` (JSONL
  ledger + pricing + aggregation CLI), `llm.py` captures the `usage`
  block of OpenAI-compatible responses, and `triage.py` appends one
  ledger entry after a successful LLM attribution (opt-in,
  env-driven).
- Cross-stack only at process boundaries: Go writes scan reports into
  SQLite, Python writes costs into a JSONL file; each is unaware of the
  other, no in-process mixing.

## Security Scanning (Trivy)

### Data model

The `run_scans` table (`pkg/store`, created idempotently by
`migrate()`; old DBs gain the table automatically):

```
id INTEGER PK
run_id INTEGER FK → runs.id
tool, target, mode TEXT          -- mode: fs | image
exit_code INTEGER                -- trivy's actual exit code
findings_count INTEGER
severity_json TEXT               -- {"CRITICAL":1,"HIGH":2,...} only keys with >0 are kept
report_json TEXT                 -- full trivy JSON (truncated at >1MiB, truncated=1)
truncated INTEGER
created_at TEXT
```

### REST API

- `POST /api/runs/{id}/scans` — report one scan. Validation: run exists
  (else 404), tool non-empty ≤64, mode ∈ {fs,image}, findings_count ≥ 0,
  each severity value ≥ 0, report_json ≤ 1MiB. 200 returns the new
  scan's DTO.
- `GET /api/runs/{id}/scans` — the run's scan list (ascending id; `[]`
  when empty).
- `GET /api/runs/{id}` — the run detail's `scans` field contains all of
  the run's scans.

### CLI

```sh
# Scan a local repo (trivy fs mode)
FLOWSTALLION_TRIVY_BIN=/opt/homebrew/bin/trivy \
  flowstallion scan --run 1 --repo /path/to/repo

# Scan an image (trivy image mode; local docker must be able to pull the image)
flowstallion scan --run 1 --image nginx:1.25

# When --server is omitted, reads FLOWSTALLION_SERVER or the flowstallion login saved config
```

Exit codes: 0 = stored successfully; 1 = scan failure / HTTP failure;
2 = usage error / trivy binary missing (stderr hint:
`set FLOWSTALLION_TRIVY_BIN or install trivy`; never silently skipped).

Trivy lookup order: `FLOWSTALLION_TRIVY_BIN` (used when non-empty) →
`trivy` on `PATH` → error. Scan timeout defaults to 10 minutes.

## FinOps (Cost Attribution)

### LLM Token Accounting

`llm.py` stores the `usage` block of each successful chat response into
`LLM.last_usage` (`TokenUsage(prompt_tokens, completion_tokens,
total_tokens)`; kept as `None` when the response has no usage — no
fabricated data). `triage.analyze` appends a JSONL record via
`cost.record_llm_usage` when LLM attribution succeeds (kind="llm") and
the `FLOWSTALLION_COST_LEDGER` env var is set; accounting failures are
swallowed and never affect the RCA result. Zero behavior change when
the env var is unset.

### Cost Ledger

`agent/flowstallion_agent/cost.py` — a JSONL append-only ledger (one
`CostRecord` per line):

```
ts, source(llm|cloud), run_id|null, pr, team, model|null,
prompt_tokens, completion_tokens, total_tokens, cost
```

Pricing: built-in approximate list prices for 2026-10
(`PRICE_PER_MTOK`, USD per 1M tokens: gpt-4o-mini 0.15/0.60, gpt-4o
2.50/10.00, claude-3-5-sonnet 3.00/15.00, claude-3-haiku 0.25/1.25);
setting either env var `FLOWSTALLION_LLM_PRICE_IN` /
`FLOWSTALLION_LLM_PRICE_OUT` overrides the whole table (unset ones become
0.0); unknown model → cost 0.0 (tokens still counted).

### Aggregation CLI

```sh
# Generate a deterministic sample ledger (LLM + cloud cost, multiple PRs × teams)
python -m flowstallion_agent.cost --sample --out ledger.jsonl

# Aggregate by PR (table)
python -m flowstallion_agent.cost --ledger ledger.jsonl --by-pr
# Aggregate by team (JSON, for script consumption)
python -m flowstallion_agent.cost --ledger ledger.jsonl --by-team --json
# Cloud cost only
python -m flowstallion_agent.cost --ledger ledger.jsonl --by-pr --source cloud
```

Aggregation semantics: sum records / prompt / completion / total tokens
/ cost per key, sorted by cost descending, with a TOTAL row at the end
of the table. `--json` emits raw floats (machine consumption); the
table shows 4 decimal places (human-readable).

## Cost Console (P6④)

The Go side (`pkg/finops`) reads the **same** JSONL ledger (env
`FLOWSTALLION_COST_LEDGER`, default `~/.flowstallion/cost-ledger.jsonl`,
matching the Python default); the console `/cost` page shows
aggregations by PR / team:

- `GET /api/cost?by=pr|team&source=llm|cloud` (readable by viewer+;
  unauthenticated API 401 / web 302 to `/login`). `by` defaults to
  `pr`; `source` defaults to all sources — when specified, filter first
  then aggregate, and the `total` row only includes the filtered
  records.
- Response `{"by", "rows", "total"[, "source"]}`; rows sorted by
  `cost_usd` descending, ties keep first-occurrence order (matching the
  Python stable sort); page costs show 4 decimal places.
- Missing ledger file → 200 with an empty result (zero behavior change
  on a fresh install); bad line → 400 with `error` shaped like
  `ledger: line N: ...` (1-based physical line number, same semantics
  as the Python strict mode).
- Parsing semantics align field-by-field with the Python reference
  (missing keys take defaults, explicit null on required fields is an
  error, token counts reject bool/non-int); in compose, scheduler and
  ai-agent point at the same ledger file via the shared named volume
  `flowstallion-cost` (both set
  `FLOWSTALLION_COST_LEDGER=/data/cost/cost-ledger.jsonl`), so the console
  reads exactly the file the agent is appending to.

Known difference: Go's `~` expansion strips any `~` prefix and joins it
to the current user's HOME (`~user/x` → `$HOME/user/x`), while Python's
`os.path.expanduser` resolves to user `user`'s home directory
(`/home/user/x`) — the two differ; when HOME cannot be determined the
literal `~` path is kept and treated as "file missing" (200 empty
result).

**Follow-up (review m4, accepted risk)**: `/api/cost` re-reads the whole
ledger on every request with no cache; the ledger grows unbounded
(append-only, never deleted). At scale this needs rotation/sharding or
indexing.

## Verification Status (three-tier assertion)

- **Verified**: Go `go test ./... -race` (including pkg/security
  table-driven + fake trivy script, store round-trip and old-DB
  migration, api validation matrix, pkg/finops parse/aggregation
  table-driven, /cost and /cost page endpoint tests); Python `pytest`
  198 passed + mypy 27 files zero errors; `make test` full gate green.
- **Verified (P6④ Go/Python parity)**: the same 11-row sample ledger
  (`/tmp/flowstallion-ledger-p6.jsonl`) — Go `pkg/finops` and the Python CLI agree
  digit-for-digit across 4 aggregation groups (by-pr all-source /
  by-team all-source / by-pr llm / by-pr cloud), including row order
  and float representation (e.g. pr-207 $3.4551, team-data
  $3.8350999999999997).
- **Passed locally** (darwin arm64, go 1.27.3, python 3.11.17, trivy
  0.76.1): a real trivy scan of this repo → `flowstallion scan` stores it →
  `GET /api/runs/1/scans` and run detail read back consistently (output
  archived at `../.tasks/flowstallion/notes/p5/scans-e2e.json`); the cost
  CLI sample ledger `--by-pr` amounts match the test expectations
  recomputed line by line (archived as `cost-by-pr.txt` /
  `cost-by-team.json`).
- **Unverified**: CI environment, real K8s cloud-billing integration
  (currently sample data + aggregation commands only).
