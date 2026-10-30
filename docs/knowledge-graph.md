# Knowledge Graph and Root Cause Analysis (P4 AIOps)

FlowStallion's AIOps layer: an embedded **Kuzu** graph database that
connects git commits, CI runs, CD canary releases, and K8s objects and
events into one graph, supporting "given an incident ID, trace back the
complete causal chain" RCA queries.

## Stack Boundary

- Data sources are the Go kernel's SQLite (the CI scheduler :8080 and
  CD scheduler :8090 REST APIs) and the local git repo. The graph is
  only a **read-side materialized view**, not a new source of truth.
- Cross-stack only at process boundaries: the Python agent pulls data
  over HTTP/JSON and reads git via subprocess. The Go side is unaware
  of Kuzu's existence.
- Kuzu 0.11.3 (MIT, Apache-2.0 compatible; verification record at
  `../.tasks/flowstallion/notes/kuzu-license.json` in the OpenDevTeam
  repo).

## Data Model

8 node types + 9 relationship types:

```
Commit  ──HAS_PARENT──▶  Commit
Run     ──RUN_OF──▶     Pipeline
Run     ──RUN_STEP──▶   Step
Run     ──RUN_TRIGGERED_BY──▶    Commit
Step    ──STEP_USES_IMAGE──▶     Image
Release ──RELEASE_DEPLOYS──▶     Image     (role: canary|stable)
Release ──RELEASE_MANAGES──▶     K8sObject
Release ──RELEASE_TRIGGERED_BY──▶ Commit
Release ──RELEASE_EVENT──▶       Event
```

Key convention (upsert idempotency relies on the key):

| Node | key |
|---|---|
| Commit | git sha |
| Pipeline | pipeline name |
| Run | `run:{origin}:{id}` |
| Step | `step:{run_key}:{step_id}` |
| Image | image reference (e.g. `flowstallion/demoapp:v2`) |
| Release | `rel:{origin}:{id}` |
| K8sObject | `{release_key}/{kind}/{namespace}/{name}` (isolated per release: when the same live object is managed by two releases — a rollback + a re-release — each keeps its own node and role without overwriting the other) |
| Event | `ev:{release_key}:{event_id}` (the API returns a stable event id; fixed datasets without an id fall back to `ev:{release_key}:{ts}:{seq}`). The CD API only returns a window of the most recent 500 events; using the stable id as the key avoids duplicate nodes as the window slides |

`Release.source_ref` / `Run.source_ref` are graph anchors: the commit
reference passed with the request at canary creation (a column added
on the Go side in P4①; old data is `''`).

## Collectors (`flowstallion_agent.collectors`)

Three collectors, all idempotent (re-running leaves counts unchanged):

- `collect_git(conn, repo_path)`: subprocess `git log --all`, writes
  Commit + HAS_PARENT (no shell, argument-list invocation).
- `collect_runs(conn, base_url, origin)`: CI scheduler `/api/runs` +
  per-run detail, writes Pipeline/Run/Step/Image + RUN_* edges; a run
  with a `git_commit` gets a RUN_TRIGGERED_BY edge.
- `collect_canaries(conn, base_url, origin)`: CD scheduler
  `/api/canaries` + per-release detail events, writes
  Release/Image/K8sObject/Event + RELEASE_* edges; when `source_ref`
  is non-empty, adds RELEASE_TRIGGERED_BY. K8sObject is derived
  deterministically per the P3 manifest rules (when promoted, the
  canary deployment is production); event text is not parsed.

CLI:

```sh
python -m flowstallion_agent.collectors --db mygraph \
    --repo /path/to/repo \
    --runs http://localhost:8080 \
    --canaries http://localhost:8090

python -m flowstallion_agent.collectors --db mygraph --sample   # built-in sample
```

## RCA (`flowstallion_agent.rca`)

`rca(conn, incident_id, kind="auto", depth=5)`:

1. Resolve by id to a Release or a Run — CI run ids and CD release ids
   are independent sequences; in `auto` mode an id that hits both
   raises `RCAError`; you must specify `--kind` explicitly;
2. Find the source commit along `*_TRIGGERED_BY`;
3. Walk up `HAS_PARENT` to at most `depth` ancestors (cycle-protected);
   a merge commit with multiple parents only follows the first parent
   the graph returns (v1 does not expand full merge topology);
4. Find sibling Release/Runs triggered by the same commit via
   `source_ref` equality;
5. A Release additionally carries an event timeline (sorted by ts +
   stable key), deployed images (with role), and managed K8s objects;
   a Run carries its pipeline and steps (failures first).

Raises `RCAError` when not found (or when the id is ambiguous) (CLI
exit code 2).

```sh
python -m flowstallion_agent.rca 3 --db mygraph            # text report
python -m flowstallion_agent.rca 3 --db mygraph --json     # structured
python -m flowstallion_agent.rca 7 --db mygraph --kind run # specify type
```

Measured run (real data, canary #3 demoapp2 rollback incident):

```
=== RCA: Release rel:localhost:3 (demoapp2 @ flowstallion-cd-demo) ===
state: rolled_back
reason: error rate 0.860 > threshold 0.30 (50 window req, 43 err)
...
Source commit: e55bf76151a5  fix mypy errors in agent tests (...)
Parent chain (5 more):
  <- 0d7994306c63  add rca module: ...
```

Full evidence: OpenDevTeam
`.tasks/flowstallion/notes/p4-rca-canary3-real.{json,txt}`.

## Known Limitations

- **Incidents without a source_ref**: the chain stops at the image
  layer (`source_commit` is null) — an honest degradation, not a bug.
- **kuzu 0.11.3 behaviors** (watch out when writing queries):
  - `execute()` is type-annotated as the union
    `QueryResult | list[QueryResult]` → code uniformly uses
    `result: Any = conn.execute(...)`;
  - node RETURNs carry `_id`/`_label` internal keys; filter `_`-prefixed
    keys before output;
  - the not-equal operator is `<>` (`!=` causes a Parser error);
  - no support for undirected inbound edge patterns `(a)<[:R]-(b)` →
    sibling nodes are found via `source_ref` equality queries;
  - the `Database` object holds a file lock: after closing in-process,
    reopening the same path from a subprocess still conflicts; tests
    build the DB in a subprocess.
- **runs collection cap**: `collect_runs` fetches
  `/api/runs?limit=200` in one shot (no pagination); CI history beyond
  200 entries only includes the most recent 200.
- The graph is a snapshot: after scheduler restart / DB wipe, re-run
  the collectors; re-runs are idempotent with no side effects.

## Tests

- `agent/tests/test_graph.py` (12): schema, idempotent upsert, key
  conventions.
- `agent/tests/test_collectors.py` (10): git collection (temp repo),
  CI/CD collection (fake fetcher), 404 degradation, K8s object
  derivation, sample build + idempotent re-run, event window slide
  idempotency (M-3 regression), bad-record isolation (m-1 regression).
- `agent/tests/test_rca.py` (12): release/run dual paths, depth
  truncation, siblings, unknown id, auto ambiguous id error (m-2
  regression), CLI JSON/text/exit codes.
