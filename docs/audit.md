# Audit Log (harness ③)

FlowStallion's persistent audit event stream: who (actor) did what (action)
to what (target) when (ts), and with what outcome. Events are stored in
the local SQLite `audit_events` table and queried via `GET /api/audit`
(viewer and above) and the `flowstallion audit` CLI. Fully implemented in Go; the
Python agent does not participate (no cross-stack writes).

## Instrumentation Scope (what is and is not recorded)

**Recorded** (at every mutation's outcome-determination point, on both success and failure paths):

| action | trigger | target convention | detail content |
|---|---|---|---|
| `auth.login` | `POST /api/auth/login` | `user:<name>` (`user:unknown` when unrecognized) | success: `role=<role>`; failure: `username=<name>` (**never logs passwords**); bad body: `invalid body`; auth disabled: `auth disabled`; 5xx: `login: <error>` |
| `auth.logout` | `POST /api/auth/logout` | `user:<name>` | — (empty) |
| `auth.deny` | 401/403 from `requireRole`/`requireAgent` | `METHOD /path` (e.g. `POST /api/users`) | 401 no credentials: `unauthenticated`; 403: `requires <role>` (no equals sign, e.g. `requires operator`); agent endpoints: `agent auth failed` |
| `pipeline.upsert` | `POST /api/pipelines` | `pipeline:<name>` (`pipeline:unknown` when name missing/bad body) | `id=<id>`; failure reason |
| `run.trigger` | `POST /api/pipelines/{name}/trigger` | `run:<id>` (`run:unknown` when run creation fails) | `trigger=<method>` (appends `source_ref=<ref>` when source_ref provided); failure reason |
| `run.cancel` | `POST /api/runs/{id}/cancel` | `run:<id>` (`run:unknown` for invalid id) | success: empty; failure reason |
| `run.approve` | `POST /api/runs/{id}/approve` | `run:<id>` (`run:unknown` for invalid id) | success: empty; failure reason |
| `run.reject` | `POST /api/runs/{id}/reject` | `run:<id>` (`run:unknown` for invalid id) | `reason=<reason>` (reason >500 chars → 400 `reason too long`) |
| `scan.save` | `POST /api/runs/{id}/scans` | `run:<id>` (`run:unknown` for invalid id/nonexistent run) | success: `tool=<tool> findings=<count>`; failure reason |
| `canary.create` | `POST /api/canaries` | `canary:<id>` (bad body: `canary:unknown`; bad name — invalid K8s name/too long — `canary:<name>`, e.g. `canary:DemoApp`) | `name=... ns=... strategy=...`; failure reason |
| `canary.rollback` | `POST /api/canaries/{id}/rollback` | `canary:<id>` (`canary:unknown` for invalid id) | success: `reason=<reason>`; failure reason |
| `user.create` | `POST /api/users` | `user:<name>` (bad body/bad username: `user:unknown`) | success: `role=<role>`; failure reason (**never logs passwords**) |
| `user.delete` | `DELETE /api/users/{name}` | `user:<name>` | success: `role=<role>`; failure reason |
| `secret.upsert` | `POST /api/secrets` | `secret:<name>` (bad body/bad name: `secret:unknown`) | success: `name=<name>`; failure reason (**never logs values**) |
| `secret.delete` | `DELETE /api/secrets/{name}` | `secret:<name>` | success: `name=<name>`; failure reason |
| `scm.push` | webhook dispatch successfully creates a run (github/gitea/gitlab) | `run:<id>` | `repo=<name> ref=<branch>` |
| `scm.pull_request` | same (PR/MR events) | `run:<id>` | `repo=<name> pr=<number>` |
| `scm.invalid` | webhook rejected: 403 (invalid or missing signature/token) / 413 (payload > 10MiB), each of the github/gitea/gitlab endpoints | `scm:<provider>` | 403: github `invalid signature`, gitea `invalid signature or token`, gitlab `invalid token`; 413: `payload too large`. Used to observe brute-force/probing against SCM endpoints |

**Not recorded**: **success paths** of GET read requests, `/healthz`,
`/api/agent/*` success paths (machine noise; 401s on agent endpoints are
covered by `auth.deny`), SSE streams, runs triggered internally by
cron/scheduler (already visible via the `trigger` column of the runs
table), webhook 503 (`FLOWSTALLION_WEBHOOK_SECRET` not configured,
fail-closed) — that branch reveals no credential attempt, and recording
while the secret is unconfigured would flood the audit table (decision:
do not record).

Note: when auth is on, 401/403 on **any method** (including GET) records
`auth.deny` (`requireRole` does not distinguish methods) — every RBAC
denial leaves a trace.

## Table Schema

```sql
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,              -- RFC3339 UTC (stamped automatically on write)
  actor TEXT NOT NULL,           -- "bob" | "anonymous" | "scm:github" ...
  action TEXT NOT NULL,          -- closed set, see table above
  target TEXT NOT NULL,          -- "run:5" | "pipeline:demo" | "user:bob" | "POST /api/users" ...
  outcome TEXT NOT NULL,         -- ok | invalid | denied | not_found | conflict | error
  detail TEXT NOT NULL DEFAULT '',  -- ≤2000 chars, key=value; must never contain passwords/secret values
  src TEXT NOT NULL DEFAULT ''     -- client IP (host part of RemoteAddr; empty when parsing fails)
)
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events (actor, id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, id);
```

- **actor**: auth on and the request carries a valid user token →
  username; otherwise `anonymous`. Webhooks are explicitly labeled
  `scm:github` / `scm:gitea` / `scm:gitlab`. When auth is off, all
  requests are `anonymous`.
- **outcome** is mapped from the HTTP status code (table-driven):
  2xx→`ok`, 400→`invalid`, 401/403→`denied`, 404→`not_found`,
  409→`conflict`, ≥500→`error`, other 4xx→`invalid`.
- **Immutable (append-only)**: the store only exposes `AddAuditEvent` /
  `ListAuditEvents` (plus `PurgeAuditEventsByAge` /
  `PurgeAuditEventsKeepLast` used by the retention policy); there is no
  UPDATE path.
- **Retention**: audit_events are driven by `FLOWSTALLION_LOG_RETENTION`
  together with logs/canary events (scheduler `RetentionTick`, at start
  plus every 5 minutes):
  - `30d` style by age: deletes events whose `ts` is older than the cutoff;
  - `runs=N` style by count: keeps the newest N events (counted per event, not per run) and deletes older ones.

## Bypass Semantics

An audit write failure **never** affects the primary request's response
code/body: a `record` failure only prints one warning line to stderr.
Audit is an observability layer, not a business write path.

## Query: GET /api/audit

Roles viewer and above. Query parameters:

- `actor` / `action` / `target` — exact-match filters (optional)
- `after` — id cursor, returns only `id < after` (for paging; invalid value → 400)
- `since` — RFC3339 time lower bound, returns only `ts >= since` (invalid value → 400);
  when both are given, they combine with AND
- `limit` — page size; default 50, >200 is clamped to 200 (invalid value → 400)

`ORDER BY id DESC` (newest first), returns `{"events": [...]}` (`[]`
when empty, not null):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/audit?action=run.trigger&limit=20'
```

```json
{
  "events": [
    {
      "id": 42,
      "ts": "2026-10-28T12:00:00Z",
      "actor": "bob",
      "action": "run.trigger",
      "target": "run:7",
      "outcome": "ok",
      "detail": "trigger=manual source_ref=refs/heads/main",
      "src": "127.0.0.1"
    }
  ]
}
```

## CLI: flowstallion audit

```bash
flowstallion audit                                  # last 20 events
flowstallion audit --limit 100 --actor admin        # filter by actor
flowstallion audit --action auth.deny --after 42    # page (only id < 42)
flowstallion audit --since 2026-10-29T00:00:00Z     # only events since a given time
```

`--limit` defaults to 20, max 200 (out of range errors out). Output is a
fixed-width table: `ts  actor  action  target  outcome`; prints
`No audit events found.` when there are no events. The session token
works the same as with `flowstallion login` and other commands
(`FLOWSTALLION_SERVER` / `FLOWSTALLION_TOKEN` or the saved login config).

## Security and Compliance Points

- **No sensitive values in the audit log**: login-failure detail carries
  only the username; `secret.*` events carry only names; `user.create`
  only the role. Tests pin this down with assertions.
- **detail ≤ 2000 characters** (rune-safe truncation), preventing large
  bodies from blowing up the table.
- **No control characters in detail**: `recordAs` replaces `\n`/`\r`/`\t`
  with spaces before writing, preventing user-controlled strings (e.g.
  the role field) from forging a second audit line.
- All fields are written parameterized; user input never enters SQL.
