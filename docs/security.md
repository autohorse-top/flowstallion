# Security: Authentication, Secrets, and Scans (P6)

FlowStallion's P6 layer: local AuthN/RBAC, encrypted pipeline secrets, and
multi-tool security scanning. All implemented in the Go standard library
(no external crypto/HTTP dependencies).

## Stack Boundary

- Go: `pkg/auth` (PBKDF2 + sessions), `pkg/secret` (AES-256-GCM vault),
  `pkg/store` (users/sessions/secrets tables), REST API + RBAC
  middleware (`pkg/api`), the `flowstallion` CLI (login/user/secret), the web
  console login page, and `pkg/security` (trivy/gitleaks/semgrep runner).
- Python: P6 is pure Go; the agent only accesses `/api/agent/*` with its
  machine token (`X-Agent-Token`), no in-process mixing.

## Authentication and RBAC (P6①)

Off by default: set `FLOWSTALLION_AUTH=on` to enable. When off, all
requests run as a synthetic admin user `system`, exactly matching the
pre-P6 open behaviour (regression baseline).

### Passwords and sessions

- PBKDF2-HMAC-SHA256 (RFC 2898 §5.2), 100,000 rounds, 16-byte random
  salt, 32-byte key; storage format
  `pbkdf2-sha256$<iter>$<saltB64>$<hashB64>`. Verification uses a
  constant-time compare (`crypto/subtle`); malformed hashes always
  return false and never panic.
- Sessions: 32-byte random token (64 hex chars), stored in the SQLite
  `sessions` table, default TTL 168h (7 days), overridable via
  `FLOWSTALLION_SESSION_TTL` (Go duration syntax); expired sessions are
  purged by a background loop every 10 minutes.
- Client auth: `Authorization: Bearer <token>`. Unauthenticated web
  console → 302 to `/login`; unauthenticated API → 401.

### Role matrix (enforced only when auth is on)

`viewer` < `operator` < `admin` (privilege levels 1/2/3; unknown roles
are rejected):

| Endpoint | Required role |
|---|---|
| `GET /healthz`, `POST /api/auth/login`, `POST /api/webhooks/github` | open (webhooks authenticate with their own HMAC secret) |
| read-only `/api/*` (pipelines, runs, logs, events, scans, canaries, **`/api/cost`**, `/api/auth/me`) + `POST /api/auth/logout` | viewer |
| trigger / cancel / approve / reject runs, `POST /api/runs/{id}/scans`, create canary | operator |
| create/update pipeline (`POST /api/pipelines`), user management (`/api/users`), secret management (`/api/secrets`) | admin |
| `/api/agent/*` + `POST /api/runs/{id}/analysis` | machine: `X-Agent-Token` equal (constant-time) to `FLOWSTALLION_AGENT_TOKEN`; **or** an operator+ user token |

Bootstrap and operations:

- When auth is on and the users table is empty, the first admin is
  bootstrapped from `FLOWSTALLION_ADMIN_USERNAME` /
  `FLOWSTALLION_ADMIN_PASSWORD` (username 3–64 chars
  `[A-Za-z0-9._-]`, password ≥8 chars); missing credentials fail
  startup (fail-fast).
- Auth on while `FLOWSTALLION_AGENT_TOKEN` is unset: the agent endpoints
  (`/api/agent/*` and `POST /api/runs/{id}/analysis`) are **completely
  open, requiring no authentication at all**; treat this deployment as
  machine-untrusted. A startup WARNING is printed (not a failure). This
  env var must be set in production.
- CLI: `flowstallion login` (saves the token), `flowstallion users` (list users, admin),
  `flowstallion user add|del` (admin; `del` is aliased as `delete`).

## Pipeline Secrets (P6②)

- Key: `FLOWSTALLION_SECRET_KEY` — 64 hex chars, or base64 of a 32-byte key
  (with or without padding). **Unset = fail-closed**: the secret API
  returns 503, and pipelines declaring `secrets:` are rejected with 400
  at trigger time (there is no "plaintext fallback" legacy mode).
- Storage: values are encrypted with AES-256-GCM; blob =
  nonce(12) || ciphertext || tag(16), stored in the SQLite `secrets`
  table. Plaintext is only ever produced in memory at step-execution
  time; the platform itself never writes plaintext to disk.
- Management (admin only): `GET/POST/DELETE /api/secrets` +
  `flowstallion secret list|set|rm`; list never echoes values; `flowstallion secret set`
  reads the value from stdin (never argv/history); POST body capped at
  64 KiB.
- Injection: `secrets: [NAME]` in `flowstallion.yaml` +
  `env: {DB_PASSWORD: ${NAME}}`, resolved from encrypted storage at
  trigger/execution time; undeclared `${NAME}` references fail fast
  (trigger 400, including the empty-declaration-set case).

### Known limitations (leftover from P6 review — operators must read)

1. **Secrets echoed by commands are persisted to the logs.** If a step
   command prints a secret value (e.g. `echo $DB_PASSWORD`), the
   plaintext lands in the `logs` table and any viewer can read it via
   `GET /api/runs/{id}/logs`. This is inherent to a command-based
   runner: the platform only encrypts at-rest / in-transit data and does
   not control runner stdout. **Discipline: never echo secrets in
   pipeline commands.**
2. **Transient exposure of the agent host's argv.** Secrets are injected
   into containers via `docker run -e NAME=value ...`; the process list
   (`ps`) on the agent host can briefly show the plaintext. Harmless on
   a single-tenant agent host; treat a shared multi-tenant agent host as
   "host is trusted".

## Multi-tool security scanning (P6③, on top of P5 trivy)

- Tools: `trivy` (fs + image modes), `gitleaks`, `semgrep`; the API
  allowlist is `{trivy,gitleaks,semgrep}` (case-sensitive; any other
  value, including capitalized, → 400). `flowstallion scan --tool <t>`, default
  trivy; `--image` is only supported by trivy.
- Hard bounds: `POST /api/runs/{id}/scans` is operator-only; request
  body capped at 2 MiB (exceeding → 400); `report_json` > 1 MiB → 400
  rejected (the API does not truncate). `truncated=1` is only set by
  the `flowstallion scan` CLI when the tool's raw report exceeds 1 MiB, which
  pre-truncates it.
- Semantic fidelity: gitleaks exit 0/1 are both treated as a completed
  scan (findings live in the report file; an empty report normalizes to
  `[]`); a semgrep report containing a top-level `errors` array is
  treated as a scan failure rather than storing a bogus "clean" result;
  unknown severities only count toward FindingsCount.

## Cost page and access control (P6④)

- `GET /api/cost?by=pr|team&source=llm|cloud` (viewer+): the Go server
  reads the JSONL ledger (env `FLOWSTALLION_COST_LEDGER`, default
  `~/.flowstallion/cost-ledger.jsonl`), aggregates by descending cost
  (records / prompt / completion / total tokens / cost_usd), and returns
  `{"by": ..., "rows": [...], "total": {...}}`.
- Missing ledger → 200 with an empty result; bad line → 400 with the
  1-based physical line number in `error` (same semantics as the Python
  CLI strict mode).
- Web `/cost` page: unauthenticated → 302 to `/login`; the run page
  gains a "Security scans" section (viewer+ readable, raw JSON
  expandable, truncation flagged).
- In compose, the scheduler and ai-agent share the same ledger file via
  the named volume `flowstallion-cost` (both set
  `FLOWSTALLION_COST_LEDGER=/data/cost/cost-ledger.jsonl`).
