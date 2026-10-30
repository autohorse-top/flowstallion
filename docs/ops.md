# Ops Runbook: Public Internet Tunnel (cloudflared + GitHub webhook)

FlowStallion's public entry point is a **cloudflared trycloudflare
ephemeral tunnel**: it exposes local `http://localhost:8080`
(the scheduler) at a `*.trycloudflare.com` address, and GitHub webhooks
reach `/api/webhooks/github` through it.

> Placeholder convention: `<owner>/<repo>` = the target GitHub repo;
> `<hook-id>` = the webhook id; `<webhook secret>` = the secret you
> configured for the webhook; the token file defaults to
> `/tmp/gh-token` and can be overridden via the `GH_TOKEN_FILE` env var
> or `~/.flowstallion/tunnel.env` (same for `GH_REPO`; when unset,
> GitHub-related steps are skipped automatically).

## Known Limitations (stated honestly)

- **trycloudflare URLs expire after ~24h** and change on restart.
  launchd only guarantees the process stays alive, **it cannot keep the
  URL stable** — every tunnel restart issues a new URL; webhook
  re-pointing is handled automatically every 60 seconds by the
  `com.flowstallion.tunnel-sync` periodic job (see "URL change flow");
  the manual fallback still works.
- **The alert channel is GitHub only** (alert after 3 consecutive
  failures, recovery alert after recovery, 6h dedup); no push/SMS
  channel. Failure alerts prefer a check-run
  (`flowstallion-tunnel-sync`); when check-run creation is non-201
  (typically 403 due to PAT lacking permission, a platform constraint),
  it automatically falls back to creating an issue (label
  `flowstallion-alert`); recovery alerts use the check-run channel only
  to avoid spam. The 6h dedup **only takes effect after the alert is
  successfully delivered**; a delivery failure does not consume the
  cooldown and retries on the next cycle.
- Generate your own random webhook secret (`openssl rand -hex 20`);
  any specific secret that appears in this repo's docs is a sample
  value — never use it in a real repo.
- The GitHub patrol depends on a token file (default `/tmp/gh-token`,
  a PAT suffices; check-run alerts need a GitHub App installation
  token, and a PAT automatically falls back to the issue channel).
  /tmp is wiped on reboot — change it to a persistent path as needed
  (`GH_TOKEN_FILE`).

## Daily Patrol

```bash
cd <FlowStallion repo root>

# One-shot health check (binary / scheduler / tunnel process / public URL / GitHub webhook)
./scripts/tunnel.sh doctor

# Quick status (PID + public URL reachability)
./scripts/tunnel.sh status
```

Meaning of each doctor check:

| Check | Remedy on FAIL |
|---|---|
| cloudflared binary | `brew install cloudflared` (script defaults to `/opt/homebrew/bin/cloudflared`, overridable via the `CLOUDFLARED` env var) |
| scheduler unreachable | first `docker compose ps`; a live tunnel is useless if the scheduler is down |
| cloudflared process | `./scripts/tunnel.sh start` (run `install` first if launchd is not set up) |
| public URL unreachable | usually URL expiry / tunnel reconnection: `./scripts/tunnel.sh restart`; tunnel-sync re-points the webhook within 60s, or `./scripts/tunnel.sh sync-webhook` for immediate re-point |
| webhook not configured | see "URL change" manual fallback step 2 (or create the webhook manually in GitHub repo settings) |
| webhook sync WARN | inspect `~/.flowstallion/tunnel-sync-status.json` (last_result/failures/last reason) and `~/Library/Logs/flowstallion/tunnel-sync.log`; after 3 consecutive failures an alert is sent (check-run, falling back to issue in PAT environments, label `flowstallion-alert`) |

Log locations (when managed by launchd):

- stdout: `~/Library/Logs/flowstallion/cloudflared.log`
- stderr/allocation info (**the trycloudflare URL is here**; cloudflared
  writes the URL line to stderr):
  `~/Library/Logs/flowstallion/cloudflared-error.log`

## URL Change Flow (semi-automatic: launchd re-points every 60s)

The `com.flowstallion.tunnel-sync` launchd job (installed via
`install-sync`) runs `tunnel.sh sync-webhook` every 60 seconds: it
extracts the current public URL from the cloudflared logs, compares it
with the GitHub webhook's `config.url`, and on mismatch PATCHes it to
`<public-url>/api/webhooks/github` (preserving content_type=json and
the secret), and **verifies by re-reading after the PATCH** before
reporting success. After a tunnel restart issues a new URL, the
webhook is re-pointed within at most 60 seconds.

- Manual run (equivalent to triggering the periodic job once now):

  ```bash
  ./scripts/tunnel.sh sync-webhook          # PATCH + verify on mismatch
  ./scripts/tunnel.sh sync-webhook --dry-run   # only prints would-PATCH, no changes
  ```

- Degraded behavior (all exit 0; the periodic job is safe to run
  repeatedly): no public URL in the logs → no-op notice; `GH_REPO`
  unset → `[SKIP]`; token file missing → `[SKIP]`.
- Sync log: `~/Library/Logs/flowstallion/tunnel-sync.log`
  (in-sync line: `webhook <id> already points at …`; successful
  re-point line: `webhook <id> repointed: <old> -> <new>`)
- **Sync status and alerts**: every non-dry-run sync records
  last_result / failures / last reason / last alert time in
  `~/.flowstallion/tunnel-sync-status.json`. After 3 consecutive failures
  it posts a `flowstallion-tunnel-sync` check-run to the repo
  (conclusion=failure); the check-run is attached to the repo's main
  head sha and is visible in the GitHub UI.
  - **check-run non-201 fallback**: when the check-run POST returns
    non-201 (typically 403 PAT without permission, a platform
    constraint; also includes 401/422/5xx/000), it automatically
    falls back to creating an issue (label `flowstallion-alert`, title
    `flowstallion tunnel-sync: tunnel-sync failing`).
  - **6h dedup only takes effect after successful delivery**: a
    delivery failure (check-run non-201 and issue non-201, or missing
    token) does not consume the cooldown window; the next cycle keeps
    retrying. Recovery alerts use the check-run channel only
    (conclusion=success; on non-201 it only WARNs, does not spam
    issues, and does not affect sync-webhook exiting 0).
- Known residue: re-point timeliness is limited by the sync interval
  (60s), i.e. for up to 60 seconds after the tunnel gets a new URL,
  webhook deliveries hit the dead URL.

### Manual fallback (when sync is unavailable / first-time setup)

1. Get the new URL:

   ```bash
   grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' \
     ~/Library/Logs/flowstallion/cloudflared-error.log | tail -1
   ```

2. Update the GitHub webhook (`<hook-id>` per the actual response of
   `GET /repos/<owner>/<repo>/hooks`):

   ```bash
   # PATCH config.url to "https://<new-subdomain>.trycloudflare.com/api/webhooks/github"
   curl -s -X PATCH \
     -H "Authorization: token $(cat "$GH_TOKEN_FILE")" \
     "https://api.github.com/repos/<owner>/<repo>/hooks/<hook-id>" \
     -d '{"config":{"url":"https://<new-subdomain>.trycloudflare.com/api/webhooks/github","content_type":"json","secret":"<webhook secret>"},"events":["pull_request"],"active":true}'
   ```

   (In restricted environments curl may be blocked; use a Python
   `urllib` script instead.)

3. Test delivery: `POST /repos/<owner>/<repo>/hooks/<hook-id>/test`,
   then check `GET .../hooks/<hook-id>/deliveries` for
   `status=OK, status_code=200`. Also confirm
   `POST /api/webhooks/github -> 200` in the scheduler log.

## Service Management (launchd)

```bash
./scripts/tunnel.sh install         # tunnel process: write plist to ~/Library/LaunchAgents and load (RunAtLoad+KeepAlive)
./scripts/tunnel.sh install-sync    # webhook re-pointing: install a StartInterval=60 periodic job
./scripts/tunnel.sh start           # nohup fallback start when not installed
./scripts/tunnel.sh stop
./scripts/tunnel.sh restart
./scripts/tunnel.sh sync-webhook [--dry-run]   # manually re-point the webhook now
./scripts/tunnel.sh uninstall       # uninstall both launchd jobs (cloudflared + tunnel-sync)
```

- launchd labels:
  - `com.flowstallion.cloudflared` (tunnel process, KeepAlive)
  - `com.flowstallion.tunnel-sync` (webhook re-pointing, StartInterval=60,
    log at `~/Library/Logs/flowstallion/tunnel-sync.log`)
- tunnel-sync executes the **staged copy** `~/.flowstallion/tunnel.sh`
  (generated by install-sync): launchd agents cannot read
  `~/Documents` (macOS TCC returns EPERM to /bin/bash). **After editing
  `scripts/tunnel.sh`, you must re-run `install-sync`** to refresh the
  staged copy.
- plist source files: `scripts/com.flowstallion.cloudflared.plist` /
  `scripts/com.flowstallion.tunnel-sync.plist` (in-repo reference copies;
  paths use the `__HOME__` placeholder; `install` / `install-sync`
  regenerate a plist with real paths under `~/Library/LaunchAgents/`,
  so the reference copies never need manual editing)
- KeepAlive=true: the tunnel process is restarted on crash, but **the
  URL changes** — the tunnel-sync job re-points the webhook within 60
  seconds (see "URL change flow").
- Manually verify launchd state: `launchctl list com.flowstallion.cloudflared`
  (note the output is plist format; the PID is on the `"PID" = <n>;`
  line; that line is absent when the service is not running).

## Formal Production Deployment (public internet / production) Checklist

> Applies to: exposing FlowStallion to the public internet or running it
> long-term in production. The default `docker-compose.yml` is a
> **developer-friendly** config: auth off by default, no token on the
> agent endpoints, webhooks 503 by default. Work through the 6 items
> below before going live.

### 1. The five required env vars

| Variable | Description | How to generate |
|---|---|---|
| `FLOWSTALLION_AUTH=on` | enable AuthN/RBAC (default off = fully open; **required for public internet**) | fixed value |
| `FLOWSTALLION_ADMIN_USERNAME` | bootstrap admin username (takes effect when the users table is empty, first start only) | choose freely |
| `FLOWSTALLION_ADMIN_PASSWORD` | bootstrap admin password (≥8 chars) | strong password |
| `FLOWSTALLION_SECRET_KEY` | server-side secret vault key (64 hex or 32-byte base64); unset = secret features 503 fail-closed | `openssl rand -hex 32` |
| `FLOWSTALLION_WEBHOOK_SECRET` | SCM webhook secret (shared by github/gitea/gitlab); unset = webhook endpoints 503 fail-closed | `openssl rand -hex 20` |
| `FLOWSTALLION_AGENT_TOKEN` | agent machine token (must match on both the scheduler and agent sides; when auth is on, agent endpoints authenticate with it) | `openssl rand -hex 20` |

The scheduler service currently only passes through
`FLOWSTALLION_WEBHOOK_SECRET` / `FLOWSTALLION_SECRET_KEY` (see the compose
header comment); the remaining variables must be declared explicitly in
compose, e.g. by creating a `docker-compose.override.yml` (same
directory as `docker-compose.yml`; compose merges automatically):

```yaml
services:
  scheduler:
    environment:
      FLOWSTALLION_AUTH: "on"
      FLOWSTALLION_ADMIN_USERNAME: "admin"
      FLOWSTALLION_ADMIN_PASSWORD: "<strong password, never commit to git>"
      FLOWSTALLION_SECRET_KEY: "<openssl rand -hex 32>"
      FLOWSTALLION_WEBHOOK_SECRET: "<openssl rand -hex 20>"
      FLOWSTALLION_AGENT_TOKEN: "<openssl rand -hex 20>"
```

The agent-side `FLOWSTALLION_AGENT_TOKEN` is already declared in compose;
just put it in `.env` (the value must match the scheduler's; `.env` is
gitignored — never commit real values). Rebuild with
`docker compose up -d` after changes. **Public deployments must never
run with auth off + an empty agent token**: the scheduler prints
`WARNING FLOWSTALLION_AGENT_TOKEN is not set; /api/agent/* is open` at
startup.

### 2. Edge TLS termination (Caddy / nginx examples)

Inside the container it is plain HTTP (:8080); a public entry point
must terminate TLS.

Caddy (automatic cert issuance/renewal, least effort):

```
https://flowstallion.example.com {
	reverse_proxy scheduler:8080
}
```

nginx (note: the SSE log stream requires buffering disabled, otherwise
console logs are not live):

```nginx
server {
	listen 443 ssl;
	server_name flowstallion.example.com;
	ssl_certificate     /etc/ssl/flowstallion.crt;
	ssl_certificate_key /etc/ssl/flowstallion.key;

	location / {
		proxy_pass http://scheduler:8080;
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_buffering off;      # required for live SSE (run log stream) forwarding
	}
}
```

Note: behind a reverse proxy, the `RemoteAddr` the scheduler sees is
the proxy IP, so the audit log `src` field records the proxy IP rather
than the real client IP (the audit layer does not read
`X-Forwarded-For`); if you need precise source IPs, place the proxy and
the scheduler in the same trusted network segment and evaluate
yourself.

### 3. Block `/api/agent/*` at the edge (command-execution surface, never expose to the public internet)

`/api/agent/*` (register / claim / logs / finish) is the executor's
dedicated API; even with a token it should not be exposed to the public
internet — agents use the docker internal network
`http://scheduler:8080`, bypassing the edge proxy, so blocking it at
the edge does not affect functionality:

```
# Caddy (before reverse_proxy; the Caddyfile matches top-down)
handle /api/agent/* {
	respond "forbidden" 403
}
```

```nginx
# nginx
location /api/agent/ {
	return 403;
}
```

### 4. `flowstallion-data` volume backup (DB actual path `/data/flowstallion.db`)

The DB lives at `/data/flowstallion.db` inside the named volume
`flowstallion-data` (compose project-name prefix: `<project>_ph-data`, default
`flowstallion_ph-data`). The image is alpine and **does not include the
sqlite3 client**; two backup methods:

```bash
mkdir -p backups

# Method A (recommended): sqlite online hot backup, no service downtime
VOLUME="$(docker volume ls --format '{{.Name}}' | grep 'flowstallion-data$' | head -1)"
docker run --rm -v "$VOLUME":/data alpine:3.20 sh -c \
  'apk add --no-cache sqlite >/dev/null && sqlite3 /data/flowstallion.db ".backup /data/flowstallion-backup.db"'
docker compose cp scheduler:/data/flowstallion-backup.db "backups/flowstallion-$(date +%F).db"
docker compose exec -T scheduler rm -f /data/flowstallion-backup.db

# Method B: cold backup (stop scheduler/agent, copy the file, zero dependencies)
docker compose stop scheduler agent ai-agent
docker compose cp scheduler:/data/flowstallion.db "backups/flowstallion-$(date +%F).db"
docker compose start scheduler agent ai-agent
```

Recommendation: one backup per day (cron running method A), keep 7
daily + 30 weekly; the `flowstallion-cost` (cost ledger) / `flowstallion-repos` (PR
checkout cache) volumes are regenerable and need no backup.

### 5. Edge rate limiting on `/api/auth/login` (brute-force protection)

The login path has no per-IP throttling (PBKDF2 only raises the cost of
brute force); put rate limiting at the edge:

```
# Caddy (before reverse_proxy)
handle /api/auth/login {
	rate_limit {
		10/1m
	}
	reverse_proxy scheduler:8080
}
```

```nginx
# nginx (inside the http{} block)
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;

# inside server{}
location /api/auth/login {
	limit_req zone=login burst=5 nodelay;
	proxy_pass http://scheduler:8080;
}
```

### 6. Fully offline combination (optional): self-hosted SCM + local Ollama

It can run fully without depending on the public GitHub / cloud LLM:

- **SCM**: point self-hosted Gitea / GitLab webhooks at
  `POST /api/webhooks/gitea` (HMAC `X-Gitea-Signature` or plaintext
  `X-Gitea-Token`) / `POST /api/webhooks/gitlab` (plaintext
  `X-Gitlab-Token`), sharing the same `FLOWSTALLION_WEBHOOK_SECRET` as
  GitHub;
- **LLM (RCA)**: local Ollama; configure the ai-agent service with
  `FLOWSTALLION_LLM_BASE_URL=http://<ollama-host>:11434/v1`,
  `FLOWSTALLION_LLM_API_KEY=<any non-empty value>` (llm.py requires a
  non-empty key; Ollama locally does not validate it), and
  `FLOWSTALLION_LLM_MODEL=<model-name>` (OpenAI-compatible API, via
  `/chat/completions`).
