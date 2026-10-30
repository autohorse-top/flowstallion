# FlowStallion One-Click Self-Hosting

`docker compose up -d --build` brings up the full stack (scheduler +
runner agent); the console is at `http://localhost:8080`.

## Prerequisites

- Docker (or colima) running on the host; pipeline step images (e.g.
  `alpine`) are pulled/run by the host daemon
- The agent container calls the host daemon through a mounted socket to
  execute steps

## Environment Variables (optional)

| Variable | Default | Description |
|---|---|---|
| `DOCKER_SOCK` | `/var/run/docker.sock` | Host docker socket; macOS/colima example: `$HOME/.colima/default/docker.sock` |
| `FLOWSTALLION_WEBHOOK_SECRET` | empty | HMAC-SHA256 secret for the GitHub webhook (`POST /api/webhooks/github`); empty = disabled (503 fail-closed) |
| `FLOWSTALLION_AGENT_NAME` | `flowstallion-agent` | agent registration name |

## Examples

```bash
# macOS/colima
export DOCKER_SOCK="$HOME/.colima/default/docker.sock"
docker compose up -d --build

# enable the GitHub webhook
export FLOWSTALLION_WEBHOOK_SECRET="<secret>"
docker compose up -d --build
```

Data persists in the `flowstallion-data` named volume (`/data/flowstallion.db`).
