#!/usr/bin/env bash
# FlowStallion cloudflared tunnel manager
# Usage: tunnel.sh {start|stop|status|restart|doctor|install|install-sync|uninstall|sync-webhook [--dry-run]}
#
# Machine-specific values (GH_REPO, GH_TOKEN_FILE, CLOUDFLARED) are NOT
# hardcoded here. Put them in the environment or in
# ~/.flowstallion/tunnel.env, e.g.:
#   GH_REPO=owner/repo
#   GH_TOKEN_FILE="$HOME/.flowstallion/gh-token"
# When GH_REPO is unset, GitHub-dependent steps (doctor webhook check,
# sync-webhook, alerting) skip gracefully instead of failing.

set -euo pipefail

LAUNCHD_LABEL="com.flowstallion.cloudflared"
PLIST_PATH="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
SYNC_LABEL="com.flowstallion.tunnel-sync"
SYNC_PLIST="${HOME}/Library/LaunchAgents/${SYNC_LABEL}.plist"
LOG_DIR="${HOME}/Library/Logs/flowstallion"
LOG_FILE="${LOG_DIR}/cloudflared.log"
ERROR_LOG="${LOG_DIR}/cloudflared-error.log"
SYNC_LOG="${LOG_DIR}/tunnel-sync.log"
URL="http://localhost:8080"
CLOUDFLARED="${CLOUDFLARED:-/opt/homebrew/bin/cloudflared}"
# GitHub repository (owner/repo) whose webhook this machine manages.
# Defaults empty: the GitHub-dependent steps then skip gracefully.
GH_REPO="${GH_REPO:-}"
GH_WEBHOOK_PATH="/api/webhooks/github"
GH_TOKEN_FILE="${GH_TOKEN_FILE:-/tmp/gh-token}"
# Load local overrides if present (machine-specific config, not tracked).
if [[ -f "${HOME}/.flowstallion/tunnel.env" ]]; then
    # shellcheck disable=SC1091
    . "${HOME}/.flowstallion/tunnel.env"
fi
# Sync-failure bookkeeping (resilience batch): every non-dry-run sync-webhook
# run appends its outcome to STATUS_FILE; after ALERT_THRESHOLD consecutive
# failed runs we post a GitHub check-run alert, re-alerting at most once per
# ALERT_COOLDOWN_S. A successful run resets the counter and posts a recovery
# check-run when the streak was >= ALERT_THRESHOLD.
STATUS_FILE="${HOME}/.flowstallion/tunnel-sync-status.json"
ALERT_THRESHOLD=3
ALERT_COOLDOWN_S=21600

# --- helpers ---

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[tunnel] $*"; }

# cloudflared writes the "Your Tunnel has been assigned" URL line to stderr
# (ERROR_LOG); prefer it, fall back to the stdout log.
latest_url() {
    local u
    u=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "${ERROR_LOG}" 2>/dev/null | tail -1 || true)
    if [[ -z "${u}" ]]; then
        u=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "${LOG_FILE}" 2>/dev/null | tail -1 || true)
    fi
    printf '%s' "${u}"
}

check_cloudflared() {
    if [[ ! -x "${CLOUDFLARED}" ]]; then
        die "cloudflared not found at ${CLOUDFLARED}. Install: brew install cloudflared"
    fi
}

get_pid() {
    # Prefer launchd-managed process; fall back to pgrep.
    # NOTE: `launchctl list <label>` prints a plist (not a table); the PID
    # lives in a line like `"PID" = 97303;` (absent when not running).
    if launchctl list "${LAUNCHD_LABEL}" 2>/dev/null | grep -qE '"PID" = [0-9]+'; then
        launchctl list "${LAUNCHD_LABEL}" 2>/dev/null | grep -oE '"PID" = [0-9]+' | grep -oE '[0-9]+'
    else
        pgrep -f "cloudflared tunnel.*--url ${URL}" 2>/dev/null | head -1 || true
    fi
}

is_running() {
    local pid
    pid=$(get_pid)
    [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

# --- sync status & alerting (resilience batch R2) ---

# Record one sync-webhook outcome in STATUS_FILE and print "decision streak":
#   decision: none | alert-failure | alert-recovery
#   streak:   failed-run counter relevant to the message
# $1: ok | failed; $2: failure reason (failed only). Dry-run callers must NOT
# call this — dry runs never mutate state.
record_sync_result() {
    PH_SYNC_RESULT="$1" PH_SYNC_ERR="${2:-}" PH_SYNC_URL="${url:-}" \
    PH_SYNC_THRESHOLD="${ALERT_THRESHOLD}" PH_SYNC_COOLDOWN_S="${ALERT_COOLDOWN_S}" \
    PH_SYNC_STATUS_FILE="${STATUS_FILE}" python3 - <<'PY'
import json, os, tempfile, time

path = os.environ["PH_SYNC_STATUS_FILE"]
threshold = int(os.environ["PH_SYNC_THRESHOLD"])
cooldown = float(os.environ["PH_SYNC_COOLDOWN_S"])
try:
    with open(path) as f:
        st = json.load(f)
except Exception:
    st = {}

def _num(value, cast):
    # A hand-edited/corrupt status file must not crash the cycle; fall back
    # to the default so the counter restarts instead of freezing (review m2).
    try:
        return cast(value)
    except Exception:
        return cast(0)

now = time.time()
url = os.environ.get("PH_SYNC_URL", "")
if url:
    st["url"] = url
stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
if os.environ["PH_SYNC_RESULT"] == "ok":
    was = _num(st.get("failures", 0), int)
    st.update(last_result="ok", failures=0, error=None, ts=now)
    decision = "alert-recovery" if was >= threshold else "none"
    if decision == "alert-recovery":
        st["last_alert"] = "recovery " + stamp
    streak = was
else:
    was = _num(st.get("failures", 0), int)
    st.update(last_result="failed", failures=was + 1, ts=now,
              error=os.environ.get("PH_SYNC_ERR") or st.get("error") or "unknown")
    # NOTE: the cooldown stamp (last_alert_ts) is deliberately NOT written here.
    # It is committed by commit_failure_alert() only after GitHub delivery
    # actually succeeded — otherwise one failed delivery would silently eat
    # the whole 6h cooldown window (review M1, 2026-10-28).
    due = was + 1 >= threshold and now - _num(st.get("last_alert_ts", 0), float) >= cooldown
    decision = "alert-failure" if due else "none"
    streak = was + 1
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
with os.fdopen(fd, "w") as f:
    json.dump(st, f, indent=2)
os.replace(tmp, path)
print(decision, streak)
PY
}

# Post an alert to GitHub. Prefer a check-run on the repo's head commit
# (works when the token is a GitHub App installation token); PATs cannot
# create check-runs (HTTP 403 "must authenticate via a GitHub App",
# verified 2026-10-28), so failure alerts fall back to an issue tagged
# flowstallion-alert. Recovery notices only use the check-run channel (an
# issue per recovery would be spam).
# Returns 0 when the alert reached GitHub (check-run or issue), 1 otherwise —
# callers use that to decide whether the 6h cooldown stamp is committed.
# $1: failure|success; $2: short title; $3: summary
post_alert() {
    local token sha payload code icode
    if [[ -z "${GH_REPO}" ]]; then
        info "[WARN] alert skipped: GH_REPO not set; nothing delivered"
        return 1
    fi
    if [[ ! -f "${GH_TOKEN_FILE}" ]]; then
        info "[WARN] alert skipped: ${GH_TOKEN_FILE} missing; nothing delivered"
        return 1
    fi
    token=$(cat "${GH_TOKEN_FILE}")
    sha=$(curl -s -m 15 -H "Authorization: token ${token}" \
        "https://api.github.com/repos/${GH_REPO}/commits/main" 2>/dev/null \
        | python3 -c 'import json, sys; print(json.load(sys.stdin).get("sha", ""))' 2>/dev/null || true)
    if [[ -z "${sha}" ]]; then
        # The token may be the broken thing (which is why we are alerting).
        # Fall back to the last head sha cached by a previous successful
        # lookup; check-runs accept any commit in the repo.
        sha=$(python3 -c '
import json, os
try:
    print(json.load(open(os.path.expanduser("~/.flowstallion/tunnel-sync-status.json"))).get("last_head_sha", ""))
except Exception:
    print("")' 2>/dev/null || true)
    fi
    if [[ -z "${sha}" ]]; then
        info "[WARN] alert skipped: cannot resolve head sha of ${GH_REPO} (token unusable and no cached sha)"
        return 1
    fi
    # Cache the sha for future fallbacks.
    PH_HEAD_SHA="${sha}" python3 -c '
import json, os, tempfile
p = os.path.expanduser("~/.flowstallion/tunnel-sync-status.json")
try:
    st = json.load(open(p))
except Exception:
    st = {}
st["last_head_sha"] = os.environ["PH_HEAD_SHA"]
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p) or ".")
with os.fdopen(fd, "w") as f:
    json.dump(st, f, indent=2)
os.replace(tmp, p)' 2>/dev/null || true
    if [[ "${1}" == "success" ]]; then
        payload=$(python3 -c '
import json, sys
print(json.dumps({
    "name": "flowstallion-tunnel-sync",
    "head_sha": sys.argv[1],
    "status": "completed",
    "conclusion": "success",
    "output": {"title": sys.argv[2], "summary": sys.argv[3][:65000]},
}, ensure_ascii=False))' "${sha}" "$2" "$3")
        code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST \
            -H "Authorization: token ${token}" -H "Content-Type: application/json" \
            "https://api.github.com/repos/${GH_REPO}/check-runs" -d "${payload}" || echo 000)
        code="${code:0:3}"
        if [[ "${code}" == "201" ]]; then
            info "[ALERT] posted recovery check-run for ${GH_REPO}"
            return 0
        fi
        info "[WARN] recovery check-run POST returned HTTP ${code} (recovery also in local status file)"
        return 1
    fi
    # Failure: try the check-run channel first...
    payload=$(python3 -c '
import json, sys
print(json.dumps({
    "name": "flowstallion-tunnel-sync",
    "head_sha": sys.argv[1],
    "status": "completed",
    "conclusion": "failure",
    "output": {"title": sys.argv[2], "summary": sys.argv[3][:65000]},
}, ensure_ascii=False))' "${sha}" "$2" "$3")
    code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: token ${token}" -H "Content-Type: application/json" \
        "https://api.github.com/repos/${GH_REPO}/check-runs" -d "${payload}" || echo 000)
    code="${code:0:3}"
    if [[ "${code}" == "201" ]]; then
        info "[ALERT] posted failure check-run for ${GH_REPO}"
        return 0
    fi
    info "[WARN] check-run POST returned HTTP ${code}; falling back to issue alert"
    # ...then an issue (works with a plain PAT).
    icode=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: token ${token}" -H "Content-Type: application/json" \
        "https://api.github.com/repos/${GH_REPO}/issues" -d "$(python3 -c '
import json, sys
print(json.dumps({
    "title": "flowstallion tunnel-sync: " + sys.argv[1],
    "body": sys.argv[2] + "\n\n_auto-posted by tunnel.sh sync-webhook (label: flowstallion-alert)_",
    "labels": ["flowstallion-alert"],
}, ensure_ascii=False))' "$2" "$3")" || echo 000)
    icode="${icode:0:3}"
    if [[ "${icode}" == "201" ]]; then
        info "[ALERT] posted failure issue for ${GH_REPO}"
        return 0
    fi
    info "[WARN] issue alert POST returned HTTP ${icode} (no working alert channel; state stays in ${STATUS_FILE})"
    return 1
}

# Commit the 6h cooldown stamp AFTER a failure alert was actually delivered;
# a failed delivery must not eat the cooldown window (retry on the next cycle).
commit_failure_alert() {
    PH_SYNC_STATUS_FILE="${STATUS_FILE}" python3 - <<'PY'
import json, os, tempfile, time

path = os.environ["PH_SYNC_STATUS_FILE"]
try:
    with open(path) as f:
        st = json.load(f)
except Exception:
    st = {}
now = time.time()
st["last_alert_ts"] = now
st["last_alert"] = "failure " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
with os.fdopen(fd, "w") as f:
    json.dump(st, f, indent=2)
os.replace(tmp, path)
PY
}

# Record a failed sync cycle; post the failure check-run when the streak
# reaches ALERT_THRESHOLD (6h cooldown committed only on successful delivery).
sync_failed() {
    local decision streak
    read -r decision streak <<<"$(record_sync_result failed "$1")"
    if [[ "${decision}" == "alert-failure" ]]; then
        info "[ALERT] sync-webhook failed ${streak} consecutive cycles; posting GitHub alert"
        if post_alert failure "tunnel-sync failing" \
            "tunnel-sync has failed ${streak} consecutive cycles. Last reason: $1. Troubleshoot: launchctl list com.flowstallion.cloudflared / com.flowstallion.tunnel-sync; run bash ~/.flowstallion/tunnel.sh doctor manually."; then
            commit_failure_alert \
                || info "[WARN] cooldown stamp not committed; will re-alert next cycle"
        else
            info "[WARN] alert delivery failed; cooldown not committed, will retry next cycle"
        fi
    fi
}

# Record a healthy cycle; post the recovery check-run after a failed streak.
sync_ok() {
    local decision streak
    read -r decision streak <<<"$(record_sync_result ok "")"
    if [[ "${decision}" == "alert-recovery" ]]; then
        info "[ALERT] sync-webhook recovered after ${streak} failed cycles; posting GitHub alert"
        # Tolerate delivery failure: a failed recovery alert must not make the
        # whole sync-webhook run exit non-zero (review M2-new, 2026-10-28).
        post_alert success "tunnel-sync recovered" \
            "tunnel-sync has recovered (after ${streak} consecutive failed cycles); the webhook now points at the current public URL." \
            || info "[WARN] recovery alert not delivered (recovery state still recorded in ${STATUS_FILE})"
    fi
}

# --- commands ---

cmd_start() {
    if is_running; then
        info "tunnel already running (PID $(get_pid))"
        return 0
    fi
    check_cloudflared
    mkdir -p "${LOG_DIR}"
    info "starting cloudflared tunnel → ${URL}"
    if launchctl load -w "${PLIST_PATH}" 2>/dev/null; then
        info "started via launchd (${LAUNCHD_LABEL})"
    else
        # fallback: nohup
        nohup "${CLOUDFLARED}" tunnel --no-autoupdate --url "${URL}" \
            >"${LOG_FILE}" 2>"${ERROR_LOG}" &
        info "started via nohup (PID $!)"
    fi
    # Cloudflared's cold start (prechecks + connection) can take several
    # seconds; poll instead of a fixed short sleep.
    local deadline=$((SECONDS + 30))
    while ! is_running; do
        if ((SECONDS >= deadline)); then
            die "tunnel failed to start; check ${ERROR_LOG}"
        fi
        sleep 1
    done
    info "tunnel is up (PID $(get_pid))"
}

cmd_stop() {
    if ! is_running; then
        info "tunnel not running"
        return 0
    fi
    info "stopping tunnel (PID $(get_pid))…"
    launchctl unload "${PLIST_PATH}" 2>/dev/null || true
    local pid
    pid=$(get_pid)
    if [[ -n "${pid}" ]]; then
        kill "${pid}" 2>/dev/null || true
    fi
    info "stopped"
}

cmd_status() {
    if is_running; then
        local pid
        pid=$(get_pid)
        info "tunnel RUNNING (PID ${pid})"
        # try to grab the current tunnel URL from the logs
        local url
        url=$(latest_url)
        if [[ -n "${url}" ]]; then
            info "public URL: ${url}"
        fi
        # check if URL is still reachable (only when a URL was found)
        if [[ -n "${url}" ]]; then
            if curl -s -o /dev/null -w '%{http_code}' -m 5 "${url}" 2>/dev/null | grep -qE '^(200|301|302|404|405)$'; then
                info "public URL reachable ✓"
            else
                info "WARNING: public URL may be stale (tunnel reconnecting?)"
            fi
        else
            info "no public URL in log yet (tunnel may still be connecting)"
        fi
    else
        info "tunnel NOT running"
        return 1
    fi
}

cmd_restart() {
    cmd_stop
    sleep 1
    cmd_start
}

cmd_doctor() {
    info "=== FlowStallion Tunnel Doctor ==="
    # 1. binary
    if [[ -x "${CLOUDFLARED}" ]]; then
        info "[OK] cloudflared: $(${CLOUDFLARED} --version 2>/dev/null | head -1)"
    else
        info "[FAIL] cloudflared not found at ${CLOUDFLARED}"
    fi
    # 2. target reachable
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://localhost:8080/" 2>/dev/null || echo "000")
    if [[ "${code}" =~ ^(200|301|302|404|405)$ ]]; then
        info "[OK] scheduler reachable at http://localhost:8080 (HTTP ${code})"
    else
        info "[FAIL] scheduler not reachable at http://localhost:8080 (HTTP ${code})"
    fi
    # 3. tunnel process
    if is_running; then
        info "[OK] cloudflared process running (PID $(get_pid))"
    else
        info "[FAIL] cloudflared not running"
    fi
    # 4. public URL (cloudflared logs the assigned URL to stderr)
    local url
    url=$(latest_url)
    if [[ -n "${url}" ]]; then
        local pub_code
        pub_code=$(curl -s -o /dev/null -w '%{http_code}' -m 8 "${url}" 2>/dev/null || echo "000")
        if [[ "${pub_code}" =~ ^(200|301|302|404|405)$ ]]; then
            info "[OK] public URL reachable: ${url} (HTTP ${pub_code})"
        else
            info "[FAIL] public URL unreachable: ${url} (HTTP ${pub_code})"
        fi
    else
        info "[WARN] no public URL found in ${LOG_FILE} (tunnel may not have connected yet)"
    fi
    # 5. GitHub webhook
    if [[ -z "${GH_REPO}" ]]; then
        info "[SKIP] GH_REPO not set (see ~/.flowstallion/tunnel.env); cannot check GitHub webhook"
    elif [[ ! -f "${GH_TOKEN_FILE}" ]]; then
        info "[SKIP] no ${GH_TOKEN_FILE}, cannot check GitHub webhook"
    else
        local gh_token
        gh_token=$(cat "${GH_TOKEN_FILE}")
        local hooks
        hooks=$(curl -s -H "Authorization: token ${gh_token}" \
            "https://api.github.com/repos/${GH_REPO}/hooks" 2>/dev/null || echo "[]")
        local active
        active=$(python3 -c "
import json,sys
hooks=json.loads(sys.argv[1])
for h in hooks:
    if h.get('config',{}).get('url','').endswith('/api/webhooks/github'):
        print(h['id'], h.get('active'), h.get('test_url',''))
" "${hooks}" 2>/dev/null || echo "none")
        if [[ -n "${active}" ]]; then
            info "[OK] GitHub webhook configured: ${active}"
        else
            info "[WARN] no active GitHub webhook pointing to tunnel found"
        fi
    fi
    # 6. webhook sync status (resilience batch R2)
    if [[ -f "${STATUS_FILE}" ]]; then
        local ss
        if ss=$(python3 -c '
import json, os, time
try:
    st = json.load(open(os.path.expanduser("~/.flowstallion/tunnel-sync-status.json")))
except Exception:
    raise SystemExit(1)
ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.get("ts", 0)))
print(" ".join([
    "last_result=" + str(st.get("last_result", "?")),
    "failures=" + str(st.get("failures", 0)),
    "url=" + str(st.get("url", "?")),
    "last_run=" + ts,
    "last_alert=" + str(st.get("last_alert") or "never"),
]))' 2>/dev/null); then
            case "${ss}" in
                *failures=0*) info "[OK] webhook sync: ${ss}" ;;
                *) info "[WARN] webhook sync: ${ss}" ;;
            esac
        else
            info "[WARN] webhook sync status unreadable: ${STATUS_FILE}"
        fi
    else
        info "[WARN] no webhook sync status yet (${STATUS_FILE}; run sync-webhook once)"
    fi
    info "=== doctor complete ==="
}

cmd_install() {
    check_cloudflared
    mkdir -p "$(dirname "${PLIST_PATH}")"
    info "writing launchd plist → ${PLIST_PATH}"
    cat > "${PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${CLOUDFLARED}</string>
        <string>tunnel</string>
        <string>--no-autoupdate</string>
        <string>--url</string>
        <string>${URL}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>${ERROR_LOG}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST
    launchctl load -w "${PLIST_PATH}"
    info "installed & started. Manage with: tunnel.sh {start|stop|status|restart}"
}

cmd_sync_webhook() {
    # Re-point the GitHub webhook at the current public tunnel URL.
    # No-op when in-sync; degrades to exit 0 (no error) when the public URL,
    # GH_REPO, or the token file is unavailable, so it is safe to run on a
    # schedule.
    local dry_run=0
    if [[ "${1:-}" == "--dry-run" ]]; then
        dry_run=1
    fi

    if [[ -z "${GH_REPO}" ]]; then
        info "[SKIP] GH_REPO not set (see ~/.flowstallion/tunnel.env); cannot sync webhook"
        return 0
    fi

    local url
    url=$(latest_url)
    if [[ -z "${url}" ]]; then
        info "no public URL in logs; nothing to sync"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "no public URL in cloudflared logs (tunnel dead?)"
        fi
        return 0
    fi

    # Guard: a dead/expired trycloudflare domain answers 403 at the CF edge,
    # 530 after the edge detects the tunnel is down (empirically observed
    # 2026-10-28: ~20s grace window returning 200, then 530), or the
    # connection fails outright (000). Only our app's own codes count as
    # alive — never repoint a working hook to a dead URL.
    local probe
    probe=$(curl -s -o /dev/null -w '%{http_code}' -m 8 "${url}" 2>/dev/null || true)
    probe="${probe:0:3}"
    if [[ ! "${probe}" =~ ^(200|301|302|404|405)$ ]]; then
        info "[WARN] public URL ${url} not serving our app (HTTP ${probe:-000}); tunnel may be dead, skipping"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "public URL not serving (HTTP ${probe})"
        fi
        return 0
    fi

    if [[ ! -f "${GH_TOKEN_FILE}" ]]; then
        info "[SKIP] no ${GH_TOKEN_FILE}; cannot sync webhook"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "GitHub token file ${GH_TOKEN_FILE} missing"
        fi
        return 0
    fi
    local token
    token=$(cat "${GH_TOKEN_FILE}")
    local api_base="https://api.github.com/repos/${GH_REPO}/hooks"

    local resp hooks http found
    resp=$(curl -s -m 15 -w $'\n%{http_code}' \
        -H "Authorization: token ${token}" "${api_base}" || printf '\n000')
    http="${resp##*$'\n'}"
    hooks="${resp%$'\n'*}"
    if [[ "${http}" != "200" ]]; then
        info "[WARN] GitHub hooks list failed (HTTP ${http}); skipping sync"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "GitHub hooks list failed (HTTP ${http})"
        fi
        return 0
    fi
    found=$(python3 -c '
import json, sys
try:
    hooks = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
if not isinstance(hooks, list):
    sys.exit(0)
# Prefer an active hook when several match the webhook path.
best = None
for h in hooks:
    cfg = h.get("config") or {}
    u = str(cfg.get("url", ""))
    if not u.endswith("/api/webhooks/github"):
        continue
    active = bool(h.get("active"))
    if best is None or (active and not best[0]):
        best = (active, h.get("id"), u)
if best is not None:
    print(best[1])
    print(best[2])
' "${hooks}" 2>/dev/null || true)
    if [[ -z "${found}" ]]; then
        info "[WARN] no webhook found"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "no webhook found on ${GH_REPO}"
        fi
        return 0
    fi
    local id cur
    { IFS= read -r id; IFS= read -r cur; } <<< "${found}"

    local want="${url}${GH_WEBHOOK_PATH}"
    if [[ "${cur}" == "${want}" ]]; then
        info "webhook ${id} already points at ${want}"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_ok
        fi
        return 0
    fi
    if [[ ${dry_run} -eq 1 ]]; then
        info "[dry-run] would PATCH hook ${id}: ${cur} -> ${want}"
        return 0
    fi

    # IMPORTANT: GitHub's webhook update REPLACES the whole config object, so
    # an url-only PATCH silently wipes the signing secret (empirically
    # verified 2026-10-28: url-only PATCH -> next delivery had no
    # X-Hub-Signature-256 -> scheduler 403). Always send url + content_type +
    # secret together. The secret lives outside the repo (env var
    # GH_WEBHOOK_SECRET or ~/.flowstallion/webhook-secret, chmod 600).
    local secret="${GH_WEBHOOK_SECRET:-}"
    if [[ -z "${secret}" && -f "${HOME}/.flowstallion/webhook-secret" ]]; then
        secret=$(tr -d '[:space:]' < "${HOME}/.flowstallion/webhook-secret")
    fi
    if [[ -z "${secret}" ]]; then
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "webhook secret not found"
        fi
        die "webhook secret not found (set GH_WEBHOOK_SECRET or ~/.flowstallion/webhook-secret); refusing to PATCH to avoid wiping the hook's secret"
    fi
    if [[ ! "${secret}" =~ ^[A-Za-z0-9_-]+$ ]]; then
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "webhook secret invalid"
        fi
        die "webhook secret contains unexpected characters; refusing to PATCH"
    fi

    info "PATCH webhook ${id}: ${cur} -> ${want}"
    local presp pcode
    presp=$(curl -s -m 15 -X PATCH \
        -w $'\n%{http_code}' \
        -H "Authorization: token ${token}" \
        -H "Content-Type: application/json" \
        "${api_base}/${id}" \
        -d "{\"config\":{\"url\":\"${want}\",\"content_type\":\"json\",\"secret\":\"${secret}\"}}" || printf '\n000')
    pcode="${presp##*$'\n'}"
    if [[ "${pcode}" != "200" ]]; then
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "PATCH hook ${id} failed (HTTP ${pcode})"
        fi
        die "PATCH hook ${id} failed (HTTP ${pcode}); want: ${want}"
    fi

    # Read back and verify the repoint actually took effect.
    local resp2 http2 hooks2 cur2
    resp2=$(curl -s -m 15 -w $'\n%{http_code}' \
        -H "Authorization: token ${token}" "${api_base}" || printf '\n000')
    http2="${resp2##*$'\n'}"
    if [[ "${http2}" != "200" ]]; then
        if [[ ${dry_run} -eq 0 ]]; then
            sync_failed "readback of hook ${id} failed (HTTP ${http2})"
        fi
        die "readback of hook ${id} failed (HTTP ${http2}); want: ${want}"
    fi
    hooks2="${resp2%$'\n'*}"
    cur2=$(python3 -c '
import json, sys
try:
    hooks = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
for h in hooks:
    if h.get("id") == int(sys.argv[2]):
        print((h.get("config") or {}).get("url", ""))
        break
' "${hooks2}" "${id}" 2>/dev/null || true)
    if [[ "${cur2}" == "${want}" ]]; then
        info "webhook ${id} repointed: ${cur} -> ${want}"
        if [[ ${dry_run} -eq 0 ]]; then
            sync_ok
        fi
        return 0
    fi
    if [[ ${dry_run} -eq 0 ]]; then
        sync_failed "webhook ${id} repoint not effective (readback: ${cur2:-<empty>})"
    fi
    die "webhook ${id} repoint not effective (readback: ${cur2:-<empty>}); want: ${want}"
}

cmd_install_sync() {
    # Periodic webhook re-point: launchd runs `tunnel.sh sync-webhook`
    # every 60s. Reference copy in repo:
    #   scripts/com.flowstallion.tunnel-sync.plist
    # NOTE: launchd agents cannot read ~/Documents (macOS TCC denies
    # /bin/bash access with EPERM), so a copy of this script is staged to
    # ~/.flowstallion/ and the plist points at the staged copy. Re-run
    # install-sync after editing tunnel.sh to refresh the copy.
    local repo_script
    repo_script="$(cd "$(dirname "$0")" && pwd)/tunnel.sh"
    local stage_dir="${HOME}/.flowstallion"
    local staged="${stage_dir}/tunnel.sh"
    mkdir -p "${stage_dir}"
    cp "${repo_script}" "${staged}"
    chmod +x "${staged}"
    info "staged script → ${staged}"
    mkdir -p "$(dirname "${SYNC_PLIST}")"
    info "writing launchd plist → ${SYNC_PLIST}"
    cat > "${SYNC_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SYNC_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${staged}</string>
        <string>sync-webhook</string>
    </array>
    <key>StartInterval</key>
    <integer>60</integer>
    <key>StandardOutPath</key>
    <string>${SYNC_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${SYNC_LOG}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST
    plutil -lint "${SYNC_PLIST}"
    # Idempotent: drop any previously loaded registration first (an old
    # one still points at the pre-staging path or a deleted file).
    launchctl unload "${SYNC_PLIST}" 2>/dev/null || true
    launchctl remove "${SYNC_LABEL}" 2>/dev/null || true
    if ! launchctl load -w "${SYNC_PLIST}"; then
        die "launchctl load failed for ${SYNC_LABEL}"
    fi
    info "installed periodic webhook sync: ${SYNC_LABEL} (every 60s; log: ${SYNC_LOG})"
}

cmd_uninstall() {
    launchctl unload "${PLIST_PATH}" 2>/dev/null || true
    rm -f "${PLIST_PATH}"
    launchctl unload "${SYNC_PLIST}" 2>/dev/null || true
    rm -f "${SYNC_PLIST}"
    info "launchd services removed (cloudflared + tunnel-sync)"
}

# --- main ---
case "${1:-}" in
    start)          cmd_start ;;
    stop)           cmd_stop ;;
    status)         cmd_status ;;
    restart)        cmd_restart ;;
    doctor)         cmd_doctor ;;
    install)        cmd_install ;;
    install-sync)   cmd_install_sync ;;
    sync-webhook)   cmd_sync_webhook "${2:-}" ;;
    uninstall)      cmd_uninstall ;;
    *)
        echo "Usage: $(basename "$0") {start|stop|status|restart|doctor|install|install-sync|uninstall|sync-webhook [--dry-run]}"
        exit 1
        ;;
esac
