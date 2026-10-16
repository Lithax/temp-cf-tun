#!/bin/bash
#
# Starts a cloudflared quick tunnel and publishes its trycloudflare URL to
# Cloudflare KV so the Worker knows where to proxy.
#
# Required env: SERVICE_URL, ACCOUNT_ID, NAMESPACE_ID, API_TOKEN
# Optional env: HTTP_HOST_HEADER   rewrite Host before it reaches your proxy
#               KV_KEY             KV key to write   (default: CF_TUNNEL_REDIRECT)
#               LOG_FILE           cloudflared log   (default: tunnel.log)
#               URL_WAIT_TRIES     polls for the URL (default: 15, 2s apart)

set -uo pipefail

KV_KEY="${KV_KEY:-CF_TUNNEL_REDIRECT}"
LOG_FILE="${LOG_FILE:-tunnel.log}"
URL_WAIT_TRIES="${URL_WAIT_TRIES:-15}"

log() { echo "[tunnel] $*"; }
die() { echo "[tunnel] CRITICAL ERROR: $*" >&2; exit 1; }

# ---------- preflight ----------

preflight() {
    cloudflared --version >/dev/null 2>&1 || die "cloudflared binary failed to execute."

    local var
    for var in SERVICE_URL ACCOUNT_ID NAMESPACE_ID API_TOKEN; do
        [ -n "${!var:-}" ] || die "$var is empty! Check your compose.yml / .env"
    done
}

# ---------- background: wait for URL, push to KV ----------

# Prints the first quick-tunnel URL found in the log (ignores api.trycloudflare.com).
extract_tunnel_url() {
    [ -f "$LOG_FILE" ] || return 1
    grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" \
        | grep -v '^https://api\.' \
        | head -n 1
}

push_to_kv() {
    local url="$1"
    curl -sS --fail -X PUT \
        "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${NAMESPACE_ID}/values/${KV_KEY}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: text/plain" \
        --data-binary "$url" >/dev/null
}

publish_url_when_ready() {
    log "Waiting for TryCloudflare URL..."

    local i url
    for ((i = 1; i <= URL_WAIT_TRIES; i++)); do
        if url=$(extract_tunnel_url) && [ -n "$url" ]; then
            log "Got URL: $url"
            if push_to_kv "$url"; then
                log "Worker KV updated. Traffic now proxies to $url"
            else
                log "FAILED to update KV (check ACCOUNT_ID / NAMESPACE_ID / API_TOKEN)."
            fi
            return 0
        fi
        sleep 2
    done

    log "FAILED to get tunnel URL after $((URL_WAIT_TRIES * 2))s, giving up."
    return 1
}

# ---------- foreground: cloudflared ----------

run_cloudflared() {
    local args=(
        tunnel
        --url "$SERVICE_URL"
        --protocol http2
        --no-tls-verify
        --no-autoupdate
    )

    if [ -n "${HTTP_HOST_HEADER:-}" ]; then
        log "Overriding Host header: $HTTP_HOST_HEADER"
        args+=(--http-host-header "$HTTP_HOST_HEADER")
    else
        log "HTTP_HOST_HEADER not set, no Host override"
    fi

    log "Starting cloudflared targeting $SERVICE_URL"
    # tee: the log file feeds the watcher, stdout keeps `docker logs` working.
    # pipefail makes this return cloudflared's exit code, not tee's.
    cloudflared "${args[@]}" 2>&1 | tee "$LOG_FILE"
}

# ---------- main ----------

preflight
: > "$LOG_FILE"

publish_url_when_ready &
WATCHER_PID=$!
trap 'kill "$WATCHER_PID" 2>/dev/null' EXIT

run_cloudflared