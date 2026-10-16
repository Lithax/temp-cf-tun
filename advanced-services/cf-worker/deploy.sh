#!/bin/bash
#
# Deploys the advanced gateway Worker to Cloudflare - one script, two jobs:
#
#   1. Secrets Store: finds or creates the account's store, then creates or
#      updates the two gateway secrets in it:
#        URL_SECRET           - the Worker 401s any request without it
#        PROXY_TUNNEL_SECRET  - stamped on proxied requests as X-Tunnel-Secret
#   2. Worker: uploads index.js as a module Worker, bound to those two
#      secrets plus the KV namespace that carries the current tunnel URL
#      (written by the cftunnel container).
#
# Then it makes sure the workers.dev route is on and sanity-checks that the
# Worker rejects a token-less request with 401.
#
# Uses only curl + jq against the Cloudflare API - no wrangler, no node.
#
# Config comes from ../.env (the same file the containers use) or the
# environment (environment wins):
#   ACCOUNT_ID  API_TOKEN  WORKER_NAME  NAMESPACE_ID
#   URL_SECRET  PROXY_TUNNEL_SECRET     (24-128 chars of A-Za-z0-9_-)
#   STORE_NAME  (optional, default: <WORKER_NAME>-secrets)
#
# Usage:
#   ./deploy.sh [worker-name] [--dry-run] [--plain-secrets]
#
#     --dry-run        show the plan (secrets masked), change nothing
#     --plain-secrets  bind as plain Worker secrets instead of Secrets Store
#                      (fallback for accounts without Secrets Store access)
#
# The API token (dash -> My Profile -> API Tokens) needs:
#   Workers Scripts:Edit     Workers KV Storage:Edit     Secrets Store:Edit
#   (make it a custom token - the "Edit Cloudflare Workers" template does
#    not include Secrets Store, and the store calls fail with a 403)
#
# Secret values are never printed or logged, and never accepted as CLI
# arguments (they would end up in shell history / ps).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env}"
API="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"
COMPAT_DATE="2025-09-01"
# API-versioning header wrangler sends for the subdomain endpoint
API_DATE_HEADER="Cloudflare-Workers-Script-Api-Date: 2025-08-01"

DRY_RUN=0
PLAIN_SECRETS=0
WORKER_NAME_ARG=""

log() { echo "[deploy] $*"; }
die() { echo "[deploy] CRITICAL ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Deploys the advanced gateway Worker to Cloudflare:
  1. creates/updates the two gateway secrets in the Secrets Store
  2. uploads index.js as a module Worker bound to them (+ the KV namespace)
  3. enables the workers.dev route and checks the Worker answers 401

Usage:
  ./deploy.sh [worker-name] [--dry-run] [--plain-secrets]

    --dry-run        show the plan (secrets masked), change nothing
    --plain-secrets  use plain Worker secrets instead of the Secrets Store

Config from ../.env or the environment: ACCOUNT_ID, API_TOKEN, WORKER_NAME,
NAMESPACE_ID, URL_SECRET, PROXY_TUNNEL_SECRET, STORE_NAME (optional).

API token needs: Workers Scripts:Edit, Workers KV Storage:Edit,
Secrets Store:Edit (a custom token - the "Edit Cloudflare Workers"
template does not include it).
EOF
    exit 0
}

# ---------- args ----------

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)       DRY_RUN=1 ;;
        --plain-secrets) PLAIN_SECRETS=1 ;;
        -h | --help)     usage ;;
        -*)              die "unknown option $1 (try --help)" ;;
        *)               WORKER_NAME_ARG="$1" ;;
    esac
    shift
done

# ---------- config ----------

load_env() {
    [ -f "$ENV_FILE" ] || die "no .env found at $ENV_FILE (copy .env.example, or export the variables yourself)"
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in '' | '#'*) continue ;; esac
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        if [[ "$val" =~ ^\"([^\"]*)\" ]]; then val="${BASH_REMATCH[1]}"; fi
        [ -n "${!key:-}" ] || export "$key=$val"
    done < "$ENV_FILE"
}

preflight() {
    command -v curl >/dev/null 2>&1 || die "curl is required"
    command -v jq   >/dev/null 2>&1 || die "jq is required"
    load_env

    WORKER_NAME="${WORKER_NAME_ARG:-${WORKER_NAME:-}}"
    STORE_NAME="${STORE_NAME:-${WORKER_NAME:+${WORKER_NAME}-secrets}}"

    local v
    for v in ACCOUNT_ID API_TOKEN WORKER_NAME NAMESPACE_ID URL_SECRET PROXY_TUNNEL_SECRET; do
        [ -n "${!v:-}" ] || die "$v is not set (add it to $ENV_FILE or export it)"
    done
    [[ "$WORKER_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] \
        || die "WORKER_NAME must be lowercase letters/digits/-/_ (got '$WORKER_NAME')"
    [[ "$NAMESPACE_ID" =~ ^[0-9a-f]{32}$ ]] \
        || die "NAMESPACE_ID must be a 32-hex-char KV namespace id"
    local s
    for s in URL_SECRET PROXY_TUNNEL_SECRET; do
        [[ "${!s}" =~ ^[A-Za-z0-9_-]{24,128}$ ]] \
            || die "$s must be 24-128 chars of A-Za-z0-9_- (try: openssl rand -hex 32)"
    done
    [ -f "$SCRIPT_DIR/index.js" ] || die "index.js not found next to deploy.sh"
}

# ---------- api helpers ----------

# Cloudflare answers a token that lacks a permission with HTTP 403 +
# code 10000 "Authentication error" - the same body for every endpoint and
# every missing permission, which is why the raw curl error is so useless.
# Map the failed call to the permission it needs, or spot a dead token.
# Prints "" when the failure is neither of those.
api_error_hint() { # PATH CURL_OUT -> hint text on stdout ("" if undiagnosable)
    local path="$1" out="$2" perm="" extra=""
    grep -q 'returned error: 40[013]' <<<"$out" || return 0
    grep -q '"code": *10000' <<<"$out" || return 0
    if ! grep -q 'returned error: 403' <<<"$out"; then
        printf '\n  what this means: the token itself was rejected (invalid,\n  expired, revoked, or a typo in API_TOKEN).\n'
        return 0
    fi
    case "$path" in
        *secrets_store*)
            perm="Secrets Store:Edit"
            extra='
  note: the "Edit Cloudflare Workers" token template does not include it -
  it has to be a custom token. And if "Secrets Store" is not offered in the
  permission editor at all, this account is not in the Secrets Store open
  beta: re-run with --plain-secrets to bind the two secrets as plain
  Worker secrets instead (identical runtime behavior).'
            ;;
        *storage/kv*) perm="Workers KV Storage:Edit" ;;
        *workers/*)   perm="Workers Scripts:Edit" ;;
        *)            return 0 ;;
    esac
    printf '\n  what this means: the token authenticated, but it lacks a permission\n  this endpoint needs (Cloudflare always says that as 403 + code 10000).\n  fix: dash -> My Profile -> API Tokens -> ... on the token -> Edit ->\n  Account Permissions -> add "%s" -> Save, then re-run this script.%s\n' "$perm" "$extra"
}

# cf METHOD PATH [JSON_BODY] -> prints the response body, dies on failure
cf() {
    local method="$1" path="$2" data="${3:-}" out rc=0
    local args=(curl -sS --fail-with-body --max-time 60 -X "$method" "$API$path"
        -H "Authorization: Bearer $API_TOKEN")
    if [ -n "$data" ]; then
        args+=(-H "Content-Type: application/json" --data "$data")
    fi
    out="$("${args[@]}" 2>&1)" || rc=$?
    [ "$rc" -eq 0 ] || die "API $method $path failed (curl exit $rc): $out$(api_error_hint "$path" "$out")"
    jq -e '.success == true' >/dev/null 2>&1 <<<"$out" \
        || die "API $method $path returned an error: $out"
    printf '%s' "$out"
}

# Enough of the value to tell two secrets apart, never enough to leak one.
mask() {
    printf '%s…(len %d, sha256 %s…)' "${1:0:2}" "${#1}" \
        "$(printf '%s' "$1" | sha256sum | cut -c1-12)"
}

# ---------- steps ----------

check_namespace() {
    if [ "$DRY_RUN" = 1 ]; then
        log "would: verify KV namespace ${NAMESPACE_ID:0:8}… exists"
        return
    fi
    local out
    out=$(cf GET "/accounts/$ACCOUNT_ID/storage/kv/namespaces/$NAMESPACE_ID") \
        || die "KV namespace not found - check NAMESPACE_ID (and that the token has Workers KV Storage:Edit)"
    log "KV namespace ok: $(jq -r '.result.title // "?"' <<<"$out")"
}

ensure_store() {
    if [ "$DRY_RUN" = 1 ]; then
        log "would: find or create Secrets Store '$STORE_NAME'"
        STORE_ID="(dry-run)"
        return
    fi
    local out count names
    out=$(cf GET "/accounts/$ACCOUNT_ID/secrets_store/stores")
    STORE_ID=$(jq -r --arg n "$STORE_NAME" '.result[]? | select(.name == $n) | .id' <<<"$out" | head -n1)
    if [ -z "$STORE_ID" ]; then
        count=$(jq -r '.result | length' <<<"$out")
        if [ "$count" -gt 0 ]; then
            names=$(jq -r '[.result[].name] | join(", ")' <<<"$out")
            die "no store named '$STORE_NAME', and this account already has: $names.
The Secrets Store beta allows one store per account - set STORE_NAME to one of those
in your .env (secrets for other purposes would then share that store), or delete the
existing store in the dash first."
        fi
        log "creating Secrets Store '$STORE_NAME'..."
        out=$(cf POST "/accounts/$ACCOUNT_ID/secrets_store/stores" "$(jq -n --arg n "$STORE_NAME" '{name: $n}')")
        STORE_ID=$(jq -r '.result.id' <<<"$out")
    fi
    log "using Secrets Store '$STORE_NAME' ($STORE_ID)"
}

upsert_secret() { # NAME VALUE COMMENT
    local name="$1" value="$2" comment="$3" sid out verb
    if [ "$DRY_RUN" = 1 ]; then
        log "would: create or update secret '$name' ($(mask "$value"))"
        return
    fi
    out=$(cf GET "/accounts/$ACCOUNT_ID/secrets_store/stores/$STORE_ID/secrets?search=$name")
    sid=$(jq -r --arg n "$name" '.result[]? | select(.name == $n) | .id' <<<"$out" | head -n1)
    if [ -n "$sid" ]; then
        out=$(cf PATCH "/accounts/$ACCOUNT_ID/secrets_store/stores/$STORE_ID/secrets/$sid" \
            "$(jq -n --arg v "$value" '{value: $v, scopes: ["workers"]}')")
        verb="updated"
    else
        # the API takes an array of secrets to create
        out=$(cf POST "/accounts/$ACCOUNT_ID/secrets_store/stores/$STORE_ID/secrets" \
            "$(jq -n --arg n "$name" --arg v "$value" --arg c "$comment" \
                '[{name: $n, value: $v, scopes: ["workers"], comment: $c}]')")
        verb="created"
    fi
    log "$verb secret '$name'"
}

upload_worker() {
    local metadata out rc=0
    if [ "$PLAIN_SECRETS" = 1 ]; then
        metadata=$(jq -cn \
            --arg ns "$NAMESPACE_ID" --arg us "$URL_SECRET" --arg ts "$PROXY_TUNNEL_SECRET" \
            --arg d "$COMPAT_DATE" \
            '{main_module: "index.js", compatibility_date: $d, bindings: [
                {type: "kv_namespace",    name: "TUNNEL_KV",          namespace_id: $ns},
                {type: "secret_text",     name: "URL_SECRET",         text: $us},
                {type: "secret_text",     name: "PROXY_TUNNEL_SECRET", text: $ts}
             ]}')
    else
        metadata=$(jq -cn \
            --arg ns "$NAMESPACE_ID" --arg st "$STORE_ID" --arg d "$COMPAT_DATE" \
            '{main_module: "index.js", compatibility_date: $d, bindings: [
                {type: "kv_namespace",          name: "TUNNEL_KV",          namespace_id: $ns},
                {type: "secrets_store_secret",  name: "URL_SECRET",         store_id: $st, secret_name: "URL_SECRET"},
                {type: "secrets_store_secret",  name: "PROXY_TUNNEL_SECRET", store_id: $st, secret_name: "PROXY_TUNNEL_SECRET"}
             ]}')
    fi

    if [ "$DRY_RUN" = 1 ]; then
        log "would: PUT /accounts/<id>/workers/scripts/$WORKER_NAME with metadata:"
        jq . <<<"$metadata" | sed 's/^/      /'
        return
    fi

    log "uploading index.js as Worker '$WORKER_NAME'..."
    out=$(curl -sS --fail-with-body --max-time 120 -X PUT \
        "$API/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME" \
        -H "Authorization: Bearer $API_TOKEN" \
        -F "metadata=$metadata;type=application/json" \
        -F "index.js=@$SCRIPT_DIR/index.js;type=application/javascript+module" 2>&1) || rc=$?
    [ "$rc" -eq 0 ] || die "worker upload failed (curl exit $rc): $out$(api_error_hint "/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME" "$out")"
    jq -e '.success == true' >/dev/null 2>&1 <<<"$out" \
        || die "worker upload rejected: $out"
    log "worker uploaded (script id: $(jq -r '.result.id // "?"' <<<"$out"))"
}

ensure_workers_dev() {
    if [ "$DRY_RUN" = 1 ]; then
        log "would: enable the workers.dev route for '$WORKER_NAME'"
        return
    fi
    local out
    out=$(cf GET "/accounts/$ACCOUNT_ID/workers/subdomain")
    SUBDOMAIN=$(jq -r '.result.subdomain // empty' <<<"$out")
    # idempotent on/off switch for this script's workers.dev route
    if out=$(curl -sS --fail-with-body --max-time 30 -X POST \
        "$API/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME/subdomain" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -H "$API_DATE_HEADER" \
        --data '{"enabled": true, "previews_enabled": false}' 2>&1); then
        log "workers.dev route enabled"
    else
        log "warning: could not toggle the workers.dev route ($out) - if it was already on, all good"
    fi
}

report() {
    local base="https://$WORKER_NAME.${SUBDOMAIN:-<your-subdomain>}.workers.dev"
    echo
    log "deployed: $base"
    log "  service URL:        $base/<URL_SECRET>.<SERVICE_SECRET><path from services.ini>"
    log "  (service w/o secret: $base/<URL_SECRET><path>)"
    log "  rotate secrets by editing .env and re-running this script"
    if [ "$DRY_RUN" = 1 ]; then return; fi
    if [ "$API" != "https://api.cloudflare.com/client/v4" ]; then
        log "skipping the live check (CF_API_BASE is overridden)"
        return
    fi
    echo
    log "checking the Worker is up (a request without a secret must get 401)..."
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$base/") || code=000
    if [ "$code" = "401" ]; then
        log "OK: worker answered 401 for a token-less request."
    else
        log "note: worker answered HTTP $code - a fresh worker can take a minute to
come up; re-check with: curl -i $base/"
    fi
}

# ---------- main ----------

main() {
    preflight
    [ "$DRY_RUN" = 1 ] && log "dry run - nothing will be changed"

    check_namespace
    if [ "$PLAIN_SECRETS" = 1 ]; then
        log "using plain Worker secrets (--plain-secrets, no Secrets Store)"
        STORE_ID=""
    else
        ensure_store
        upsert_secret "URL_SECRET" "$URL_SECRET" \
            "temp-cf-tun entry secret: the Worker 401s any request without it"
        upsert_secret "PROXY_TUNNEL_SECRET" "$PROXY_TUNNEL_SECRET" \
            "temp-cf-tun tunnel secret: sent as X-Tunnel-Secret to nginx"
    fi
    upload_worker
    ensure_workers_dev
    report
}

main
