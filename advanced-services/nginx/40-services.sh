#!/bin/bash
#
# nginx container startup hook (runs from /docker-entrypoint.d before nginx starts).
# Reads services.ini, then:
#   1. generates the nginx upstream/location blocks
#   2. publishes the routing table to Workers KV so the Worker knows which paths
#      exist and which secrets guard them (URL/service secrets go up as SHA-256
#      hashes, never in plaintext)
#
# Required env: URL_SECRET, PROXY_TUNNEL_SECRET, ACCOUNT_ID, NAMESPACE_ID, API_TOKEN
#               plus every env var named by a `secret =` line in services.ini
# Optional env: SERVICES_INI   (default /etc/nginx/services.ini)
#               GEN_DIR        (default /etc/nginx/generated)
#               KV_CONFIG_KEY  (default CF_TUNNEL_CONFIG)

set -euo pipefail

SERVICES_INI="${SERVICES_INI:-/etc/nginx/services.ini}"
GEN_DIR="${GEN_DIR:-/etc/nginx/generated}"
KV_CONFIG_KEY="${KV_CONFIG_KEY:-CF_TUNNEL_CONFIG}"

log() { echo "[services] $*"; }
die() { echo "[services] CRITICAL ERROR: $*" >&2; exit 1; }

# Everything from the ini ends up inside nginx config, so it is validated strictly.
RE_NAME='^[A-Za-z0-9_-]+$'
RE_PATH='^(/[A-Za-z0-9._~-]+)+$'
RE_UPSTREAM='^[A-Za-z0-9.-]+:[0-9]{1,5}$'
RE_ENVNAME='^[A-Za-z_][A-Za-z0-9_]*$'
RE_SECRET='^[A-Za-z0-9_-]{24,}$'

declare -A CFG=()
SECTIONS=()
ROUTES='[]'

sha256() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# ---------- preflight ----------

preflight() {
    command -v jq   >/dev/null 2>&1 || die "jq is not installed in this image."
    command -v curl >/dev/null 2>&1 || die "curl is not installed in this image."

    local v
    for v in URL_SECRET PROXY_TUNNEL_SECRET ACCOUNT_ID NAMESPACE_ID API_TOKEN; do
        [ -n "${!v:-}" ] || die "$v is empty! Check your compose.yml / .env"
    done
    for v in URL_SECRET PROXY_TUNNEL_SECRET; do
        [[ "${!v}" =~ $RE_SECRET ]] \
            || die "$v must be 24+ chars of A-Z a-z 0-9 _ - (try: openssl rand -hex 32)"
    done
}

# ---------- services.ini ----------

parse_ini() {
    [ -f "$SERVICES_INI" ] || die "$SERVICES_INI not found (mount it in compose.yml)"

    local line section="" key val n=0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"   # ltrim
        line="${line%"${line##*[![:space:]]}"}"   # rtrim
        case "$line" in '' | '#'* | ';'*) continue ;; esac

        if [[ "$line" =~ ^\[([^]]+)\]$ ]]; then
            section="${BASH_REMATCH[1]}"
            [[ "$section" =~ $RE_NAME ]] || die "$SERVICES_INI:$n: bad section name '$section'"
            [ -z "${CFG[$section.__seen]:-}" ] || die "$SERVICES_INI:$n: duplicate section [$section]"
            CFG["$section.__seen"]=1
            SECTIONS+=("$section")
        elif [[ "$line" =~ ^([a-z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            [ -n "$section" ] || die "$SERVICES_INI:$n: setting outside of a [section]"
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            case "$key" in
                path | upstream | secret | scheme | backend_path) ;;
                *) die "$SERVICES_INI:$n: unknown key '$key'" ;;
            esac
            CFG["$section.$key"]="$val"
        else
            die "$SERVICES_INI:$n: can't parse: $line"
        fi
    done < "$SERVICES_INI"

    [ "${#SECTIONS[@]}" -gt 0 ] || die "no services defined in $SERVICES_INI"
}

# ---------- nginx config + routing table ----------

check_path() { # label, value
    [[ "$2" =~ $RE_PATH ]] \
        || die "$1 must look like /mcp/name (letters, digits and . _ ~ - only, no trailing slash), got '$2'"
    case "$2/" in */./* | */../*) die "$1 must not contain . or .. segments" ;; esac
}

generate() {
    mkdir -p "$GEN_DIR"
    : > "$GEN_DIR/upstreams.conf"
    : > "$GEN_DIR/locations.conf"

    declare -A seen_paths=() seen_names=()
    local s path upstream scheme backend secret_var secret hash up_name

    for s in "${SECTIONS[@]}"; do
        path="${CFG[$s.path]:-}"
        upstream="${CFG[$s.upstream]:-}"
        scheme="${CFG[$s.scheme]:-https}"
        backend="${CFG[$s.backend_path]:-}"
        secret_var="${CFG[$s.secret]:-}"

        [ -n "$path" ] || die "[$s] path is required"
        check_path "[$s] path" "$path"
        [ -z "${seen_paths[$path]:-}" ] || die "[$s] path $path is already used by another service"
        seen_paths[$path]=1

        [[ "$upstream" =~ $RE_UPSTREAM ]] || die "[$s] upstream must be host:port, got '$upstream'"
        [[ "$scheme" == http || "$scheme" == https ]] || die "[$s] scheme must be http or https"
        [ -z "$backend" ] || check_path "[$s] backend_path" "$backend"

        hash=""
        if [ -n "$secret_var" ]; then
            [[ "$secret_var" =~ $RE_ENVNAME ]] \
                || die "[$s] 'secret =' takes the NAME of an env var, not the secret itself"
            secret="${!secret_var:-}"
            [ -n "$secret" ] || die "[$s] env var $secret_var is empty or unset (add it to .env)"
            [[ "$secret" =~ $RE_SECRET ]] \
                || die "[$s] $secret_var must be 24+ chars of A-Z a-z 0-9 _ - (try: openssl rand -hex 32)"
            hash=$(sha256 "$secret")
        fi

        up_name="svc_${s//-/_}"
        [ -z "${seen_names[$up_name]:-}" ] || die "[$s] section name clashes with another one (- and _ are treated the same)"
        seen_names[$up_name]=1

        printf 'upstream %s { server %s; }\n' "$up_name" "$upstream" >> "$GEN_DIR/upstreams.conf"
        {
            printf '# [%s]\n' "$s"
            printf 'location ^~ %s {\n' "$path"
            printf '    proxy_pass %s://%s%s;\n' "$scheme" "$up_name" "$backend"
            printf '    include /etc/nginx/snippets/mcp-proxy.conf;\n'
            printf '}\n\n'
        } >> "$GEN_DIR/locations.conf"

        ROUTES=$(jq -c --arg path "$path" --arg h "$hash" \
            '. + [{path: $path} + (if $h == "" then {} else {secret_sha256: $h} end)]' <<<"$ROUTES")

        log "route $path -> $scheme://$upstream${backend:+ (as $backend)} [${secret_var:-no secret}]"
    done
}

# Refuse to publish routes for a config nginx won't load.
validate_nginx() {
    command -v nginx >/dev/null 2>&1 || return 0
    local out
    out=$(nginx -t 2>&1) || { echo "$out" >&2; die "generated nginx config is invalid, not publishing routes."; }
}

# ---------- publish to Worker KV ----------

publish() {
    local url_hash payload resp
    url_hash=$(sha256 "$URL_SECRET")
    payload=$(jq -n -c \
        --arg t "$PROXY_TUNNEL_SECRET" --arg u "$url_hash" --argjson r "$ROUTES" \
        '{v: 1, tunnel_secret: $t, url_secret_sha256: $u, routes: $r}')

    log "Publishing routing table to Worker KV ($KV_CONFIG_KEY)..."
    resp=$(curl -sS --fail-with-body --max-time 20 --retry 3 --retry-all-errors --retry-delay 2 \
        -X PUT \
        "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${NAMESPACE_ID}/values/${KV_CONFIG_KEY}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: text/plain" \
        --data-binary "$payload" 2>&1) \
        || { echo "$resp" >&2; die "failed to write $KV_CONFIG_KEY to KV (check ACCOUNT_ID / NAMESPACE_ID; API_TOKEN needs 'Workers KV Storage: Edit')."; }

    log "Worker KV updated (${#SECTIONS[@]} service(s)). Allow up to ~60s for KV to propagate."
}

# ---------- main ----------

preflight
parse_ini
generate
validate_nginx
publish
