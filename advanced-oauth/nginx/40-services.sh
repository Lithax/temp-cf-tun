#!/bin/bash
#
# nginx container startup hook (runs from /docker-entrypoint.d before nginx starts).
# Reads services.ini and generates two nginx include files in GEN_DIR:
#   upstreams.conf   one upstream per service
#   locations.conf   one location per service
#
# Authentication happens at the Worker (OAuth: a valid token for exactly that
# service), and nginx's own check is X-Tunnel-Secret (set in nginx.conf.template).
# Nothing here needs to talk to Cloudflare - no API token in this container.
#
# Required env: PROXY_TUNNEL_SECRET
# Optional env: SERVICES_INI   (default /etc/nginx/services.ini)
#               GEN_DIR        (default /etc/nginx/generated)

set -euo pipefail

SERVICES_INI="${SERVICES_INI:-/etc/nginx/services.ini}"
GEN_DIR="${GEN_DIR:-/etc/nginx/generated}"

log() { echo "[services] $*"; }
die() { echo "[services] CRITICAL ERROR: $*" >&2; exit 1; }

# Everything from the ini ends up inside nginx config, so it is validated strictly.
RE_NAME='^[A-Za-z0-9_-]+$'
RE_PATH='^(/[A-Za-z0-9._~-]+)+$'
RE_UPSTREAM='^[A-Za-z0-9.-]+:[0-9]{1,5}$'
RE_SECRET='^[A-Za-z0-9_-]{24,}$'

declare -A CFG=()
SECTIONS=()

# ---------- preflight ----------

preflight() {
    [ -n "${PROXY_TUNNEL_SECRET:-}" ] || die "PROXY_TUNNEL_SECRET is empty! Check your compose.yml / .env"
    [[ "$PROXY_TUNNEL_SECRET" =~ $RE_SECRET ]] \
        || die "PROXY_TUNNEL_SECRET must be 24+ chars of A-Z a-z 0-9 _ - (try: openssl rand -hex 32)"
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
                path | upstream | scheme | backend_path) ;;
                secret) die "$SERVICES_INI:$n: 'secret =' is gone in advanced-oauth: the Worker's OAuth token (one audience per service) replaces it. Delete the line." ;;
                *) die "$SERVICES_INI:$n: unknown key '$key'" ;;
            esac
            CFG["$section.$key"]="$val"
        else
            die "$SERVICES_INI:$n: can't parse: $line"
        fi
    done < "$SERVICES_INI"

    [ "${#SECTIONS[@]}" -gt 0 ] || die "no services defined in $SERVICES_INI"
}

# ---------- nginx config ----------

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
    local s path upstream scheme backend up_name

    for s in "${SECTIONS[@]}"; do
        path="${CFG[$s.path]:-}"
        upstream="${CFG[$s.upstream]:-}"
        scheme="${CFG[$s.scheme]:-https}"
        backend="${CFG[$s.backend_path]:-}"

        [ -n "$path" ] || die "[$s] path is required"
        check_path "[$s] path" "$path"
        [ -z "${seen_paths[$path]:-}" ] || die "[$s] path $path is already used by another service"
        seen_paths[$path]=1

        [[ "$upstream" =~ $RE_UPSTREAM ]] || die "[$s] upstream must be host:port, got '$upstream'"
        [[ "$scheme" == http || "$scheme" == https ]] || die "[$s] scheme must be http or https"
        [ -z "$backend" ] || check_path "[$s] backend_path" "$backend"

        # - and _ would create clashing upstream names, treat them as the same
        up_name="svc_${s//-/_}"
        [ -z "${seen_names[$up_name]:-}" ] || die "[$s] section name clashes with another one (- and _ are treated the same)"
        seen_names[$up_name]=1

        printf 'upstream %s { server %s; }\n' "$up_name" "$upstream" >> "$GEN_DIR/upstreams.conf"

        {
            printf '# [%s]\n' "$s"
            printf 'location ^~ %s {\n' "$path"
            printf '    proxy_pass %s://%s%s;\n' "$scheme" "$up_name" "$backend"
            printf '    include /etc/nginx/snippets/proxy.conf;\n'
            printf '}\n\n'
        } >> "$GEN_DIR/locations.conf"

        log "route $path -> $scheme://$upstream${backend:+ (as $backend)}"
    done
}

# Refuse to start on a config nginx won't load.
validate_nginx() {
    command -v nginx >/dev/null 2>&1 || return 0
    local out
    out=$(nginx -t 2>&1) || { echo "$out" >&2; die "generated nginx config is invalid."; }
}

# ---------- main ----------

preflight
parse_ini
generate
validate_nginx
