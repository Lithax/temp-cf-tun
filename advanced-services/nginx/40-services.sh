#!/bin/bash
#
# nginx container startup hook (runs from /docker-entrypoint.d before nginx starts).
# Reads services.ini and generates three nginx include files in GEN_DIR:
#   upstreams.conf   one upstream per service
#   maps.conf        one `map` per secret-guarded service (checks X-Service-Secret)
#   locations.conf   one location per service (401s when its secret is wrong)
#
# The Worker upstream has already gated the request on the URL secret and
# forwards the service secret (from the URL token) as X-Service-Secret, so
# nothing here needs to talk to Cloudflare - no API token in this container.
#
# Required env: PROXY_TUNNEL_SECRET
#               plus every env var named by a `secret =` line in services.ini
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
RE_ENVNAME='^[A-Za-z_][A-Za-z0-9_]*$'
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

# ---------- nginx config ----------

check_path() { # label, value
    [[ "$2" =~ $RE_PATH ]] \
        || die "$1 must look like /mcp/name (letters, digits and . _ ~ - only, no trailing slash), got '$2'"
    case "$2/" in */./* | */../*) die "$1 must not contain . or .. segments" ;; esac
}

generate() {
    mkdir -p "$GEN_DIR"
    : > "$GEN_DIR/upstreams.conf"
    : > "$GEN_DIR/maps.conf"
    : > "$GEN_DIR/locations.conf"

    declare -A seen_paths=() seen_names=()
    local s path upstream scheme backend secret_var secret up_name

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

        # - and _ would create clashing upstream names, treat them as the same
        up_name="svc_${s//-/_}"
        [ -z "${seen_names[$up_name]:-}" ] || die "[$s] section name clashes with another one (- and _ are treated the same)"
        seen_names[$up_name]=1

        printf 'upstream %s { server %s; }\n' "$up_name" "$upstream" >> "$GEN_DIR/upstreams.conf"

        # The map is what actually checks the secret: $svc_<name>_ok is 1 only
        # when X-Service-Secret matches exactly. nginx map keys are literals
        # here (RE_SECRET bans "~"), compared after the map hash - close enough
        # to constant time for this threat model, and never logged.
        if [ -n "$secret_var" ]; then
            [[ "$secret_var" =~ $RE_ENVNAME ]] \
                || die "[$s] 'secret =' takes the NAME of an env var, not the secret itself"
            secret="${!secret_var:-}"
            [ -n "$secret" ] || die "[$s] env var $secret_var is empty or unset (add it to proxy.env)"
            [[ "$secret" =~ $RE_SECRET ]] \
                || die "[$s] $secret_var must be 24+ chars of A-Z a-z 0-9 _ - (try: openssl rand -hex 32)"

            # shellcheck disable=SC2016  # $http_x_service_secret / $svc_* are nginx variables, not shell
            printf 'map $http_x_service_secret $svc_%s_ok {\n    default 0;\n    "%s" 1;\n}\n' \
                "$up_name" "$secret" >> "$GEN_DIR/maps.conf"
        fi

        {
            printf '# [%s]\n' "$s"
            printf 'location ^~ %s {\n' "$path"
            if [ -n "$secret_var" ]; then
                printf '    # %s is a map from maps.conf (1 only with the right X-Service-Secret)\n' "\$svc_${up_name}_ok"
                # shellcheck disable=SC2016  # $svc_* is an nginx variable
                printf '    if ($svc_%s_ok = 0) { return 401; }\n' "$up_name"
            fi
            printf '    proxy_pass %s://%s%s;\n' "$scheme" "$up_name" "$backend"
            printf '    include /etc/nginx/snippets/proxy.conf;\n'
            printf '}\n\n'
        } >> "$GEN_DIR/locations.conf"

        log "route $path -> $scheme://$upstream${backend:+ (as $backend)} [${secret_var:-no secret}]"
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
