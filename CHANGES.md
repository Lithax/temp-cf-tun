# Changes: advanced-services reworked around the Secrets Store

## What changed

**Worker (`cf-worker/index.js`)** – rewritten.
- Auth no longer depends on a `CF_TUNNEL_CONFIG` KV key. The Worker now checks
  the **URL secret** against two Secrets Store bindings
  (`URL_SECRET`, `PROXY_TUNNEL_SECRET`) and 401s at the edge before touching
  KV or the tunnel.
- URL format changed (see below). The service secret is no longer a path
  segment that the Worker hashes and matches against KV - it is forwarded as
  the `X-Service-Secret` header and checked by nginx.
- Adds `Host: <tunnel-hostname>` and `X-Forwarded-Proto: https` on the
  proxied request (previously the incoming workers.dev Host was copied
  through, which the quick-tunnel edge would misroute).

**nginx (`nginx/`)** –
- `40-services.sh` no longer publishes a routing table to Workers KV (and no
  longer needs `curl`, `jq` or any Cloudflare credentials). It now generates
  `maps.conf` too: one `map` per `secret =` service, checking
  `X-Service-Secret`; the generated location 401s when it doesn't match.
- **`proxy.conf` added** - the Dockerfile always referenced it but it was
  never committed, so `docker build` of the proxy image failed. It also
  strips `X-Tunnel-Secret`/`X-Service-Secret` before the backend.
- `nginx.conf.template.example`: includes `maps.conf`, and `server_name` now
  comes from `${HTTP_SERVER_NAME}` (envsubst) instead of a hand-edited
  placeholder. **Host-header mismatch fixed**: compose sets both
  `HTTP_HOST_HEADER` (cloudflared `--http-host-header`) and nginx's
  `HTTP_SERVER_NAME` from the same value, defaulting to `proxy-cftunnel`.

**compose.yml** –
- The proxy container no longer gets the whole `.env` via `env_file` (that
  leaked `API_TOKEN`, `ACCOUNT_ID`, ... to nginx). It gets its own
  `proxy.env` (service secrets only) plus its two settings.
- `HTTP_HOST_HEADER` defaults to `proxy-cftunnel` on the cftunnel service, so
  Host rewriting is always on (quick-tunnel hostnames change every restart;
  without the rewrite every request fell into nginx's catch-all 444).

**New: `cf-worker/deploy.sh`** – one script, curl + jq only:
creates/finds the Secrets Store, creates or updates the two secrets in it,
uploads `index.js` as a module Worker with all bindings (KV + the two
Secrets Store secrets), enables the workers.dev route, and verifies the
Worker 401s a token-less request. `--dry-run` and `--plain-secrets` (plain
`secret_text` bindings instead of the store) are available.

## URL format: old vs new

```
old:  https://<worker>/<URL_SECRET>/<service path>/<SERVICE_SECRET>/<rest>
new:  https://<worker>/<URL_SECRET>.<SERVICE_SECRET>/<service path>/<rest>
new:  https://<worker>/<URL_SECRET>/<service path>/<rest>   (no-secret service)
```

Rationale: `.` is never percent-encoded (unlike `+`), both secrets stay in
one opaque first segment, and everything after the first `/` is a plain
service path - no ambiguity about which segment is the secret, and no secret
appears in any path or log downstream (the service secret becomes a header,
checked by nginx and stripped before the backend).

## Migration

1. `cd advanced-services && cp proxy.env.example proxy.env` and move your
   service secrets (e.g. `MCP_SHELL_SECRET`) from `.env` into `proxy.env`.
2. In `.env`: set `WORKER_NAME`; rename `PROXY_ENTRY_SECRET` →
   `PROXY_TUNNEL_SECRET`; keep `URL_SECRET`; optionally set `STORE_NAME`
   (default `<WORKER_NAME>-secrets`).
3. `cd cf-worker && ./deploy.sh` (creates the store, secrets, worker).
4. Recreate the proxy container: `docker compose up -d --build`.
5. The old `CF_TUNNEL_CONFIG` KV key is no longer read; you can delete it
   (dash → Workers KV → your namespace, or
   `wrangler kv key delete CF_TUNNEL_CONFIG --namespace-id=<id> --remote`).
6. Update your clients to the new URL format.

## Notes

- The beta allows **one store per account**; `deploy.sh` refuses to hijack an
  existing store with a different name and tells you what to set instead.
- API token permissions: Workers Scripts:Edit, Workers KV Storage:Edit,
  Secrets Store:Edit.
- Secrets Store values propagate to the Worker within ~a minute (the Worker
  also caches them for 60s), so rotation needs no redeploy.
- `basic/` is untouched.
