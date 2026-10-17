# advanced-oauth

The `advanced-services` stack with the URL-secret Worker replaced by a real **OAuth 2.1** front door, built for
Claude's **custom connectors** (remote MCP). Same quick tunnel and nginx routing; different front door.

```
Claude ─► https://<worker>/mcp/shell        Bearer <access token>
            │  Worker (cf-worker/): validates the token, one audience per service
            ▼  adds X-Tunnel-Secret, forwards the same path
        trycloudflare quick tunnel (cftunnel/ publishes its URL to Workers KV)
            ▼  nginx (nginx/): drops anything without X-Tunnel-Secret, routes by path
        your MCP servers on the host
```

| | advanced-services | advanced-oauth |
|---|---|---|
| Public URL | `/<URL_SECRET>.<SERVICE_SECRET>/mcp/shell` | `/mcp/shell` |
| Gate at the edge | static URL secret | OAuth token (expiring, revocable) |
| Per-service isolation | per-service secret | token audience: a `/mcp/files` token fails on `/mcp/shell` |
| Claude connector | secret lives in the URL | normal OAuth sign-in, owner password once |
| Kill switch | rotate secrets | `https://<worker>/revoke` |
| Worker deploy | `deploy.sh` (curl + jq) | `wrangler deploy` (needs a bundler for the OAuth library) |

## Layout

```
advanced-oauth/
  compose.yml            cftunnel + nginx
  .env.example           cp to .env
  services.ini.example   cp to services.ini (paths must match SERVICES in cf-worker/wrangler.jsonc)
  cftunnel/              unchanged from advanced-services
  nginx/                 simplified: no per-service secrets, tunnel-secret gate kept
  cf-worker/             the OAuth Worker: setup, operation, security notes and tests are in its README
```

## Quick start

```sh
cd advanced-oauth
cp .env.example .env                 # fill ACCOUNT_ID, NAMESPACE_ID, API_TOKEN, PROXY_TUNNEL_SECRET (openssl rand -hex 32)
cp services.ini.example services.ini # point it at your MCP servers
# same prerequisites as advanced-services: ./server.crt + ./server.key for nginx, and the shared network
#   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=proxy-cftunnel" -keyout server.key -out server.crt
#   docker network create cftunnel
docker compose up -d --build

cd cf-worker                         # then follow cf-worker/README.md:
npm install                          #   KV namespace, wrangler.jsonc, two secrets, `npx wrangler deploy`
```

Then in Claude: Customize → Connectors → **Add custom connector** → `https://<worker>/mcp/shell`
(leave the OAuth client fields empty), Connect, enter the owner password, Allow.

`PROXY_TUNNEL_SECRET` is set in two places and must be identical: `.env` (nginx) and
`wrangler secret put PROXY_TUNNEL_SECRET` (Worker). The service paths are also in two places: `services.ini`
(nginx) and `SERVICES` in `cf-worker/wrangler.jsonc` (Worker).

## Migrating from advanced-services

1. Use the same `WORKER_NAME` in `cf-worker/wrangler.jsonc` so the deploy replaces the old Worker and keeps its hostname.
2. Delete every `secret =` line from `services.ini` (the generator refuses them). `proxy.env` is no longer used.
3. `.env`: `URL_SECRET`, `STORE_NAME` and the Secrets Store token permission are no longer needed. Keep
   `PROXY_TUNNEL_SECRET`.
4. Old connector URLs stop working by design; add new connectors with the clean URLs.
5. Optional cleanup: delete the old Secrets Store (`<WORKER_NAME>-secrets`) once the new Worker is live.

## Good to know

- Restarting cftunnel gives a new quick-tunnel URL; the Worker caches the old one for up to 60 s, so expect a brief
  502 after a restart.
- Backends see `Host: proxy-cftunnel` (nginx forwards the Host cloudflared rewrote). An MCP server with strict
  Host/Origin validation must allow it.
