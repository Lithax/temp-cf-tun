# temp-cf-tun

Reverse-proxy tunnels through a Cloudflare Worker + a free `cloudflared` quick
tunnel, for HTTP(S) services on a machine you don't want to expose directly.

- **`basic/`** – one Worker checking HTTP Basic auth in front of one nginx.
  If you just want a plain reverse-proxy tunnel, use this.
- **`advanced-services/`** – a multi-service gateway with URL-token auth:
  a single Worker gates every request at the edge, nginx routes to several
  services and checks a per-service secret. The gateway secrets live in the
  Cloudflare **Secrets Store**, and `cf-worker/deploy.sh` provisions
  everything (secrets + worker + bindings) with just curl + jq.

Both flavors share one `.env` (see `symlinks.sh`).

---

## advanced-services

```
 client                        Cloudflare edge                     your machine
─────────    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    ~~~~~~~~~~~~~~~~~~~~~
   GET https://personal.lithax.workers.dev/<URL_SECRET>.<SVC_SECRET>/mcp/shell
        │                                              │
        ▼                                              │
   ┌───────────────── Worker ─────────────────┐        │
   │ URL secret ok?  no ──► 401 (edge, done)  │        │
   │ read current trycloudflare URL from KV   │        │
   │ forward as /mcp/shell + X-Tunnel-Secret  │        │
   │                + X-Service-Secret        │        │
   └──────────────────┬───────────────────────┘        │
                      ▼                                │
              xyz.trycloudflare.com ──────────────────►│
                      │                                ▼
                      │                        ┌──── nginx ────┐
                      │                        │ X-Tunnel-Secret
                      │                        │ wrong/missing ─► 444
                      │                        │ route by path  │
                      │                        │ X-Service-Secret
                      │                        │ wrong ────────► 401
                      │                        └───────┬───────┘
                      │                                ▼
                      │                         your MCP services
```

### The URL format

```
https://<worker>/<URL_SECRET>.<SERVICE_SECRET>/<service path...>
https://<worker>/<URL_SECRET>/<service path...>        (service without a secret)
```

Why both secrets live in one first path segment, joined by a `.`:

- **`.` is never percent-encoded** by any client or library (`+` gets mangled
  to `%2B` or a space by enough stacks to be a support nightmare), and it is
  not a reserved path character.
- Both secrets are restricted to `A-Za-z0-9_-`, so the split at the **first**
  `.` is unambiguous and the whole thing still just looks like one opaque
  token in any log.
- After the first `/` everything is the plain service path - the worker never
  has to guess which segment is a secret, and neither do you.
- Both secrets are **stripped from the URL** before proxying: the service
  secret travels to nginx as the `X-Service-Secret` header (checked per
  service, then dropped), and the URL secret never leaves the Worker at all.

Why keep two secrets instead of just one per service: the URL secret lets the
**Worker reject scanners at the edge with a 401** - fake traffic never
touches the tunnel, nginx or your services. The service secret then decides
*which* service the caller may use, at nginx.

### Layered auth, in order

1. **Worker**: wrong/missing URL secret → `401 Unauthorized` at the edge.
   Cheap, and the tunnel isn't bothered.
2. **nginx**: request without the correct `X-Tunnel-Secret` (i.e. someone
   found the raw `*.trycloudflare.com` URL and went around the Worker) →
   connection dropped (`444`). Rate limited per real client IP on top.
3. **nginx**: service with a `secret =` in `services.ini` and wrong
   `X-Service-Secret` → `401`.
4. Backends never see any of the gateway secrets - nginx strips both headers.

### Setup

Prereqs: a Cloudflare account, an API token with **Workers Scripts:Edit,
Workers KV Storage:Edit, Secrets Store:Edit**, and a KV namespace (Storage &
Databases → Workers KV; put its id in `NAMESPACE_ID`).

```bash
cd advanced-services

# 1. copy the examples
cp .env.example ../.env            # or symlink, see symlinks.sh
cp proxy.env.example proxy.env
cp services.ini.example services.ini
cp nginx/nginx.conf.template.example nginx/nginx.conf.template

# 2. generate secrets (24+ chars, and NOT the examples below)
openssl rand -hex 32               # -> URL_SECRET            (.env)
openssl rand -hex 32               # -> PROXY_TUNNEL_SECRET   (.env)
openssl rand -hex 32               # -> MCP_SHELL_SECRET etc. (proxy.env)

# 3. fill in .env: ACCOUNT_ID, NAMESPACE_ID, API_TOKEN, WORKER_NAME,
#    URL_SECRET, PROXY_TUNNEL_SECRET

# 4. TLS cert nginx presents to the tunnel, and edit services.ini +
#    proxy.env to match your services

# 5. deploy the Worker (creates/updates the Secrets Store + its two secrets,
#    uploads index.js with all bindings, enables the workers.dev route)
cd cf-worker && ./deploy.sh

# 6. start the tunnel + nginx
cd .. && docker compose up -d --build
```

The `cftunnel` container publishes the current quick-tunnel URL to KV on
every restart; the Worker picks it up within a minute. Your service URLs
never change, because callers only ever see the workers.dev hostname.

Rotating secrets: edit `.env` / `proxy.env`, re-run `cf-worker/deploy.sh`
(gateway secrets) and `docker compose restart proxy` (service secrets).

### Files

```
advanced-services/
├── cf-worker/
│   ├── index.js          the Worker (URL-secret gate + proxy)
│   └── deploy.sh         secrets store + worker upload, curl/jq only
├── cftunnel/             cloudflared quick tunnel -> publishes URL to KV
├── nginx/
│   ├── 40-services.sh    startup hook: services.ini -> upstreams/maps/locations
│   ├── proxy.conf        shared proxy snippet (websocket/SSE, header hygiene)
│   ├── nginx.conf.template.example
│   └── Dockerfile
├── compose.yml           cftunnel + proxy (proxy gets NO cloudflare creds)
├── proxy.env.example     per-service secrets (only env the proxy gets extra)
└── services.ini.example  service routes
```

`deploy.sh --dry-run` shows the plan without changing anything;
`deploy.sh --plain-secrets` is a fallback that binds the two secrets as plain
Worker secrets if your account can't use the Secrets Store.

## basic

Plain Worker (Basic auth + rate limit) in front of one nginx. See
`basic/compose.yml`; the Worker needs its bindings (USER, PASSWORD,
SHARED_SECRET, KV) set up in the dash or with wrangler.
