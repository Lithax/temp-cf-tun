# cf-worker: the OAuth front door

Replaces the URL-secret Worker with a real OAuth 2.1 flow, built on
[`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) 1.x, so Claude's
**custom connectors** can connect to your local MCP servers through the quick tunnel.

```
Claude (Anthropic's servers)
   │  POST https://<worker>/mcp/shell        Authorization: Bearer <access token>
   ▼
Cloudflare Worker  (this project)
   ├─ no / bad token ─► 401 + WWW-Authenticate ─► Claude discovers OAuth, registers, opens /authorize
   │                                              └─ you type the owner password once, click Allow
   └─ valid token for *this service* ─► same path, + X-Tunnel-Secret ─► quick tunnel ─► nginx ─► your MCP server
                                         (OAuth token stripped; backends never see it)
```

- URLs are clean: `https://<worker>/mcp/<service>`. No secret segment, so redirects, SSE `endpoint` events and
  OAuth discovery all work.
- **One token audience per service.** A token approved for `/mcp/files` is refused on `/mcp/shell`. This replaces the
  old per-service secret.
- nginx's `X-Tunnel-Secret` check is unchanged and still protects the public quick-tunnel hostname.

## Setup

```sh
cd advanced-oauth/cf-worker
npm install
npx wrangler login                          # or export CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID

npx wrangler kv namespace create OAUTH_KV   # paste the id into wrangler.jsonc (OAUTH_KV)
# TUNNEL_KV id = NAMESPACE_ID from your ../.env (the namespace cftunnel already writes into)
```

Edit `wrangler.jsonc`:

| var | set it to |
|---|---|
| `PUBLIC_ORIGIN` | your Worker's origin, e.g. `https://personal.<subdomain>.workers.dev` (https, no path). This is the OAuth issuer and must match exactly. |
| `SERVICES` | comma-separated paths, the same as `path =` in `services.ini` (e.g. `/mcp/shell,/mcp/files`) |

Secrets:

```sh
openssl rand -base64 24                     # generate a password; needs 20+ characters
npx wrangler secret put OWNER_PASSWORD      # what the consent page asks for
npx wrangler secret put PROXY_TUNNEL_SECRET # same value nginx uses for X-Tunnel-Secret
```

`services.ini` has no `secret =` lines in this stack (OAuth replaces them; the nginx generator refuses them). Then:

```sh
npx wrangler deploy                         # same Worker name as your old one replaces it
```

### Connect Claude

Customize → Connectors → **Add custom connector**, URL `https://<worker>/mcp/shell`. Leave the OAuth client ID and
secret empty (Claude registers itself). Click Connect; your browser opens the consent page; enter the owner password
and choose **Allow access**. Add one connector per service.

Claude Code or a desktop client on `localhost`? Set `ALLOW_LOOPBACK_REDIRECTS` to `"true"` and redeploy.

## Operating it

| I want to… | Do this |
|---|---|
| Cut off everything now | Open `https://<worker>/revoke`, enter the owner password. Every grant and token dies immediately. |
| Rotate the owner password | `npx wrangler secret put OWNER_PASSWORD` |
| Rotate the tunnel secret | `wrangler secret put PROXY_TUNNEL_SECRET`, update nginx's value, restart nginx |
| Add a service | add it to `services.ini` and to `SERVICES`, redeploy, add a connector for it |
| See what's happening | `npx wrangler tail` (wrong passwords, refused redirect URIs and revocations are logged; secrets and tokens never are) |

Lifetimes: access tokens 1 hour (`ACCESS_TOKEN_TTL_SECONDS`); a grant lasts `GRANT_LIFETIME_DAYS` (30) and then you
approve again. Approving the same client for the same service again replaces its older grant. Changing
`PUBLIC_ORIGIN` changes the issuer and invalidates existing connectors.

## What protects what

| Layer | Stops |
|---|---|
| OAuth token at the Worker (audience-bound per service) | anyone without a grant; a token for one service being used on another |
| Owner password + one-time, browser-bound consent handle + redirect allowlist | a stranger (or a hostile app) obtaining a token; consent forged from another site; codes sent anywhere but Claude's callbacks |
| 5-attempts-per-15-min lockout per IP | password guessing |
| `X-Tunnel-Secret` (nginx) | direct hits on the quick-tunnel hostname |
| `TUNNEL_HOST_SUFFIX` check | a bad KV value turning the Worker into a proxy to an arbitrary host |

Honest limits:

- The owner password is the only human factor. The lockout is per IP and KV is eventually consistent, so it slows
  guessing rather than hard-capping it; that is why a 20+ character random password is enforced. For stronger sign-in
  put an identity provider in front of `/authorize` (see the library's `docs/upstream-sign-in.md`).
- Dynamic client registration is open by nature. Registrations are only accepted with allowlisted redirect URIs, so a
  stray client can't receive a code, but it can add clutter to KV (cleaned by TTL and the daily cron).
- Backends still see `Host: proxy-cftunnel` (nginx's choice). An MCP server with Host/Origin checking must allow it.
- Anything that can read your `OAUTH_KV` or Worker secrets can mint access. Guard the Cloudflare account accordingly.

## Troubleshooting

- **`503 Gateway misconfigured: …`**: the message names the variable or secret that is missing or invalid.
- **`DCR refused` / `authorize refused` in `wrangler tail`**: Claude used a redirect URI that isn't in
  `ALLOWED_REDIRECT_URIS`; add it exactly as logged.
- **`502 Tunnel offline`**: cftunnel hasn't written `CF_TUNNEL_REDIRECT`, or the value isn't under `TUNNEL_HOST_SUFFIX`.
- **"Authorization with the MCP server failed" in Claude**: the error URL contains an `ofid_…` id. Check
  `wrangler tail` for the matching attempt, and if the Worker issued a token but Claude still fails, report the id on
  [`anthropics/claude-ai-mcp`](https://github.com/anthropics/claude-ai-mcp/issues). Claude's guide:
  <https://claude.com/docs/connectors/building/troubleshooting>.
- Claude resolves your hostname from Anthropic's network, IPv4 only, and waits 10 s for the token endpoint. A
  `workers.dev` hostname satisfies both.

## Tests

`npm run test:e2e` starts the Worker in workerd (simulated KV) with a fake tunnel upstream and plays Claude through
the whole flow: 401 challenge, discovery, registration, PKCE consent, token, refresh, proxying (path, headers, SSE
streaming, redirect rewriting), per-service isolation, code replay, tunnel URL guard, `/revoke`, lockout. It needs
ports 8799 and 9999.

Not covered by it: a real `wrangler deploy`, a real Claude connection, Client ID Metadata Document fetching (it is
enabled and advertised, but needs a public client URL), and the consent page in a real browser.
