// OAuth 2.1 front door for the temp-cf-tun quick-tunnel gateway.
//
//   Claude ──► https://<worker>/mcp/<service>          (Bearer access token)
//                │
//                ├─ no/invalid token ─► 401 + WWW-Authenticate (points at the
//                │                      resource metadata; Claude then runs
//                │                      OAuth discovery, registers, and sends
//                │                      you to /authorize)
//                └─ valid token ─► forwarded to the tunnel as the *same path*,
//                                  with X-Tunnel-Secret. The OAuth token is
//                                  stripped: backends never see it.
//
// One Worker plays both OAuth roles (@cloudflare/workers-oauth-provider 1.x,
// functional API):
//
//   - authorization server: /.well-known/oauth-authorization-server,
//     /oauth/register (DCR), /oauth/token (+ revocation), and /authorize,
//     which is *your* page: an owner-password consent screen (below).
//   - one resource server per entry in SERVICES. Every service is its own
//     token audience, so a token granted for /mcp/files cannot call /mcp/shell.
//
// Everything else lives next to this folder: cloudflared publishes the quick-tunnel URL
// to KV, nginx (../nginx) checks X-Tunnel-Secret and routes by path.
//
// Config (wrangler.jsonc "vars" unless noted):
//   PUBLIC_ORIGIN           https://<worker>.<subdomain>.workers.dev   (the issuer; no path)
//   SERVICES                comma-separated service paths, same as services.ini  (/mcp/shell,/mcp/files)
//   ALLOWED_REDIRECT_URIS   exact redirect URIs OAuth clients may use (default: Claude's two callbacks)
//   ALLOW_LOOPBACK_REDIRECTS  "true" also allows http://localhost|127.0.0.1|[::1] callbacks (Claude Code)
//   ACCESS_TOKEN_TTL_SECONDS  default 3600
//   GRANT_LIFETIME_DAYS       default 30; after that you approve again
//   TUNNEL_HOST_SUFFIX      default ".trycloudflare.com"; the KV tunnel URL must end with it
//   HTTP_HOST_HEADER        default "proxy-cftunnel"; backend-visible host, rewritten in redirects
// Secrets (wrangler secret put):
//   OWNER_PASSWORD          the password the /authorize page asks for (20+ chars)
//   PROXY_TUNNEL_SECRET     stamped as X-Tunnel-Secret; must equal nginx's PROXY_TUNNEL_SECRET
// Bindings: OAUTH_KV (OAuth state), TUNNEL_KV (holds CF_TUNNEL_REDIRECT, written by cftunnel)

import {
  AuthorizationError,
  CimdFetchError,
  OAuthAuthorizationServer,
  OAuthResourceServer,
} from "@cloudflare/workers-oauth-provider";

const KV_URL_KEY = "CF_TUNNEL_REDIRECT";
const CACHE_MS = 60_000;
const OWNER_ID = "owner";
const MAX_FAILS = 5; // wrong passwords per IP ...
const FAIL_WINDOW_S = 900; // ... per 15 minutes
const WELL_KNOWN_PRC = "/.well-known/oauth-protected-resource";
const DEFAULT_REDIRECTS =
  "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback";

const enc = new TextEncoder();
const tunnelCache = { url: null, at: 0 };
let built = null; // { cfg, as, resources } - built once per isolate

class ConfigError extends Error {}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "cache-control": "no-store",
};

const text = (body, status = 200, extra = {}) =>
  new Response(body + "\n", {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", ...SECURITY_HEADERS, ...extra },
  });

const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Hash both sides first: constant-time and length-independent.
async function secretsEqual(given, expected) {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

const isLoopbackHost = (h) => h === "localhost" || h === "127.0.0.1" || h === "[::1]";

const pathCovers = (base, path) => path === base || path.startsWith(base + "/");

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

function loadConfig(env) {
  let origin;
  try {
    origin = new URL(env.PUBLIC_ORIGIN);
  } catch {
    throw new ConfigError("PUBLIC_ORIGIN is missing or not a URL");
  }
  const dev = origin.protocol === "http:" && isLoopbackHost(origin.hostname);
  if (origin.protocol !== "https:" && !dev) throw new ConfigError("PUBLIC_ORIGIN must be https");
  if (origin.pathname !== "/" || origin.search || origin.hash || origin.username) {
    throw new ConfigError("PUBLIC_ORIGIN must be a bare origin like https://name.sub.workers.dev");
  }

  const services = String(env.SERVICES ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (services.length === 0) throw new ConfigError("SERVICES is empty (e.g. /mcp/shell)");
  for (const s of services) {
    if (!/^(\/[A-Za-z0-9._~-]+)+$/.test(s) || s.split("/").some((seg) => seg === "." || seg === "..")) {
      throw new ConfigError(`SERVICES entry '${s}' must look like /mcp/name (no trailing slash)`);
    }
  }
  for (const a of services) {
    for (const b of services) {
      if (a !== b && pathCovers(a, b)) {
        throw new ConfigError(`SERVICES '${a}' covers '${b}': tokens for one would work on the other`);
      }
    }
  }

  const redirectUris = new Set();
  for (const raw of String(env.ALLOWED_REDIRECT_URIS || DEFAULT_REDIRECTS).split(",")) {
    const r = raw.trim();
    if (!r) continue;
    try {
      redirectUris.add(new URL(r).href);
    } catch {
      throw new ConfigError(`ALLOWED_REDIRECT_URIS has an invalid entry: ${r}`);
    }
  }

  const int = (name, dflt, min) => {
    const v = env[name] === undefined || env[name] === "" ? dflt : Number(env[name]);
    if (!Number.isInteger(v) || v < min) throw new ConfigError(`${name} must be an integer >= ${min}`);
    return v;
  };

  if (typeof env.OWNER_PASSWORD !== "string" || env.OWNER_PASSWORD.length < 20) {
    throw new ConfigError("secret OWNER_PASSWORD is not set (needs 20+ characters)");
  }
  if (typeof env.PROXY_TUNNEL_SECRET !== "string" || !/^[A-Za-z0-9_-]{24,}$/.test(env.PROXY_TUNNEL_SECRET)) {
    throw new ConfigError("secret PROXY_TUNNEL_SECRET is not set (24+ chars of A-Za-z0-9_-)");
  }
  if (!env.OAUTH_KV || !env.TUNNEL_KV) throw new ConfigError("KV bindings OAUTH_KV and TUNNEL_KV are required");

  return {
    origin: origin.origin,
    host: origin.host,
    dev,
    services,
    redirectUris,
    allowLoopback: String(env.ALLOW_LOOPBACK_REDIRECTS).toLowerCase() === "true",
    accessTtl: int("ACCESS_TOKEN_TTL_SECONDS", 3600, 60),
    grantDays: int("GRANT_LIFETIME_DAYS", 30, 1),
    tunnelSuffix: String(env.TUNNEL_HOST_SUFFIX ?? ".trycloudflare.com").toLowerCase(),
    backendHost: String(env.HTTP_HOST_HEADER || "proxy-cftunnel").toLowerCase(),
  };
}

// Only these redirect URIs may ever receive an authorization code.
function redirectAllowed(uri, cfg) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.username || u.password || u.hash) return false;
  if (cfg.redirectUris.has(u.href)) return true;
  return cfg.allowLoopback && u.protocol === "http:" && isLoopbackHost(u.hostname);
}

// ---------------------------------------------------------------------------
// the two OAuth roles
// ---------------------------------------------------------------------------

function getApp(env) {
  if (built) return built;
  const cfg = loadConfig(env);

  const as = new OAuthAuthorizationServer({
    issuer: cfg.origin,
    resources: cfg.services.map((s) => cfg.origin + s),
    // Claude prefers pre-registration, then CIMD, then DCR. Offer both of the
    // self-service ones; the redirect allowlist makes either safe to expose.
    // (CIMD needs the global_fetch_strictly_public flag, set in wrangler.jsonc.)
    clientIdMetadataDocumentEnabled: true,
    clientRegistrationEndpoint: "/oauth/register",
    clientRegistrationCallback: ({ clientMetadata }) => {
      const uris = clientMetadata.redirect_uris;
      const ok =
        Array.isArray(uris) && uris.length > 0 && uris.every((u) => typeof u === "string" && redirectAllowed(u, cfg));
      if (!ok) {
        console.warn("DCR refused: redirect_uris not on ALLOWED_REDIRECT_URIS", JSON.stringify(uris));
        return {
          code: "invalid_redirect_uri",
          description: "redirect_uris must all be on this gateway's allowlist",
          status: 400,
        };
      }
    },
    accessTokenTTL: cfg.accessTtl,
    refreshTokenTTL: cfg.grantDays * 86400,
  });

  const resources = cfg.services.map((path) => ({
    path,
    server: new OAuthResourceServer({
      resourceMetadata: {
        resource: cfg.origin + path,
        authorization_servers: [cfg.origin],
        bearer_methods_supported: ["header"],
        resource_name: `MCP ${path}`,
      },
      // This Worker is the authorization server: validate against it directly.
      validateToken: (env) => (resource, token) => as.validateToken(resource, token, env),
      handler: { fetch: (request, env) => proxy(request, env, cfg) },
    }),
  }));

  built = { cfg, as, resources };
  return built;
}

// ---------------------------------------------------------------------------
// the proxy (valid token only)
// ---------------------------------------------------------------------------

async function loadTunnelUrl(env, cfg) {
  if (tunnelCache.url && Date.now() - tunnelCache.at < CACHE_MS) return tunnelCache.url;
  const raw = (await env.TUNNEL_KV.get(KV_URL_KEY))?.trim() || null;
  let url = null;
  if (raw) {
    try {
      const u = new URL(raw);
      const okHost = u.hostname.toLowerCase().endsWith(cfg.tunnelSuffix) && cfg.tunnelSuffix !== "";
      const okDev = cfg.dev && isLoopbackHost(u.hostname); // local testing only
      if ((u.protocol === "https:" && okHost) || okDev) url = u.origin;
      else console.error("tunnel URL in KV rejected (host not under TUNNEL_HOST_SUFFIX)");
    } catch {
      console.error("tunnel URL in KV is not a valid URL");
    }
  }
  tunnelCache.url = url;
  tunnelCache.at = Date.now();
  return url;
}

// A backend redirect must stay on our host: a redirect to another host makes
// clients drop the Authorization header, and the connection then fails.
function rewriteRedirect(res, cfg, target) {
  const loc = res.headers.get("location");
  if (!loc || res.status < 300 || res.status >= 400) return res;
  let u;
  try {
    u = new URL(loc, target);
  } catch {
    return res;
  }
  const ours = u.hostname.toLowerCase() === target.hostname.toLowerCase() || u.hostname.toLowerCase() === cfg.backendHost;
  if (!ours) return res;
  const out = new Response(res.body, res);
  out.headers.set("location", cfg.origin + u.pathname + u.search);
  return out;
}

async function proxy(request, env, cfg) {
  const tunnelUrl = await loadTunnelUrl(env, cfg);
  if (!tunnelUrl) return text("502 Tunnel offline.", 502);

  const url = new URL(request.url);
  const target = new URL(tunnelUrl);
  target.pathname = url.pathname; // clean URLs: the public path *is* the service path
  target.search = url.search;

  // Client-supplied copies of our headers are overwritten, never trusted.
  const headers = new Headers(request.headers);
  headers.delete("authorization"); // the OAuth token stops here
  headers.delete("cookie");
  headers.delete("x-service-secret");
  headers.set("Host", target.hostname);
  headers.set("X-Tunnel-Secret", env.PROXY_TUNNEL_SECRET);
  headers.set("X-Client-IP", request.headers.get("CF-Connecting-IP") ?? "");
  headers.set("X-Forwarded-Host", url.host);
  headers.set("X-Forwarded-Proto", "https");

  try {
    const res = await fetch(
      new Request(target, {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
        redirect: "manual",
      }),
    );
    if (res.status === 530) tunnelCache.at = 0; // tunnel gone: re-read its URL next time
    return rewriteRedirect(res, cfg, target);
  } catch (err) {
    console.error("upstream fetch failed:", err?.message);
    tunnelCache.at = 0;
    return text("502 Upstream error.", 502);
  }
}

// ---------------------------------------------------------------------------
// /authorize: the owner-password consent page
// ---------------------------------------------------------------------------

const CSS = `
:root{color-scheme:light dark;--bg:#f2f4f7;--card:#fff;--ink:#16202a;--mute:#556270;--line:#d5dbe2;--accent:#1d5fbf;--accent-ink:#fff;--bad:#b3261e;--field:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1319;--card:#161d25;--ink:#e6ebf0;--mute:#98a6b4;--line:#2a3541;--accent:#6aa3f0;--accent-ink:#0b1117;--bad:#f2928b;--field:#0e1319}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.25rem;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%;max-width:30rem;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1.75rem}
h1{margin:0 0 1.25rem;font-size:1.3rem;line-height:1.3;font-weight:650}
dl{margin:0 0 1.25rem;display:grid;grid-template-columns:max-content 1fr;gap:.6rem 1rem;align-items:baseline}
dt{color:var(--mute);font-size:.9rem}
dd{margin:0;min-width:0;overflow-wrap:anywhere}
.dest{font:600 1.15rem/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.note{color:var(--mute);font-size:.92rem;margin:0 0 1.25rem}
.warn{border-left:3px solid var(--bad);padding:.1rem .8rem;margin:0 0 1.25rem}
label{display:block;font-weight:600;margin-bottom:.35rem}
input[type=password]{width:100%;padding:.65rem .75rem;font:inherit;color:var(--ink);background:var(--field);border:1px solid var(--line);border-radius:6px}
.err{color:var(--bad);margin:.6rem 0 0;font-size:.95rem}
.row{display:flex;gap:.75rem;margin-top:1.25rem}
button{font:inherit;font-weight:600;padding:.65rem 1.1rem;border-radius:6px;border:1px solid var(--line);background:transparent;color:var(--ink);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.primary:only-child{width:100%}
button:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
`;

const CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

function html(title, body, { status = 200, headers = new Headers() } = {}) {
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Content-Security-Policy", CSP);
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cache-Control", "no-store");
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head>` +
      `<body><main>${body}</main></body></html>`,
    { status, headers },
  );
}

function consentPage({ details, service, cfg, handle, headers, error, status }) {
  const name = esc(details.clientName);
  const who = details.clientDomain
    ? `${name}, published by <strong>${esc(details.clientDomain)}</strong>`
    : `${name} <span style="color:var(--mute)">(name set by the app, not verified)</span>`;
  const local = details.redirectIsLoopback
    ? `<p class="warn"><strong>This sends access to an app on your own computer.</strong> Continue only if you just started signing in from it.</p>`
    : "";
  return html(
    `Allow ${details.clientName}?`,
    `<h1>Allow ${name} to use ${esc(service)}?</h1>
<dl>
  <dt>Requested by</dt><dd>${who}</dd>
  <dt>Access is sent to</dt><dd class="dest">${esc(details.redirectHost)}</dd>
  <dt>Service</dt><dd>${esc(service)} on ${esc(cfg.host)}</dd>
</dl>
${local}<p class="note">If you allow it, this app can call that service on your machine for up to ${cfg.grantDays} days, or until you revoke it. It cannot reach your other services.</p>
<form method="post" autocomplete="off">
  <input type="hidden" name="handle" value="${esc(handle)}">
  <label for="pw">Owner password</label>
  <input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
  ${error ? `<p class="err" role="alert">${esc(error)}</p>` : ""}
  <div class="row">
    <button class="primary" type="submit" name="decision" value="approve">Allow access</button>
    <button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
  </div>
</form>`,
    { status, headers },
  );
}

const clientIp = (request) => request.headers.get("CF-Connecting-IP") || "unknown";
const failKey = (ip) => `x:pwfail:${ip}`;

async function failures(env, ip) {
  return parseInt((await env.OAUTH_KV.get(failKey(ip))) ?? "0", 10) || 0;
}
async function recordFailure(env, ip, current) {
  await env.OAUTH_KV.put(failKey(ip), String(current + 1), { expirationTtl: FAIL_WINDOW_S });
  return current + 1;
}
const clearFailures = (env, ip) => env.OAUTH_KV.delete(failKey(ip));

const tooMany = () =>
  text("429 Too many wrong passwords from this address. Try again in 15 minutes.", 429, {
    "retry-after": String(FAIL_WINDOW_S),
  });

function authorizeError(error, cfg) {
  if (error instanceof AuthorizationError) {
    if (error.redirectTo) {
      // Client and redirect URI were validated; still only ever redirect to an allowed one.
      const u = new URL(error.redirectTo);
      const base = new URL(u.origin + u.pathname);
      if (redirectAllowed(base.href, cfg)) return Response.redirect(error.redirectTo, 302);
    }
    return text(`400 ${error.description ?? "Invalid authorization request."}`, 400);
  }
  if (error instanceof CimdFetchError) {
    console.warn("CIMD fetch failed:", error.reason);
    return text("400 This app could not be verified.", 400);
  }
  throw error;
}

async function authorize(request, env, { cfg, as }) {
  if (request.method !== "GET" && request.method !== "POST") {
    return text("405 Method not allowed.", 405, { allow: "GET, POST" });
  }
  const oauth = as.getOAuthApi(env);
  try {
    const authReq = await oauth.parseAuthRequest(request);
    if (!redirectAllowed(authReq.redirectUri, cfg)) {
      console.warn("authorize refused: redirect URI not allowed:", authReq.redirectUri);
      return text("400 This app's redirect address is not allowed by this gateway.", 400);
    }
    const details = await oauth.describeConsent(authReq); // before beginConsent: a failed lookup leaves nothing in KV
    const service = new URL(authReq.resource).pathname;
    const show = async (extra = {}) => {
      const consent = await oauth.beginConsent(authReq);
      return consentPage({ details, service, cfg, handle: consent.handle, headers: consent.headers, ...extra });
    };

    if (request.method === "GET") return await show();

    // ---- POST: the owner decided ----
    const ip = clientIp(request);
    const failed = await failures(env, ip);
    if (failed >= MAX_FAILS) return tooMany();

    const form = await request.formData();
    const handle = String(form.get("handle") ?? "");

    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }

    // Check the password *before* consuming the one-time handle, so a typo doesn't kill the page.
    if (!(await secretsEqual(String(form.get("password") ?? ""), env.OWNER_PASSWORD))) {
      const n = await recordFailure(env, ip, failed);
      const left = MAX_FAILS - n;
      console.warn("wrong owner password at /authorize");
      return left > 0
        ? await show({ error: `Wrong password. ${left} ${left === 1 ? "attempt" : "attempts"} left.`, status: 401 })
        : tooMany();
    }
    await clearFailures(env, ip);

    const approved = await oauth.approveConsent(request, handle); // stored request, not the form's
    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request,
      userId: OWNER_ID,
      metadata: { clientName: details.clientName, resource: authReq.resource },
      scope: [], // access is controlled by the audience (one service per token), not by scopes
      props: { userId: OWNER_ID },
    });
    approved.headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (error) {
    return authorizeError(error, cfg);
  }
}

// ---------------------------------------------------------------------------
// /revoke: kill switch (owner password): revokes every grant and token
// ---------------------------------------------------------------------------

async function revoke(request, env, { cfg, as }) {
  if (request.method !== "GET" && request.method !== "POST") {
    return text("405 Method not allowed.", 405, { allow: "GET, POST" });
  }
  const form = (error, status = 200) =>
    html(
      "Revoke all access",
      `<h1>Revoke all access?</h1>
<p class="note">Every connector signed in to ${esc(cfg.host)} stops working immediately and has to ask you to sign in again.</p>
<form method="post" autocomplete="off">
  <label for="pw">Owner password</label>
  <input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
  ${error ? `<p class="err" role="alert">${esc(error)}</p>` : ""}
  <div class="row"><button class="primary" type="submit">Revoke all access</button></div>
</form>`,
      { status },
    );
  if (request.method === "GET") return form();

  const ip = clientIp(request);
  const failed = await failures(env, ip);
  if (failed >= MAX_FAILS) return tooMany();
  const body = await request.formData();
  if (!(await secretsEqual(String(body.get("password") ?? ""), env.OWNER_PASSWORD))) {
    const n = await recordFailure(env, ip, failed);
    return n >= MAX_FAILS ? tooMany() : form("Wrong password.", 401);
  }
  await clearFailures(env, ip);

  const oauth = as.getOAuthApi(env);
  let revoked = 0;
  let cursor;
  do {
    const page = await oauth.listUserGrants(OWNER_ID, { limit: 100, cursor });
    for (const g of page.items) {
      await oauth.revokeGrant(g.id, OWNER_ID);
      revoked++;
    }
    cursor = page.cursor;
  } while (cursor);
  console.warn(`revoked ${revoked} grant(s)`);
  return html(
    "Access revoked",
    `<h1>Access revoked</h1><p class="note" style="margin:0">${revoked} ${revoked === 1 ? "grant was" : "grants were"} revoked. Connectors will ask you to sign in again.</p>`,
  );
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------

function resourceFor(path, resources) {
  // /.well-known/oauth-protected-resource/<service path> belongs to that service too
  const p = path.startsWith(WELL_KNOWN_PRC + "/") ? path.slice(WELL_KNOWN_PRC.length) : path;
  return resources.find((r) => pathCovers(r.path, p));
}

const route = {
  async fetch(request, env, ctx) {
    // Only this Worker's own proxy() sends the real X-Tunnel-Secret. If a request arrives carrying it, the
    // quick tunnel is pointing back at this Worker (check SERVICE_URL in .env) - refuse the loop.
    const stamped = request.headers.get("x-tunnel-secret");
    if (stamped && typeof env.PROXY_TUNNEL_SECRET === "string" && (await secretsEqual(stamped, env.PROXY_TUNNEL_SECRET))) {
      console.error("LOOP: request carries X-Tunnel-Secret; the tunnel's origin is this Worker, not nginx");
      return text("508 Loop detected: the tunnel forwards back to this Worker. Check SERVICE_URL in advanced-oauth/.env (should be https://proxy-cftunnel:9443).", 508);
    }
    let app;
    try {
      app = getApp(env);
    } catch (err) {
      if (!(err instanceof ConfigError)) throw err;
      console.error("misconfigured:", err.message);
      return text(`503 Gateway misconfigured: ${err.message}`, 503);
    }
    const { cfg, as, resources } = app;
    const url = new URL(request.url);
    if (url.origin !== cfg.origin) return text("404 Not found.", 404); // only the configured issuer host

    if (url.pathname === "/authorize") return authorize(request, env, app);
    if (url.pathname === "/revoke") return revoke(request, env, app);

    const r = resourceFor(url.pathname, resources);
    if (r) return r.server.fetch(request, env, ctx);

    // discovery (authorization-server metadata), registration, token, revocation
    return as.fetch(request, env, ctx);
  },

  // Cron: sweep expired/orphaned OAuth records (KV TTLs do most of it already).
  async scheduled(_event, env, ctx) {
    const { as } = getApp(env);
    ctx.waitUntil(as.purgeExpiredData(env).then((r) => console.log("purge:", JSON.stringify(r))));
  },
};

// Debug (delete once the connector works): one log line per request with the real HTTP status.
// Logs shapes only: header NAMES, token lengths, field names. Never token values, codes or verifiers.
const shape = (t) => (typeof t === "string" ? `len=${t.length},parts=${t.split(":").length}` : "none");
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    let pre = "";
    try {
      if (url.pathname.startsWith("/mcp/")) {
        const a = request.headers.get("authorization");
        pre = ` | auth=${a ? a.split(" ")[0] + "/" + shape(a.split(" ").slice(1).join(" ")) : "NONE"}` +
          ` | headers=${[...request.headers.keys()].filter((k) => !k.startsWith("cf-") && !k.startsWith("x-forwarded")).join(",")}`;
      } else if (url.pathname === "/oauth/token" && request.method === "POST") {
        const f = await request.clone().formData();
        pre = ` | grant=${f.get("grant_type")} client_id=${f.get("client_id")} resource=${f.get("resource")} redirect_uri=${f.get("redirect_uri")} scope=${f.get("scope")} has_secret=${f.has("client_secret")} has_assertion=${f.has("client_assertion")}`;
      }
    } catch {}
    const res = await route.fetch(request, env, ctx);
    try {
      const www = res.headers.get("www-authenticate");
      let post = "";
      if (url.pathname === "/oauth/token") {
        const j = await res.clone().json().catch(() => null);
        if (j) post = ` | resp keys=${Object.keys(j).join(",")} token_type=${j.token_type} expires_in=${j.expires_in} scope=${JSON.stringify(j.scope)} access=${shape(j.access_token)} error=${j.error ?? ""} ${j.error_description ?? ""}`;
      }
      console.log(`${request.method} ${url.pathname} -> ${res.status}${pre}${post}` + (www ? ` | www-authenticate: ${www.slice(0, 240)}` : ""));
    } catch {}
    return res;
  },
  scheduled: route.scheduled,
};