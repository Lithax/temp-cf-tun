// End-to-end test: runs the Worker in workerd (wrangler dev, simulated KV), stands up a fake
// "tunnel" upstream, and plays an MCP client through the whole OAuth flow the way Claude does:
// 401 challenge -> metadata discovery -> dynamic client registration -> PKCE authorize (consent
// page + owner password) -> token -> refresh -> proxied call.   Run: npm run test:e2e
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, openSync, readFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const PORT = 8799;
const UP_PORT = 9999;
const ORIGIN = `http://localhost:${PORT}`;
const CB = "https://claude.ai/api/mcp/auth_callback";
const PASSWORD = "test-owner-password-" + randomBytes(6).toString("hex");
const TUNNEL_SECRET = "tunnel_" + randomBytes(16).toString("hex");
const state = mkdtempSync(join(tmpdir(), "oauth-gw-"));
const devVars = join(here, ".dev.vars");
const LOG = join(tmpdir(), "oauth-gw-e2e.log");
const cfgArgs = ["-c", join(here, "wrangler.test.jsonc")];

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) pass++;
  else fail++;
  console.log(`${ok ? "  ok  " : " FAIL "} ${name}${!ok && detail ? `\n         -> ${detail}` : ""}`);
}
const section = (s) => console.log(`\n${s}`);

// ---- fake tunnel upstream -------------------------------------------------
const seen = [];
const upstream = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
  if (req.url.startsWith("/mcp/shell/sse")) {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("data: one\n\n");
    setTimeout(() => (res.write("data: two\n\n"), res.end()), 1500);
    return;
  }
  if (req.url.startsWith("/mcp/shell/redir")) {
    res.writeHead(307, { location: "http://proxy-cftunnel/mcp/shell/redir/" });
    return res.end();
  }
  if (req.url.startsWith("/mcp/shell/ext")) {
    res.writeHead(302, { location: "https://example.org/elsewhere" });
    return res.end();
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, path: req.url }));
});

// ---- tiny OAuth client ------------------------------------------------------
const b64url = (b) => b.toString("base64url");
const pkce = () => {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
};
const jar = new Map();
function eat(res) {
  for (const line of res.headers.getSetCookie?.() ?? []) {
    const [pair, ...attrs] = line.split(";").map((s) => s.trim());
    const i = pair.indexOf("=");
    const [name, value] = [pair.slice(0, i), pair.slice(i + 1)];
    if (attrs.some((a) => /^max-age=0$/i.test(a)) || value === "") jar.delete(name);
    else jar.set(name, value);
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const req = (path, init = {}) => fetch(ORIGIN + path, { redirect: "manual", ...init });

async function register(name, redirect = CB) {
  const r = await req("/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirect],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

function authorizeUrl(clientId, resource, ch, extra = {}) {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: CB,
    code_challenge: ch,
    code_challenge_method: "S256",
    state: "st-" + randomBytes(4).toString("hex"),
    resource,
    ...extra,
  });
  return "/authorize?" + p;
}

async function consent(url) {
  jar.clear();
  const res = await req(url, { headers: { cookie: cookieHeader() } });
  eat(res);
  const body = await res.text();
  return { res, body, handle: /name="handle" value="([^"]+)"/.exec(body)?.[1], url };
}
const post = (c, fields, cookie = cookieHeader()) =>
  req(c.url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({ handle: c.handle, ...fields }),
  });

async function fullFlow(clientId, resource, { password = PASSWORD } = {}) {
  const { verifier, challenge } = pkce();
  const c = await consent(authorizeUrl(clientId, resource, challenge));
  const res = await post(c, { decision: "approve", password });
  const loc = res.headers.get("location");
  if (res.status !== 302 || !loc) return { c, res, loc };
  const code = new URL(loc).searchParams.get("code");
  return { c, res, loc, code, verifier };
}
const tokenReq = (fields) =>
  req("/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
const call = (path, token, init = {}) =>
  req(path, { ...init, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...init.headers } });


const kvPut = (value) =>
  execFileSync("npx", ["wrangler", "kv", "key", "put", "CF_TUNNEL_REDIRECT", value, "--binding", "personal", "--local", "--persist-to", state, ...cfgArgs], { cwd: root, stdio: "ignore" });

async function startDev() {
  // Never test against a stale server from an earlier run.
  const busy = await fetch(ORIGIN, { signal: AbortSignal.timeout(2000) }).then(() => true, (e) => e.name === "TimeoutError");
  if (busy) throw new Error(`port ${PORT} is already in use; stop whatever is listening there`);
  const log = openSync(LOG, "a");
  // Own process group, so cleanup can kill npx *and* the workerd it spawns.
  dev = spawn("npx", ["wrangler", "dev", ...cfgArgs, "--port", String(PORT), "--local", "--persist-to", state, "--test-scheduled"], {
    cwd: root,
    stdio: ["ignore", log, log],
    detached: true,
  });
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(ORIGIN + "/mcp/shell", { signal: AbortSignal.timeout(2000) })).status === 401) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("wrangler dev did not start");
}
async function stopDev() {
  if (!dev?.pid) return;
  try {
    process.kill(-dev.pid, "SIGTERM");
  } catch {}
  for (let i = 0; i < 40; i++) {
    if (!(await fetch(ORIGIN, { signal: AbortSignal.timeout(1000) }).then(() => true, () => false))) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  dev = null;
}

// ---- run ----------------------------------------------------------------------
let dev;
async function main() {
  writeFileSync(devVars, `OWNER_PASSWORD=${PASSWORD}\nPROXY_TUNNEL_SECRET=${TUNNEL_SECRET}\n`);
  await new Promise((r) => upstream.listen(UP_PORT, "127.0.0.1", r));
  kvPut(`http://127.0.0.1:${UP_PORT}`);
  await startDev();
  const SHELL = `${ORIGIN}/mcp/shell`;
  const FILES = `${ORIGIN}/mcp/files`;

  section("Discovery: what Claude sees before it is signed in");
  let r = await req("/mcp/shell", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const www = r.headers.get("www-authenticate") ?? "";
  check("unauthenticated MCP call -> 401", r.status === 401, String(r.status));
  check("401 names the path-inserted resource metadata", www.includes(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp/shell"`), www);
  r = await req("/.well-known/oauth-protected-resource/mcp/shell");
  let j = await r.json();
  check("protected-resource metadata: resource + authorization_servers", r.status === 200 && j.resource === SHELL && j.authorization_servers?.[0] === ORIGIN, JSON.stringify(j));
  r = await req("/.well-known/oauth-authorization-server");
  j = await r.json();
  check("AS metadata: authorize/token/registration endpoints", !!j.authorization_endpoint && !!j.token_endpoint && !!j.registration_endpoint, JSON.stringify(j));
  check("AS metadata: S256 PKCE advertised", j.code_challenge_methods_supported?.includes("S256"));
  check("AS metadata: CIMD advertised", j.client_id_metadata_document_supported === true);
  check("origin root is not a service", (await req("/")).status !== 200);

  section("Client registration policy (redirect allowlist)");
  let reg = await register("Evil", "https://evil.example/cb");
  check("DCR with a non-allowlisted redirect is refused", reg.status === 400, JSON.stringify(reg));
  reg = await register("Claude (test)");
  const clientId = reg.body.client_id;
  check("DCR with Claude's callback is accepted", reg.status === 201 && !!clientId, JSON.stringify(reg));

  section("/authorize: consent page and owner password");
  const { verifier: v0, challenge: ch0 } = pkce();
  let c = await consent(authorizeUrl(clientId, SHELL, ch0));
  check("consent page renders with a handle and a binding cookie", c.res.status === 200 && !!c.handle && jar.size > 0, `${c.res.status}`);
  check("page forbids framing + has a strict CSP", /frame-ancestors 'none'/.test(c.res.headers.get("content-security-policy") ?? "") && c.res.headers.get("x-frame-options") === "DENY");
  check("page shows client, destination host and service", c.body.includes("Claude (test)") && c.body.includes("claude.ai") && c.body.includes("/mcp/shell"));

  const xss = await register(`<script>alert(1)</script>`);
  const cx = await consent(authorizeUrl(xss.body.client_id, SHELL, ch0));
  check("client-supplied name is HTML-escaped", cx.res.status === 200 && !cx.body.includes("<script>alert(1)") && cx.body.includes("&#60;script&#62;"));

  c = await consent(authorizeUrl(clientId, SHELL, ch0));
  let res = await post(c, { decision: "approve", password: PASSWORD }, "");
  check("POST without the browser-bound cookie is refused (CSRF)", res.status === 400, `${res.status}`);

  res = await req(authorizeUrl(clientId, SHELL, ch0).replace(encodeURIComponent(CB), encodeURIComponent("https://evil.example/cb")));
  check("authorize with a different redirect_uri is refused, not redirected", res.status === 400 && !res.headers.get("location"), `${res.status}`);

  res = await req(authorizeUrl(clientId, FILES.replace("files", "nope"), ch0));
  check("authorize for an unknown resource is refused", res.status !== 200, `${res.status}`);

  c = await consent(authorizeUrl(clientId, SHELL, ch0));
  res = await post(c, { decision: "approve", password: "wrong-password" });
  let body = await res.text();
  check("wrong password -> 401 page with attempts left", res.status === 401 && /4 attempts left/.test(body), `${res.status} ${body.slice(0, 80)}`);

  const flow = await fullFlow(clientId, SHELL);
  const cbUrl = new URL(flow.loc ?? "http://x/");
  check("right password -> 302 to Claude's callback with code, state, iss", flow.res.status === 302 && cbUrl.origin + cbUrl.pathname === CB && !!flow.code && cbUrl.searchParams.get("iss") === ORIGIN, flow.loc);
  res = await post(flow.c, { decision: "approve", password: PASSWORD });
  check("consent handle is single-use", res.status === 400, `${res.status}`);

  c = await consent(authorizeUrl(clientId, SHELL, ch0, { state: "deny-me" }));
  res = await post(c, { decision: "deny" });
  const dl = new URL(res.headers.get("location") ?? "http://x/");
  check("Deny -> redirect with error=access_denied and state", res.status === 302 && dl.searchParams.get("error") === "access_denied" && dl.searchParams.get("state") === "deny-me", res.headers.get("location"));

  section("Token endpoint");
  // (a new grant for the same client + resource revokes the older one, so use a separate client here)
  const other = (await register("Claude (second install)")).body.client_id;
  const bad = await fullFlow(other, SHELL);
  res = await tokenReq({ grant_type: "authorization_code", code: bad.code, redirect_uri: CB, client_id: other, code_verifier: b64url(randomBytes(32)), resource: SHELL });
  check("wrong PKCE verifier is refused", res.status === 400, `${res.status}`);

  res = await tokenReq({ grant_type: "authorization_code", code: flow.code, redirect_uri: CB, client_id: clientId, code_verifier: flow.verifier, resource: SHELL });
  const tok = await res.json();
  check("code + verifier -> access_token and refresh_token", res.status === 200 && !!tok.access_token && !!tok.refresh_token && /bearer/i.test(tok.token_type), JSON.stringify(tok));

  section("Proxy: what a valid token reaches");
  seen.length = 0;
  res = await call("/mcp/shell", tok.access_token, {
    method: "POST",
    headers: { "content-type": "application/json", "x-tunnel-secret": "evil", "x-service-secret": "evil", cookie: "a=b", "mcp-session-id": "sess-1" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  const s = seen.at(-1) ?? { headers: {} };
  check("valid token -> 200 from upstream", res.status === 200 && (await res.json()).ok === true, `${res.status} ${res.headers.get("www-authenticate") ?? ""}`);
  check("upstream saw the same path (no prefix games)", s.url === "/mcp/shell", s.url);
  check("upstream got the real X-Tunnel-Secret (client's overwritten)", s.headers["x-tunnel-secret"] === TUNNEL_SECRET);
  check("OAuth token, cookie and X-Service-Secret never reach the backend", !s.headers.authorization && !s.headers.cookie && !s.headers["x-service-secret"], JSON.stringify(s.headers));
  check("body and MCP headers pass through", s.body.includes("tools/list") && s.headers["mcp-session-id"] === "sess-1" && s.method === "POST");
  check("X-Forwarded-Host/Proto set", s.headers["x-forwarded-host"] === `localhost:${PORT}` && s.headers["x-forwarded-proto"] === "https");

  res = await call("/mcp/shell/deep/path?x=1&y=2", tok.access_token);
  check("descendant path + query are forwarded", seen.at(-1)?.url === "/mcp/shell/deep/path?x=1&y=2" && res.status === 200, seen.at(-1)?.url);

  res = await call("/mcp/files", tok.access_token, { method: "POST", body: "{}" });
  check("a /mcp/shell token is refused on /mcp/files (audience isolation)", res.status === 401, `${res.status}`);
  res = await call("/mcp/shell", "not-a-real-token", { method: "POST", body: "{}" });
  check("garbage bearer -> 401", res.status === 401, `${res.status}`);

  const t0 = Date.now();
  res = await call("/mcp/shell/sse", tok.access_token);
  const reader = res.body.getReader();
  const first = await reader.read();
  const tFirst = Date.now() - t0;
  const rest = await reader.read();
  check("SSE streams through (first event before upstream finishes)", new TextDecoder().decode(first.value).includes("one") && tFirst < 1200 && new TextDecoder().decode(rest.value ?? new Uint8Array()).includes("two"), `first chunk after ${tFirst}ms`);

  res = await call("/mcp/shell/redir", tok.access_token);
  check("backend redirect to its internal host is rewritten to the public origin", res.status === 307 && res.headers.get("location") === `${ORIGIN}/mcp/shell/redir/`, res.headers.get("location"));
  res = await call("/mcp/shell/ext", tok.access_token);
  check("redirect to a foreign host is left alone", res.headers.get("location") === "https://example.org/elsewhere", res.headers.get("location"));

  section("Refresh");
  res = await tokenReq({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: clientId });
  const tok2 = await res.json();
  check("refresh_token -> new access token", res.status === 200 && !!tok2.access_token && tok2.access_token !== tok.access_token, JSON.stringify(tok2));
  res = await call("/mcp/shell", tok2.access_token, { method: "POST", body: "{}" });
  check("refreshed token works", res.status === 200, `${res.status}`);

  section("Second service gets its own grant");
  const f2 = await fullFlow(clientId, FILES);
  res = await tokenReq({ grant_type: "authorization_code", code: f2.code, redirect_uri: CB, client_id: clientId, code_verifier: f2.verifier, resource: FILES });
  const filesTok = await res.json();
  res = await call("/mcp/files", filesTok.access_token, { method: "POST", body: "{}" });
  check("/mcp/files token works on /mcp/files", res.status === 200, `${res.status}`);
  res = await call("/mcp/shell", filesTok.access_token, { method: "POST", body: "{}" });
  check("...but not on /mcp/shell", res.status === 401, `${res.status}`);
  res = await call("/mcp/shell", tok2.access_token, { method: "POST", body: "{}" });
  check("the shell grant survived the files grant", res.status === 200, `${res.status}`);

  section("Authorization-code replay");
  const rp = (await register("Claude (replay test)")).body.client_id;
  const rf = await fullFlow(rp, SHELL);
  const exch = () => tokenReq({ grant_type: "authorization_code", code: rf.code, redirect_uri: CB, client_id: rp, code_verifier: rf.verifier, resource: SHELL });
  const rtok = await (await exch()).json();
  res = await call("/mcp/shell", rtok.access_token, { method: "POST", body: "{}" });
  check("fresh token works", res.status === 200, `${res.status}`);
  res = await exch();
  check("replaying the code is refused", res.status === 400, `${res.status}`);
  res = await call("/mcp/shell", rtok.access_token, { method: "POST", body: "{}" });
  check("...and revokes the token already issued from it", res.status === 401, `${res.status}`);

  section("Tunnel URL guard (KV value is validated)");
  const gc = (await register("Claude (guard test)")).body.client_id;
  const gf = await fullFlow(gc, SHELL);
  const gtok = await (await tokenReq({ grant_type: "authorization_code", code: gf.code, redirect_uri: CB, client_id: gc, code_verifier: gf.verifier, resource: SHELL })).json();
  await stopDev();
  kvPut("https://evil.example.com"); // not under .trycloudflare.com
  await startDev(); // OAuth state persists, so gtok is still valid
  seen.length = 0;
  res = await call("/mcp/shell", gtok.access_token, { method: "POST", body: "{}" });
  check("tunnel URL outside TUNNEL_HOST_SUFFIX is refused (502, nothing forwarded)", res.status === 502 && seen.length === 0, `${res.status}`);
  await stopDev();
  kvPut(`http://127.0.0.1:${UP_PORT}`);
  await startDev();
  res = await call("/mcp/shell", gtok.access_token, { method: "POST", body: "{}" });
  check("...and a good URL works again after restart", res.status === 200, `${res.status}`);

  section("Cron purge");
  res = await fetch(`${ORIGIN}/cdn-cgi/handler/scheduled`);
  check("scheduled() runs purgeExpiredData without error", res.status === 200, `${res.status}`);

  section("/revoke kill switch");
  res = await req("/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: "nope" }) });
  check("wrong password -> 401", res.status === 401, `${res.status}`);
  res = await req("/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: PASSWORD }) });
  body = await res.text();
  check("right password revokes grants", res.status === 200 && /grants? (was|were) revoked/.test(body), body.slice(0, 200));
  res = await call("/mcp/shell", tok2.access_token, { method: "POST", body: "{}" });
  check("revoked access token no longer works", res.status === 401, `${res.status}`);
  res = await tokenReq({ grant_type: "refresh_token", refresh_token: tok2.refresh_token, client_id: clientId });
  check("revoked refresh token no longer works", res.status >= 400, `${res.status}`);

  section("Brute-force lockout");
  let last;
  for (let i = 0; i < 6; i++) {
    const cc = await consent(authorizeUrl(clientId, SHELL, ch0));
    last = await post(cc, { decision: "approve", password: "guess-" + i });
  }
  check("after 5 wrong passwords -> 429 with Retry-After", last.status === 429 && !!last.headers.get("retry-after"), `${last.status}`);
  const cc = await consent(authorizeUrl(clientId, SHELL, ch0));
  res = await post(cc, { decision: "approve", password: PASSWORD });
  check("even the right password is refused while locked out", res.status === 429, `${res.status}`);
}

try {
  await main();
} catch (e) {
  fail++;
  console.log(` FAIL  test run crashed: ${e.stack || e}`);
} finally {
  if (fail) {
    try {
      console.log("\n--- last Worker log lines (" + LOG + ") ---");
      console.log(readFileSync(LOG, "utf8").split("\n").slice(-40).join("\n"));
    } catch {}
  }
  await stopDev();
  upstream.close();
  rmSync(state, { recursive: true, force: true });
  rmSync(devVars, { force: true });
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
