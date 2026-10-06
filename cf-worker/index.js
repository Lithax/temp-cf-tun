var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.ts
var CF_TUNNEL_REDIRECT_KEY = "CF_TUNNEL_REDIRECT";
function authFail() {
  return new Response("401 Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Restricted Area"'
    }
  });
}
__name(authFail, "authFail");
var index_default = {
  async fetch(request, env, ctx) {
    const clientIP = request.headers.get("cf-connecting-ip") || "unknown-ip";
    const { success } = await env.RATE_LIMIT.limit({ key: clientIP });
    if (!success) {
      return new Response("Too Many Requests. Please slow down.", { status: 429 });
    }
    const auth = request.headers.get("Authorization");
    if (!auth || !auth.startsWith("Basic ")) return authFail();
    const base64 = auth.slice(6);
    const decoded = atob(base64);
    const [givenUser, givenPassword] = decoded.split(":");
    const authenticated = env.USER == givenUser && env.PASSWORD == givenPassword;
    if (!authenticated) return authFail();
    const tunnelBaseUrl = await env.terz.get(CF_TUNNEL_REDIRECT_KEY);
    if (!tunnelBaseUrl) {
      return new Response("Tunnel URL not found in KV storage.", { status: 404 });
    }
    const incomingUrl = new URL(request.url);
    const targetUrl = new URL(incomingUrl.pathname + incomingUrl.search, tunnelBaseUrl);
    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set("X-Tunnel-Secret", env.SHARED_SECRET);
    proxyHeaders.set("Host", targetUrl.hostname);
    const proxyRequest = new Request(targetUrl.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: request.body,
      redirect: "manual"
      // Prevents the worker from following 301s natively, passing them to the browser instead
    });
    try {
      return await fetch(proxyRequest);
    } catch (error) {
      return new Response(`Error connecting to tunnel: ${error}`, { status: 502 });
    }
  }
};
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
