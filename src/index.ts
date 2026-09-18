import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer, BERNSTEIN_VERSION, type RequestTrace } from "./mcp.js";
import { renderHome } from "./pages/home.js";
import { base64UrlDecode, renderVerdict, renderVerifyForm, verdictJson } from "./pages/verify.js";
import { verifyReceiptBounded } from "./verify/bounded.js";
import { KEYS_PATH, loadSigner, signVerdict, type Signer } from "./verify/attest.js";
import frauncesLatin from "../fonts/fraunces-latin.woff2";
import frauncesLatinItalic from "../fonts/fraunces-latin-italic.woff2";
import jetbrainsMonoLatin from "../fonts/jetbrains-mono-latin.woff2";
import {
  MAX_BODY_BYTES,
  readBodyWithLimit,
  parseJsonWithDepthLimit,
  jsonRpcError,
  withStandardHeaders,
  JSON_RPC_PARSE_ERROR,
  JSON_RPC_REQUEST_TOO_LARGE,
} from "./limits.js";

// Bindings: the rate limiter (wrangler.toml [[ratelimits]]) and one secret.
// No KV/R2/D1/DO/service binding, nothing to pivot on. The zone's single free
// WAF rate-limit rule is taken by the leaked-credential check, so the
// 60 req/min/IP limit lives here instead. Absent (unit tests, `wrangler dev`
// without the binding) means unlimited. VERDICT_SIGNING_KEY is the private
// Ed25519 JWK that signs verdict statements; absent → verdicts are unsigned.
export interface Env {
  MCP_RATE_LIMITER?: RateLimit;
  VERDICT_SIGNING_KEY?: string;
}

const RATE_LIMIT_PERIOD_S = 60;

function rateLimited(): Response {
  return jsonResponse(
    {
      error: "rate_limited",
      message: "More than 60 requests per minute from this address; retry later.",
    },
    429,
    { "retry-after": String(RATE_LIMIT_PERIOD_S) },
  );
}

/** True when the caller has exhausted its per-IP bucket. Fails open: a
 * limiter error must not take the endpoint down. */
async function overLimit(request: Request, env: Env): Promise<boolean> {
  if (!env.MCP_RATE_LIMITER) return false;
  const key = request.headers.get("cf-connecting-ip") ?? "unknown";
  try {
    const { success } = await env.MCP_RATE_LIMITER.limit({ key });
    return !success;
  } catch {
    return false;
  }
}

function jsonResponse(
  body: unknown,
  status: number,
  extraHeaders?: Record<string, string>,
): Response {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
  return withStandardHeaders(response);
}

function methodNotAllowed(allow: string[]): Response {
  return jsonResponse(
    {
      error: "method_not_allowed",
      message: `This route only accepts ${allow.join(", ")}.`,
    },
    405,
    { Allow: allow.join(", ") },
  );
}

function notFound(): Response {
  return jsonResponse({ error: "not_found" }, 404);
}

/** The fields of a JSON-RPC envelope worth a log line: method, tool, client. */
function describeRpc(value: unknown, log: RequestLog): void {
  const msgs = Array.isArray(value) ? value : [value];
  for (const m of msgs) {
    if (!m || typeof m !== "object") continue;
    const { method, params } = m as { method?: unknown; params?: Record<string, unknown> };
    if (typeof method !== "string") continue;
    log.rpc = log.rpc ? `${log.rpc},${method}` : method;
    if (method === "initialize" && params) {
      const ci = params["clientInfo"] as { name?: unknown; version?: unknown } | undefined;
      if (ci && typeof ci.name === "string") log.client = ci.name.slice(0, 80);
      if (ci && typeof ci.version === "string") log.client_version = ci.version.slice(0, 40);
      if (typeof params["protocolVersion"] === "string") log.protocol = (params["protocolVersion"] as string).slice(0, 20);
    }
    if (method === "tools/call" && params && typeof params["name"] === "string") log.tool = params["name"] as string;
  }
}

/**
 * Handles POST /mcp: stateless Streamable HTTP via the official SDK's
 * web-standard transport. A fresh McpServer + transport is built for every
 * request — no state survives between requests, and there is no session id.
 */
async function handleMcpPost(request: Request, signer: Signer | null, log: RequestLog): Promise<Response> {
  const bodyResult = await readBodyWithLimit(request, MAX_BODY_BYTES);
  if (!bodyResult.ok) {
    return jsonResponse(
      jsonRpcError(
        null,
        JSON_RPC_REQUEST_TOO_LARGE,
        "Request body exceeds the 1 MB limit.",
      ),
      413,
    );
  }

  const parsed = parseJsonWithDepthLimit(bodyResult.text);
  if (!parsed.ok) {
    const message =
      parsed.reason === "parse_error"
        ? "Parse error: request body is not valid JSON."
        : "Request JSON is nested deeper than the allowed limit.";
    // The SDK itself would answer a bad body with -32700 and HTTP 200/400;
    // we pre-parse (for the size + depth guards) so we return the same
    // JSON-RPC shape ourselves rather than re-reading the body twice.
    return jsonResponse(jsonRpcError(null, JSON_RPC_PARSE_ERROR, message), 200);
  }

  describeRpc(parsed.value, log);
  const trace: RequestTrace = {};
  const server = createServer({ signer, trace });
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless: no session id anywhere
    enableJsonResponse: true,
  });

  try {
    await server.connect(transport);
    const response = await transport.handleRequest(request, {
      parsedBody: parsed.value,
    });
    if (trace.verdict) log.verdict = trace.verdict;
    return withStandardHeaders(response);
  } catch {
    // Never leak a stack trace: any unexpected failure becomes a JSON-RPC
    // internal-error object.
    return jsonResponse(jsonRpcError(null, -32603, "Internal error."), 200);
  } finally {
    await transport.close().catch(() => undefined);
  }
}

const FONTS: Record<string, ArrayBuffer> = {
  "/fonts/fraunces-latin.woff2": frauncesLatin,
  "/fonts/fraunces-latin-italic.woff2": frauncesLatinItalic,
  "/fonts/jetbrains-mono-latin.woff2": jetbrainsMonoLatin,
};

function html(markup: string, cacheControl = "no-store"): Response {
  const response = withStandardHeaders(
    new Response(markup, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }),
  );
  response.headers.set("cache-control", cacheControl);
  // A share link carries the receipt in its query string; no referrer may
  // ever leak it to a linked site. Inline script/style are the page's own.
  response.headers.set("referrer-policy", "no-referrer");
  response.headers.set(
    "content-security-policy",
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; font-src 'self'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  return response;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

function wantsJson(request: Request): boolean {
  const accept = request.headers.get("accept") ?? "";
  return accept.includes("application/json") && !accept.includes("text/html");
}

/** Read the receipt out of a form post, a JSON post, or a raw text post. */
async function receiptFromPost(request: Request): Promise<{ ok: true; receipt: string } | { ok: false; status: number; message: string }> {
  const body = await readBodyWithLimit(request, MAX_BODY_BYTES);
  if (!body.ok) return { ok: false, status: 413, message: "Request body exceeds the 1 MB limit." };
  const type = request.headers.get("content-type") ?? "";
  if (type.startsWith("application/x-www-form-urlencoded")) {
    const receipt = new URLSearchParams(body.text).get("receipt");
    if (receipt === null) return { ok: false, status: 400, message: "Form field `receipt` is missing." };
    return { ok: true, receipt };
  }
  if (type.startsWith("application/json")) {
    // Either {"receipt": <string|object>} or the receipt object itself.
    const parsed = parseJsonWithDepthLimit(body.text);
    if (!parsed.ok) return { ok: false, status: 400, message: "Body is not valid JSON." };
    const v = parsed.value as { receipt?: unknown; receipt_type?: unknown };
    if (v && typeof v === "object" && "receipt" in v && !("receipt_type" in v)) {
      return { ok: true, receipt: typeof v.receipt === "string" ? v.receipt : JSON.stringify(v.receipt) };
    }
    return { ok: true, receipt: body.text };
  }
  return { ok: true, receipt: body.text };
}

async function handleVerifyPost(request: Request, signer: Signer | null, log: RequestLog): Promise<Response> {
  const got = await receiptFromPost(request);
  if (!got.ok) {
    return wantsJson(request)
      ? jsonResponse({ error: "bad_request", message: got.message }, got.status)
      : html(renderVerifyForm({ problem: got.message }));
  }
  const v = await verifyReceiptBounded(got.receipt);
  log.verdict = v.verdict;
  const signed = signer ? await signVerdict(v, signer, BERNSTEIN_VERSION) : null;
  if (wantsJson(request)) return jsonResponse(verdictJson(v, signed), 200);
  return html(renderVerdict(got.receipt, v, { signed }));
}

async function handleVerifyGet(request: Request, url: URL, signer: Signer | null, log: RequestLog): Promise<Response> {
  const rest = url.pathname.slice("/verify".length).replace(/^\//, "");
  if (rest !== "" && !SHA256_HEX.test(rest)) return notFound();
  const expected = rest || undefined;
  const r = url.searchParams.get("r");
  if (r === null) return html(renderVerifyForm({ expected }));
  const receipt = base64UrlDecode(r);
  if (receipt === null) return html(renderVerifyForm({ expected, problem: "The `r` parameter is not base64url text." }));
  const v = await verifyReceiptBounded(receipt);
  log.verdict = v.verdict;
  const signed = signer ? await signVerdict(v, signer, BERNSTEIN_VERSION) : null;
  if (wantsJson(request)) return jsonResponse(verdictJson(v, signed), 200);
  return html(renderVerdict(receipt, v, { expected, signed }));
}

/**
 * One line per request, as JSON, to the Workers log: what was asked and
 * how it went — route, method, status, the JSON-RPC method, the tool, the
 * verdict, the MCP client's name/version, country and colo. Timing is not
 * measured here (the clock does not advance inside a request); the
 * invocation record the platform writes alongside carries wall and CPU time.
 * Never the address, never a header, never a byte of the body or receipt.
 */
export interface RequestLog {
  evt: "mcp.request";
  route: string;
  method: string;
  status: number;
  rpc?: string;
  tool?: string;
  verdict?: string;
  client?: string;
  client_version?: string;
  protocol?: string;
  country?: string;
  colo?: string;
}

function routeOf(pathname: string): string {
  if (pathname.startsWith("/verify/")) return "/verify/<sha256>";
  if (pathname.startsWith("/fonts/")) return "/fonts/*";
  return pathname.length > 64 ? pathname.slice(0, 64) + "…" : pathname;
}

async function route(request: Request, env: Env, log: RequestLog): Promise<Response> {

      const url = new URL(request.url);
      const { pathname } = url;
      const signer = await loadSigner(env.VERDICT_SIGNING_KEY);

      if (pathname === "/mcp") {
        if (request.method === "POST") {
          if (await overLimit(request, env)) return rateLimited();
          return handleMcpPost(request, signer, log);
        }
        // Stateless mode does not support a standalone GET/SSE stream.
        return methodNotAllowed(["POST"]);
      }

      if (pathname === KEYS_PATH) {
        if (request.method !== "GET") return methodNotAllowed(["GET"]);
        // The public half of the verdict-signing key, JWKS-shaped. Cacheable:
        // it only changes on rotation, and a stale copy fails closed (an
        // envelope signed by a newer key just does not verify against it).
        const response = jsonResponse({ keys: signer ? [signer.publicJwk] : [] }, 200);
        response.headers.set("cache-control", "public, max-age=3600");
        response.headers.set("Access-Control-Allow-Origin", "*");
        return response;
      }

      if (pathname === "/healthz") {
        if (request.method !== "GET") return methodNotAllowed(["GET"]);
        return jsonResponse({ ok: true, version: BERNSTEIN_VERSION }, 200);
      }

      if (pathname === "/") {
        if (request.method !== "GET") return methodNotAllowed(["GET"]);
        return html(await renderHome(BERNSTEIN_VERSION), "public, max-age=300");
      }

      if (pathname in FONTS) {
        if (request.method !== "GET") return methodNotAllowed(["GET"]);
        const response = withStandardHeaders(
          new Response(FONTS[pathname], { status: 200, headers: { "content-type": "font/woff2" } }),
        );
        response.headers.set("cache-control", "public, max-age=31536000, immutable");
        return response;
      }

      if (pathname === "/verify" || pathname.startsWith("/verify/")) {
        // Verdicts are pure functions of the pasted bytes; the only
        // cross-origin surface is reading one back (GET), never posting.
        let response: Response;
        if (request.method === "POST" && pathname === "/verify") {
          if (await overLimit(request, env)) return rateLimited();
          response = await handleVerifyPost(request, signer, log);
        } else if (request.method === "GET") {
          response = await handleVerifyGet(request, url, signer, log);
          response.headers.set("Access-Control-Allow-Origin", "*");
          response.headers.set("Access-Control-Allow-Methods", "GET");
        } else {
          return methodNotAllowed(pathname === "/verify" ? ["GET", "POST"] : ["GET"]);
        }
        return response;
      }

      return notFound();
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const cf = (request as Request & { cf?: { country?: string; colo?: string } }).cf;
    const log: RequestLog = {
      evt: "mcp.request",
      route: routeOf(new URL(request.url).pathname),
      method: request.method,
      status: 0,
      ...(cf?.country ? { country: cf.country } : {}),
      ...(cf?.colo ? { colo: cf.colo } : {}),
    };
    let response: Response;
    try {
      response = await route(request, env, log);
    } catch {
      response = jsonResponse({ error: "internal_error" }, 500);
    }
    log.status = response.status;
    console.log(JSON.stringify(log));
    return response;
  },
};
