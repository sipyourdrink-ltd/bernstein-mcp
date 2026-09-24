// bernstein-page-seal: a Worker on the public site's HTML routes. It passes
// every request to the origin untouched and, for a 200 HTML page, hashes the
// exact bytes the reader receives, signs a page receipt with the seal key and
// hands both back in headers. GET /.well-known/page-receipt?p=<path> builds
// the receipt for a page and sends the reader to the verifier with it.
//
// Nothing about the reader is read or kept: no address, no referrer, no
// user agent. The receipt names the page, its bytes and the time — that is
// all. Any failure (no key, body too large, origin error) passes the origin
// response through unchanged; the seal never breaks the page.
import { base64Url, buildPageReceipt, importSealKey, SEAL_VERSION, type SealKey } from "./receipt.js";

export interface Env {
  PAGE_SEAL_KEY?: string;
  VERIFIER_ORIGIN?: string;
}

const MAX_SEAL_BYTES = 2 * 1024 * 1024;
const RECEIPT_PATH = "/.well-known/page-receipt";
const KEYS_PATH = "/.well-known/page-receipt/keys.json";
const DEFAULT_VERIFIER = "https://mcp.bernstein.run";

let cached: { secret: string; key: Promise<SealKey | null> } | null = null;
function sealKey(env: Env): Promise<SealKey | null> {
  const secret = env.PAGE_SEAL_KEY ?? "";
  if (!cached || cached.secret !== secret) cached = { secret, key: importSealKey(secret) };
  return cached.key;
}

function verifier(env: Env): string {
  return (env.VERIFIER_ORIGIN ?? DEFAULT_VERIFIER).replace(/\/$/, "");
}

function isHtml(response: Response): boolean {
  return response.status === 200 && (response.headers.get("content-type") ?? "").startsWith("text/html");
}

/** Only same-origin paths the seal runs on; anything else → null. */
function pagePath(raw: string | null): string | null {
  if (!raw || !raw.startsWith("/blog/") || raw.includes("\\")) return null;
  return raw.split(/[?#]/)[0];
}

function verifyLink(env: Env, text: string, receiptSha256: string): string {
  return `${verifier(env)}/verify/${receiptSha256}?r=${base64Url(text)}`;
}

async function sealHtml(request: Request, env: Env): Promise<Response> {
  const origin = await fetch(request);
  if (!isHtml(origin)) return origin;
  const length = Number(origin.headers.get("content-length") ?? "0");
  if (length > MAX_SEAL_BYTES) return origin;
  const key = await sealKey(env);
  if (!key) return origin;

  const body = new Uint8Array(await origin.arrayBuffer());
  if (body.length > MAX_SEAL_BYTES) return new Response(body, origin);
  const url = new URL(request.url);
  const page = await buildPageReceipt({ url, body, now: Math.floor(Date.now() / 1000), key });

  const headers = new Headers(origin.headers);
  headers.set("Content-Digest", `sha-256=:${hexToBase64(page.contentSha256)}:`);
  headers.set("Bernstein-Page-Receipt", base64Url(page.text));
  headers.append("Link", `<${verifyLink(env, page.text, page.receiptSha256)}>; rel="describedby"; type="text/html"; title="page receipt"`);
  headers.set("Bernstein-Page-Seal", `${key.keyId}; v=${SEAL_VERSION}`);
  return new Response(body, { status: origin.status, statusText: origin.statusText, headers });
}

async function receiptRedirect(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = pagePath(url.searchParams.get("p"));
  const key = await sealKey(env);
  if (!path || !key) return Response.redirect(`${verifier(env)}/verify`, 302);
  const pageUrl = new URL(path, url.origin);
  const origin = await fetch(new Request(pageUrl.toString(), { headers: { accept: "text/html" } }));
  if (!isHtml(origin)) return Response.redirect(`${verifier(env)}/verify`, 302);
  const body = new Uint8Array(await origin.arrayBuffer());
  if (body.length > MAX_SEAL_BYTES) return Response.redirect(`${verifier(env)}/verify`, 302);
  const page = await buildPageReceipt({ url: pageUrl, body, now: Math.floor(Date.now() / 1000), key });
  const wantsJson = (request.headers.get("accept") ?? "").includes("application/json");
  if (wantsJson) {
    return new Response(page.text + "\n", {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
    });
  }
  return new Response(null, { status: 303, headers: { location: verifyLink(env, page.text, page.receiptSha256), "cache-control": "no-store" } });
}

async function keys(env: Env): Promise<Response> {
  const key = await sealKey(env);
  const body = { keys: key ? [{ ...key.publicJwk, use: "sig", key_id: key.keyId }] : [], producer: "bernstein-page-seal", version: SEAL_VERSION };
  return new Response(JSON.stringify(body, null, 1) + "\n", {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=3600", "x-content-type-options": "nosniff" },
  });
}

function hexToBase64(hex: string): string {
  const bytes = new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === KEYS_PATH) return request.method === "GET" || request.method === "HEAD" ? keys(env) : fetch(request);
    if (pathname === RECEIPT_PATH) return request.method === "GET" ? receiptRedirect(request, env) : fetch(request);
    if (request.method !== "GET") return fetch(request);
    try {
      return await sealHtml(request, env);
    } catch {
      return fetch(request);
    }
  },
};
