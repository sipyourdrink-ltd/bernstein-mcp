/// <reference types="node" />
// A page receipt built by the seal must verify with the same verifier a run
// receipt does, and a single changed byte of the page must not.

import { afterEach, describe, expect, it, vi } from "vitest";
import seal, { type Env } from "../src/seal/index.js";
import { buildPageReceipt, importSealKey } from "../src/seal/receipt.js";
import { verifyReceipt } from "../src/verify/receipt.js";
import { base64ToBytes } from "../src/verify/receipt.js";

async function testKey(): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d });
}

const HTML = "<!doctype html><html><body><h1>hello</h1></body></html>";

describe("page receipt", () => {
  it("verifies as a valid run receipt bound to the page bytes", async () => {
    const key = (await importSealKey(await testKey()))!;
    const url = new URL("https://bernstein.run/blog/example");
    const page = await buildPageReceipt({ url, body: new TextEncoder().encode(HTML), now: 1_790_000_000, key });
    const v = await verifyReceipt(page.text);
    expect(v.verdict).toBe("valid");
    expect(v.receipt_sha256).toBe(page.receiptSha256);
    const entries = (page.receipt.spine as { entries: { content_hash: string; artifact_path: string }[] }).entries;
    expect(entries[0].content_hash).toBe("sha256:" + page.contentSha256);
    expect(entries[0].artifact_path).toBe("https://bernstein.run/blog/example");
  });

  it("a tampered signature or a tampered row is invalid", async () => {
    const key = (await importSealKey(await testKey()))!;
    const url = new URL("https://bernstein.run/blog/example");
    const page = await buildPageReceipt({ url, body: new TextEncoder().encode(HTML), now: 1_790_000_000, key });
    const tampered = page.text.replace('"path":"/blog/example"', '"path":"/blog/other"');
    expect(tampered).not.toBe(page.text);
    expect((await verifyReceipt(tampered)).verdict).toBe("invalid");
  });

  it("rejects a malformed key", async () => {
    expect(await importSealKey("{}")).toBeNull();
    expect(await importSealKey(undefined)).toBeNull();
  });
});

describe("seal worker", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function originFetch(html = HTML) {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (u.endsWith("/blog/example")) return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cf-cache-status": "HIT" } });
      return new Response("nope", { status: 404 });
    }) as unknown as typeof fetch;
  }

  it("adds Content-Digest, the receipt header and a verify link; body untouched", async () => {
    originFetch();
    const env: Env = { PAGE_SEAL_KEY: await testKey() };
    const res = await seal.fetch(new Request("https://bernstein.run/blog/example"), env);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(HTML);
    expect(res.headers.get("cf-cache-status")).toBe("HIT");
    expect(res.headers.get("content-digest")).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
    const link = res.headers.get("link")!;
    expect(link).toContain("https://mcp.bernstein.run/verify/");
    expect(link).toContain('rel="describedby"');
    const r = res.headers.get("bernstein-page-receipt")!;
    const receipt = new TextDecoder().decode(base64ToBytes(r, true));
    expect((await verifyReceipt(receipt)).verdict).toBe("valid");
  });

  it("passes the page through unchanged without a key", async () => {
    originFetch();
    const res = await seal.fetch(new Request("https://bernstein.run/blog/example"), {});
    expect(res.status).toBe(200);
    expect(res.headers.get("content-digest")).toBeNull();
    expect(res.headers.get("bernstein-page-receipt")).toBeNull();
  });

  it("GET /.well-known/page-receipt?p= sends the reader to the verifier with the receipt", async () => {
    originFetch();
    const env: Env = { PAGE_SEAL_KEY: await testKey() };
    const res = await seal.fetch(new Request("https://bernstein.run/.well-known/page-receipt?p=/blog/example"), env);
    expect(res.status).toBe(303);
    const loc = res.headers.get("location")!;
    expect(loc.startsWith("https://mcp.bernstein.run/verify/")).toBe(true);
    const r = new URL(loc).searchParams.get("r")!;
    const receipt = new TextDecoder().decode(base64ToBytes(r, true));
    const v = await verifyReceipt(receipt);
    expect(v.verdict).toBe("valid");
    expect(loc).toContain(`/verify/${v.receipt_sha256}?`);
    expect(new URL(loc).searchParams.get("r")!.length).toBeLessThan(6 * 1024);
  });

  it("page-receipt only accepts paths the seal runs on", async () => {
    originFetch();
    const env: Env = { PAGE_SEAL_KEY: await testKey() };
    for (const p of ["//evil.example/x", "/", "/about", "https://evil.example/blog/x"]) {
      const res = await seal.fetch(new Request(`https://bernstein.run/.well-known/page-receipt?p=${encodeURIComponent(p)}`), env);
      expect(res.status, p).toBe(302);
      expect(res.headers.get("location")).toBe("https://mcp.bernstein.run/verify");
    }
  });

  it("serves the public key", async () => {
    const env: Env = { PAGE_SEAL_KEY: await testKey() };
    const res = await seal.fetch(new Request("https://bernstein.run/.well-known/page-receipt/keys.json"), env);
    const body = (await res.json()) as { keys: { kty: string; crv: string; x: string; kid: string }[] };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].crv).toBe("Ed25519");
  });
});
