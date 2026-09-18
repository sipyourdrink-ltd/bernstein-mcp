/// <reference types="node" />
// The two HTML surfaces and the form/JSON variants of /verify.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.js";
import { base64UrlEncode } from "../src/pages/verify.js";
import { receiptString } from "./helpers.js";

const env = {} as Env;
const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined } as unknown as ExecutionContext;
const req = (path: string, init?: RequestInit) => worker.fetch(new Request(`https://mcp.bernstein.run${path}`, init), env, ctx);

const vector = JSON.parse(readFileSync(join(process.cwd(), "vectors", "valid-short-with-audit-range.json"), "utf-8"));
const receipt = JSON.stringify(vector.input);
const tampered = receiptString("invalid-truncated");

describe("GET /", () => {
  it("renders the install line, the tools and a verified ledger", async () => {
    const res = await req("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    const body = await res.text();
    expect(body).toContain("claude mcp add --transport http bernstein https://mcp.bernstein.run/mcp");
    for (const tool of ["verify_receipt", "explain_receipt", "verify_chain", "verify_trace_record", "verify_delegation_chain", "explain_trace_mapping", "list_presets", "get_preset", "list_adapters", "server_info"]) {
      expect(body).toContain(`<td>${tool}</td>`);
    }
    expect(body).toContain('class="verdict valid"');
    expect(body).toContain("run golden-short");
    expect(body).not.toMatch(/https?:\/\/(fonts\.googleapis|fonts\.gstatic|cdn\.)/);
  });
});

describe("GET /fonts/*", () => {
  it("serves the bundled woff2 with immutable caching", async () => {
    const res = await req("/fonts/fraunces-latin.woff2");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("font/woff2");
    expect(res.headers.get("cache-control")).toContain("immutable");
    const bytes = new Uint8Array(await res.arrayBuffer());
    expect(String.fromCharCode(...bytes.slice(0, 4))).toBe("wOF2");
  });
});

describe("/verify", () => {
  it("GET renders the paste form", async () => {
    const res = await req("/verify");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(await res.text()).toContain('<textarea id="receipt"');
  });

  it("GET /verify/<digest> names the expected receipt", async () => {
    const digest = vector.canonical.receipt_sha256;
    const res = await req(`/verify/${digest}`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(`sha256:${digest}`);
  });

  it("GET /verify/<not a digest> is 404", async () => {
    expect((await req("/verify/hello")).status).toBe(404);
  });

  it("POST form-encoded renders the ledger", async () => {
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ receipt }).toString(),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    const body = await res.text();
    expect(body).toContain('class="verdict valid"');
    expect(body).toContain(`/verify/${vector.canonical.receipt_sha256}`);
    expect(body).toContain("share:");
  });

  it("POST JSON with accept: application/json returns the verdict as JSON", async () => {
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: receipt,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.verdict).toBe("valid");
    expect(body.receipt_sha256).toBe(vector.canonical.receipt_sha256);
    expect(body.verify_url).toBe(`https://mcp.bernstein.run/verify/${vector.canonical.receipt_sha256}`);
  });

  it("POST {receipt: ...} envelope is accepted too", async () => {
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ receipt: tampered }),
    });
    const body = (await res.json()) as any;
    expect(body.verdict).toBe("invalid");
    expect(body.failing_check).toBe("journal_head");
  });

  it("GET /verify/<digest>?r= renders the verdict from the link alone", async () => {
    const digest = vector.canonical.receipt_sha256;
    const res = await req(`/verify/${digest}?r=${base64UrlEncode(receipt)}`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('class="verdict valid"');
    expect(body).not.toContain("not the");
  });

  it("flags a digest mismatch between the address and the pasted bytes", async () => {
    const res = await req(`/verify/${"0".repeat(64)}?r=${base64UrlEncode(receipt)}`);
    expect(await res.text()).toContain("not the <code>sha256:" + "0".repeat(64));
  });

  it("GET /verify/<digest> carries the digest into the form as a hidden field", async () => {
    const digest = vector.canonical.receipt_sha256;
    const body = await (await req(`/verify/${digest}`)).text();
    expect(body).toContain(`<input type="hidden" name="expected" value="${digest}">`);
    expect(await (await req("/verify")).text()).not.toContain('name="expected"');
  });

  it("POST with an expected digest binds the verdict to the address", async () => {
    const post = (expected: string) => req("/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ receipt, expected }).toString(),
    });
    const wrong = await post("0".repeat(64));
    expect(wrong.status).toBe(200);
    expect(await wrong.text()).toContain("not the <code>sha256:" + "0".repeat(64));
    const right = await post(vector.canonical.receipt_sha256);
    expect(right.status).toBe(200);
    expect(await right.text()).not.toContain("not the");
    // A value that is not a digest is ignored rather than echoed.
    const junk = await post("<script>");
    expect(junk.status).toBe(200);
    const junkBody = await junk.text();
    expect(junkBody).not.toContain("not the");
    expect(junkBody).not.toContain("&lt;script&gt;");
  });

  it("POST of garbage renders an unverifiable ledger, no stack trace", async () => {
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ receipt: "{nope" }).toString(),
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('class="verdict unverifiable"');
    expect(body).not.toMatch(/at .*\.ts:\d+/);
  });

  it("escapes what it reflects", async () => {
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ receipt: '{"run_id":"x","receipt_type":"<script>alert(1)</script>"}' }).toString(),
    });
    const body = await res.text();
    expect(body).not.toContain("<script>alert(1)</script>");
    expect(body).toContain("&lt;script&gt;");
  });

  it("caps the rows a pasted receipt may carry", async () => {
    const big = JSON.parse(receipt);
    const last = big.journal.events[big.journal.events.length - 1];
    while (big.journal.events.length <= 2000) big.journal.events.push({ ...last });
    const res = await req("/verify", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(big),
    });
    const body = (await res.json()) as any;
    expect(body.verdict).toBe("unverifiable");
    expect(body.checks[0].detail).toMatch(/exceeds this endpoint's limits/);
  });

  it("sets a referrer policy and a CSP on every HTML page", async () => {
    for (const path of ["/", "/verify", `/verify/${vector.canonical.receipt_sha256}?r=${base64UrlEncode(receipt)}`]) {
      const res = await req(path);
      expect(res.headers.get("referrer-policy"), path).toBe("no-referrer");
      expect(res.headers.get("content-security-policy"), path).toContain("default-src 'none'");
    }
  });

  it("PUT is 405", async () => {
    expect((await req("/verify", { method: "PUT" })).status).toBe(405);
  });
});

describe("GET /verify?from=", () => {
  const from = "https://raw.githubusercontent.com/o/r/main/.bernstein/receipts/s.json";
  it("renders a page that fetches the receipt in the browser and submits it", async () => {
    const res = await req(`/verify/${"ab".repeat(32)}?from=${encodeURIComponent(from)}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toContain("connect-src https:");
    const body = await res.text();
    expect(body).toContain('data-from="' + from + '"');
    expect(body).toContain("raw.githubusercontent.com");
    expect(body).toContain("<script>");
    expect(body).toContain("requestSubmit");
    expect(body).not.toContain("innerHTML");
    expect(body).toContain(`sha256:${"ab".repeat(32)}`);
  });
  it("refuses anything but https and keeps the plain form", async () => {
    for (const bad of ["http://x/r.json", "ftp://x", "javascript:alert(1)", "not a url"]) {
      const res = await req(`/verify?from=${encodeURIComponent(bad)}`);
      const body = await res.text();
      expect(res.status).toBe(200);
      expect(body).toContain("must be an https URL");
      expect(body).not.toContain("<script>");
      expect(res.headers.get("content-security-policy")).not.toContain("connect-src");
    }
  });
  it("the plain form still carries no script and no connect-src", async () => {
    const res = await req("/verify");
    expect(res.headers.get("content-security-policy")).not.toContain("connect-src");
    expect(await res.text()).not.toContain("<script>");
  });
});
