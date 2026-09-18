/// <reference types="node" />
// The MCP tools end to end through the Worker: JSON-RPC in, structured
// content out. Receipts come from the golden vectors.

import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.js";
import { MAX_CHAIN_ENTRIES } from "../src/limits.js";
import { receiptString, vectorText } from "./helpers.js";

const env = {} as Env;
const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined } as unknown as ExecutionContext;
const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };

async function call(tool: string, args: Record<string, unknown>) {
  const res = await worker.fetch(
    new Request("https://mcp.bernstein.run/mcp", {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }),
    }),
    env,
    ctx,
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result?: { structuredContent?: unknown; isError?: boolean; content?: { text: string }[] }; error?: unknown };
  if (body.error) throw new Error(JSON.stringify(body.error));
  if (body.result?.isError) throw new Error(body.result.content?.[0]?.text ?? "tool error");
  return body.result!.structuredContent as any;
}

describe("tools/list", () => {
  it("exposes every read-only tool", async () => {
    const res = await worker.fetch(
      new Request("https://mcp.bernstein.run/mcp", {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
      env,
      ctx,
    );
    const body = (await res.json()) as any;
    const names = body.result.tools.map((t: { name: string }) => t.name).sort();
    expect(names).toEqual(["explain_receipt", "get_preset", "list_adapters", "list_presets", "server_info", "verify_chain", "verify_receipt"]);
    for (const t of body.result.tools) expect(t.outputSchema, `${t.name} outputSchema`).toBeDefined();
  });
});

describe("verify_receipt", () => {
  it("verifies the short vector passed as a string", async () => {
    const out = await call("verify_receipt", { receipt: receiptString("valid-short-with-audit-range") });
    expect(out.verdict).toBe("valid");
    expect(out.failing_check).toBeNull();
    expect(out.summary.run_id).toBe("golden-short");
    expect(out.summary.audit_events).toBe(2);
    expect(out.receipt_sha256).toBe(JSON.parse(vectorText("valid-short-with-audit-range")).canonical.receipt_sha256);
    expect(out.verify_url).toBe(`https://mcp.bernstein.run/verify/${out.receipt_sha256}`);
  });

  it("verifies the same receipt passed as an object", async () => {
    const out = await call("verify_receipt", { receipt: JSON.parse(vectorText("valid-short-with-audit-range")).input });
    expect(out.verdict).toBe("valid");
  });

  it("names the tampered row", async () => {
    const out = await call("verify_receipt", { receipt: receiptString("invalid-entry-tampered") });
    expect(out.verdict).toBe("invalid");
    expect(out.failing_check).toBe("journal_chain");
    expect(out.divergent_step).toBe(50);
  });

  it("rejects a bad signature with intact chains", async () => {
    const out = await call("verify_receipt", { receipt: receiptString("invalid-bad-signature") });
    expect(out.verdict).toBe("invalid");
    expect(out.failing_check).toBe("signature");
    expect(out.checks.filter((c: { outcome: string }) => c.outcome === "fail").map((c: { name: string }) => c.name)).toEqual(["signature"]);
  });

  it("is unverifiable for a non-receipt", async () => {
    const out = await call("verify_receipt", { receipt: { hello: "world" } });
    expect(out.verdict).toBe("unverifiable");
    expect(out.verify_url).toBeNull();
  });

  it(`is unverifiable above ${MAX_CHAIN_ENTRIES} rows without walking the chain`, async () => {
    const receipt = JSON.parse(vectorText("valid-100-stress-canonicalization")).input;
    const last = receipt.journal.events[receipt.journal.events.length - 1];
    while (receipt.journal.events.length <= MAX_CHAIN_ENTRIES) receipt.journal.events.push({ ...last });
    const out = await call("verify_receipt", { receipt });
    expect(out.verdict).toBe("unverifiable");
    expect(out.checks[0].detail).toMatch(/exceeds this endpoint's limits/);
  });

  it("flags lost number spelling when an object input fails a chain check", async () => {
    // -0.0 in the stress vector parses to -0, which serialises as 0.
    const out = await call("verify_receipt", { receipt: JSON.parse(vectorText("valid-100-stress-canonicalization")).input });
    expect(out.verdict).toBe("invalid");
    expect(out.note).toMatch(/number spelling/);
    const exact = await call("verify_receipt", { receipt: receiptString("valid-100-stress-canonicalization") });
    expect(exact.verdict).toBe("valid");
    expect(exact.note).toBeNull();
  });
});

describe("explain_receipt", () => {
  it("narrates a valid receipt", async () => {
    const out = await call("explain_receipt", { receipt: receiptString("valid-short-with-audit-range") });
    expect(out.verdict).toBe("valid");
    expect(out.explanation).toContain("Run golden-short");
    expect(out.explanation).toContain("trusts the key embedded");
  });

  it("points at the first divergent row", async () => {
    const out = await call("explain_receipt", { receipt: receiptString("invalid-linkage-break") });
    expect(out.verdict).toBe("invalid");
    expect(out.explanation).toContain("row 10 is the first");
  });
});

describe("verify_chain", () => {
  it("detects journal rows and finds the break", async () => {
    const events = JSON.parse(vectorText("valid-short-with-audit-range")).input.journal.events;
    expect((await call("verify_chain", { entries: events })).intact).toBe(true);
    [events[1], events[2]] = [events[2], events[1]];
    const out = await call("verify_chain", { entries: events });
    expect(out.kind).toBe("journal");
    expect(out.intact).toBe(false);
    expect(out.divergent_index).toBe(1);
    expect(out.detail).toBe("step 1: prev_hash break");
  });

  it("detects spine entries", async () => {
    const entries = JSON.parse(vectorText("valid-short-with-audit-range")).input.spine.entries;
    const out = await call("verify_chain", { entries });
    expect(out.kind).toBe("spine");
    expect(out.intact).toBe(true);
    expect(out.head).toMatch(/^sha256:/);
  });

  it("honours an explicit kind", async () => {
    const events = JSON.parse(vectorText("valid-short-with-audit-range")).input.audit_range.events;
    const out = await call("verify_chain", { entries: events, kind: "audit_linkage" });
    expect(out.intact).toBe(true);
  });
});

describe("presets and adapters", () => {
  it("lists the four presets with their enabled switches", async () => {
    const out = await call("list_presets", {});
    expect(out.presets.map((p: { name: string }) => p.name)).toEqual(["development", "hipaa", "regulated", "standard"]);
    const hipaa = out.presets.find((p: { name: string }) => p.name === "hipaa");
    expect(hipaa.enabled).toContain("phi_detection");
  });

  it("returns every field of one preset", async () => {
    const out = await call("get_preset", { name: "regulated" });
    expect(out.config.audit_hmac_chain).toBe(true);
    expect(out.config.data_residency_region).toBe("eu");
  });

  it("rejects an unknown preset", async () => {
    await expect(call("get_preset", { name: "nope" })).rejects.toThrow();
  });

  it("lists adapters without host paths", async () => {
    const out = await call("list_adapters", {});
    expect(out.adapters.length).toBeGreaterThan(40);
    for (const a of out.adapters) {
      expect(a.module).toMatch(/^bernstein\.adapters\.[a-z0-9_]+$/);
      expect(JSON.stringify(a)).not.toMatch(/\/Users|\/home|\.py"/);
    }
  });
});
