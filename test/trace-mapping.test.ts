/// <reference types="node" />
// explain_trace_mapping: how a bernstein run maps onto a TRACE v0.2 Trust Record.

import { describe, expect, it } from "vitest";
import { explainTraceMapping, journalFacts, MAPPING_CLAIMS } from "../src/verify/trace/mapping.js";
import { fromParsed, jcs, type JsonObject } from "../src/verify/pyjson.js";
import { sha256Hex } from "../src/verify/chains.js";
import { utf8 } from "../src/verify/pyjson.js";
import { receiptString } from "./helpers.js";

describe("explainTraceMapping", () => {
  it("lists every claim with no receipt, all values null", async () => {
    const out = await explainTraceMapping(undefined);
    expect(out.mapping.map((m) => m.claim)).toEqual([...MAPPING_CLAIMS]);
    expect(out.mapping.every((m) => m.value === null)).toBe(true);
    expect(out.verdict).toBeNull();
    expect(out.receipt_sha256).toBeNull();
    expect(out.markdown.split("\n")[0]).toBe("| claim | source | rule | value |");
    expect(out.markdown.split("\n")).toHaveLength(2 + MAPPING_CLAIMS.length);
    const byClaim = Object.fromEntries(out.mapping.map((m) => [m.claim, m]));
    expect(byClaim["eat_profile"].rule).toContain("tag:agentrust-io.com,2026:trace-v0.2");
    expect(byClaim["data_class"].rule).toContain("confidential");
    expect(byClaim["appraisal"].rule).toContain("https://bernstein.run/trace/verifier");
    expect(byClaim["runtime"].rule).toContain("0".repeat(64));
  });

  it("fills what the golden receipt can answer", async () => {
    const out = await explainTraceMapping(receiptString("valid-short-with-audit-range"));
    expect(out.verdict).toBe("valid");
    expect(out.receipt_sha256).toMatch(/^[0-9a-f]{64}$/);
    const byClaim = Object.fromEntries(out.mapping.map((m) => [m.claim, m.value]));
    expect(byClaim["subject"]).toBe("spiffe://bernstein.run/run/golden-short/exec/golden-short");
    expect(byClaim["iat"]).toBeNull();
    expect(byClaim["model"]).toBeNull();
    expect(byClaim["tool_transcript"]).toContain('"call_count":0');
    expect(out.markdown).toContain("spiffe://bernstein.run/run/golden-short/exec/golden-short");
  });

  it("reports the verdict of a broken receipt and still maps the subject", async () => {
    const out = await explainTraceMapping(receiptString("invalid-entry-tampered"));
    expect(out.verdict).toBe("invalid");
    const byClaim = Object.fromEntries(out.mapping.map((m) => [m.claim, m.value]));
    expect(byClaim["subject"]).toMatch(/^spiffe:\/\/bernstein\.run\/run\//);
  });

  it("is unverifiable for a non-receipt with all values null", async () => {
    const out = await explainTraceMapping("{}");
    expect(out.verdict).toBe("unverifiable");
    expect(out.mapping.every((m) => m.value === null)).toBe(true);
  });
});

describe("journalFacts", () => {
  const rows = [
    { event: "run_started", ts: 1700000000.2, run_id: "r1", model_id: "m-old", model_provider: "p", gate_config: { a: 1 } },
    { event: "tool_call", ts: 1700000001.5, index: 1, prev_hash: "x", payload_hash: "y", event_hash: "z", elapsed_s: 0.1, tool: "read", args: { path: "a" } },
    { event: "tool_call", ts: 1700000002.5, tool: "write", data_class: "restricted", model_id: "m-new", model_provider: "p", model_version: "v2" },
    { event: "run_completed", ts: 1700000002.5, gate_config: { a: 2 } },
  ].map((r) => fromParsed(r) as JsonObject);

  it("folds the last-wins fields and the tool_call payloads the way the emitter does", () => {
    const f = journalFacts(rows);
    expect(f.iat).toBe(1700000002); // Python round(): half to even
    expect(f.run_id).toBe("r1");
    expect(f.model).toEqual({ provider: "p", model_id: "m-new", version: "v2" });
    expect(f.data_class).toBe("restricted");
    expect(f.call_count).toBe(2);
    const payloads = [
      { tool: "read", args: { path: "a" } },
      { tool: "write", data_class: "restricted", model_id: "m-new", model_provider: "p", model_version: "v2" },
    ];
    expect(f.tool_transcript_hash).toBe("sha256:" + sha256Hex(utf8(jcs(fromParsed(payloads)))));
    expect(f.bundle_hash).toBe("sha256:" + sha256Hex(utf8(jcs(fromParsed({ a: 2 })))));
  });

  it("rounds a .5 timestamp half to even and reads event_type as a fallback", () => {
    const f = journalFacts([fromParsed({ event_type: "tool_call", ts: 1700000003.5 }) as JsonObject]);
    expect(f.iat).toBe(1700000004);
    expect(f.call_count).toBe(1);
    expect(f.model).toBeNull();
    expect(f.bundle_hash).toBeNull();
  });
});
