/// <reference types="node" />
// Every golden vector in vectors/ was produced by the Python reference
// (scripts/gen_vectors.py against the pinned bernstein source). The TypeScript
// verifier must reproduce the verdict, the first failing check, every
// per-check outcome, and the canonical bytes the reference hashed.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { journalEventHash, journalPayloadHash, spineEntryHash } from "../src/verify/chains.js";
import { JsonNumber, parseJson, pyDumps, type JsonObject } from "../src/verify/pyjson.js";
import { verifyChain, verifyReceipt } from "../src/verify/receipt.js";

const VECTOR_DIR = join(process.cwd(), "vectors");

interface Vector {
  name: string;
  input: unknown;
  expected: {
    verdict: string;
    failing_check: string | null;
    checks: { name: string; outcome: string; detail: string }[];
    divergent_step: number | null;
  };
  canonical: {
    binding_block: Record<string, unknown>;
    binding_bytes_b64: string;
    binding_bytes_sha256: string;
    pae_sha256: string;
    journal_rows: { index: number; payload_hash: string; event_hash: string }[];
    spine_rows: { index: number; entry_hash: string }[];
    receipt_canonical_sha256: string;
    receipt_sha256: string;
  };
}

function loadVectors(): { file: string; text: string; vector: Vector }[] {
  return readdirSync(VECTOR_DIR)
    .filter((f: string) => f.endsWith(".json") && f !== "cpu_timing.json")
    .sort()
    .map((file: string) => {
      const text = readFileSync(join(VECTOR_DIR, file), "utf-8");
      return { file, text, vector: JSON.parse(text) as Vector };
    });
}

/** The receipt exactly as Python serialised it inside the vector file. */
function receiptText(text: string): string {
  // The vector file was written by json.dump(indent=2); slicing the parsed
  // object back out of the raw text keeps every number lexeme intact.
  const parsed = parseJson(text) as JsonObject;
  return pyDumps(parsed["input"]);
}

const vectors = loadVectors();

describe("golden vectors", () => {
  for (const { file, text, vector } of vectors) {
    describe(file, () => {
      const receipt = receiptText(text);

      it("reproduces the verdict and the first failing check", async () => {
        const result = await verifyReceipt(receipt);
        expect(result.verdict).toBe(vector.expected.verdict);
        expect(result.failing_check).toBe(vector.expected.failing_check);
        expect(result.divergent_step).toBe(vector.expected.divergent_step);
      });

      it("reproduces every per-check outcome and detail", async () => {
        const result = await verifyReceipt(receipt);
        expect(result.checks).toEqual(vector.expected.checks);
      });

      it("hashes the receipt exactly like the reference", async () => {
        const result = await verifyReceipt(receipt);
        expect(result.receipt_sha256).toBe(vector.canonical.receipt_sha256);
      });

      it("rebuilds the binding bytes and PAE byte-for-byte", async () => {
        const result = await verifyReceipt(receipt);
        expect(result.binding).not.toBeNull();
        expect(result.binding!.bytes_b64).toBe(vector.canonical.binding_bytes_b64);
        expect(result.binding!.pae_sha256).toBe(vector.canonical.pae_sha256);
        expect(JSON.parse(pyDumps(result.binding!.block))).toEqual(vector.canonical.binding_block);
      });

      it("recomputes every journal payload_hash and event_hash", () => {
        const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
        const events = (input["journal"] as JsonObject)["events"] as JsonObject[];
        const rows = vector.canonical.journal_rows;
        // Only rows before the tampered step are expected to recompute.
        const upto = vector.expected.divergent_step ?? events.length;
        let prev = "";
        for (let i = 0; i < upto; i++) {
          const payload = journalPayloadHash(events[i]);
          expect(payload, `payload_hash row ${i}`).toBe(rows[i].payload_hash);
          const event = journalEventHash(prev, events[i]["event"] as string, payload, i);
          expect(event, `event_hash row ${i}`).toBe(rows[i].event_hash);
          prev = event;
        }
      });

      it("recomputes every spine entry_hash", () => {
        const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
        const entries = (input["spine"] as JsonObject)["entries"] as JsonObject[];
        entries.forEach((entry, i) => {
          const v = entry["v"];
          const version = v instanceof JsonNumber ? v.value : null;
          const hash = spineEntryHash(entry, version === 2 ? "bernstein:lineage:v2" : "");
          expect(hash, `entry_hash row ${i}`).toBe(vector.canonical.spine_rows[i].entry_hash);
        });
      });

      it("verify_chain agrees with the receipt-level walk", () => {
        const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
        const events = (input["journal"] as JsonObject)["events"] as JsonObject[];
        const chain = verifyChain(events);
        expect(chain.kind).toBe("journal");
        const journalFailed = vector.expected.checks.some((c) => c.name === "journal_chain" && c.outcome === "fail");
        expect(chain.intact).toBe(!journalFailed);
        expect(chain.divergent_index).toBe(journalFailed ? vector.expected.divergent_step : null);
      });
    });
  }
});

describe("verifyReceipt on non-receipts", () => {
  it("rejects invalid JSON as unverifiable", async () => {
    const r = await verifyReceipt("{not json");
    expect(r.verdict).toBe("unverifiable");
    expect(r.failing_check).toBe("schema");
  });

  it("rejects a JSON object that is not a receipt", async () => {
    const r = await verifyReceipt('{"hello": "world"}');
    expect(r.verdict).toBe("unverifiable");
    expect(r.checks[0].detail).toBe("receipt.run_id missing");
  });

  it("accepts an already parsed object and notes the number ambiguity via the same verdict", async () => {
    const { text } = vectors.find((v) => v.file === "valid-short-with-audit-range.json")!;
    const obj = JSON.parse(text).input;
    const r = await verifyReceipt(obj);
    expect(r.verdict).toBe("valid");
  });
});

describe("verifyChain kinds", () => {
  it("walks spine entries and audit linkage", () => {
    const { text } = vectors.find((v) => v.file === "valid-short-with-audit-range.json")!;
    const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
    const spine = verifyChain((input["spine"] as JsonObject)["entries"] as JsonObject[]);
    expect(spine.kind).toBe("spine");
    expect(spine.intact).toBe(true);
    const audit = verifyChain((input["audit_range"] as JsonObject)["events"] as JsonObject[]);
    expect(audit.kind).toBe("audit_linkage");
    expect(audit.intact).toBe(true);
  });

  it("names a broken spine link", () => {
    const { text } = vectors.find((v) => v.file === "valid-short-with-audit-range.json")!;
    const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
    const entries = ((input["spine"] as JsonObject)["entries"] as JsonObject[]).map((e) => ({ ...e }));
    entries[1]["prev_hash"] = "sha256:" + "0".repeat(64);
    const r = verifyChain(entries);
    expect(r.intact).toBe(false);
    expect(r.divergent_index).toBe(1);
    expect(r.detail).toBe("spine entry 1: prev_hash break");
  });

  it("refuses rows it cannot classify", () => {
    const r = verifyChain([{ a: new JsonNumber("1") }]);
    expect(r.intact).toBe(false);
    expect(r.detail).toMatch(/cannot tell the row kind/);
  });
});
