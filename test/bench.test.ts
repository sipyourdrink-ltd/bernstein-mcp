/// <reference types="node" />
// Cost ceiling: the largest receipt the endpoint accepts must verify well
// inside a Worker's CPU budget. Measured with the 10000-row vector cut to
// MAX_CHAIN_ENTRIES journal rows (the chain is walked, the signature will
// not match the truncated head — the walk is what we time).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MAX_CHAIN_ENTRIES } from "../src/limits.js";
import { walkJournal } from "../src/verify/chains.js";
import { parseJson, type JsonObject } from "../src/verify/pyjson.js";
import { verifyReceipt } from "../src/verify/receipt.js";

describe("verification cost", () => {
  it(`walks ${MAX_CHAIN_ENTRIES} journal rows in under 50 ms`, async () => {
    const text = readFileSync(join(process.cwd(), "vectors", "valid-10000.json"), "utf-8");
    const input = (parseJson(text) as JsonObject)["input"] as JsonObject;
    const events = ((input["journal"] as JsonObject)["events"] as JsonObject[]).slice(0, MAX_CHAIN_ENTRIES);
    walkJournal(events); // warm-up
    const t0 = performance.now();
    const walk = walkJournal(events);
    const walkMs = performance.now() - t0;
    expect(walk.divergentIndex).toBeNull();

    const t1 = performance.now();
    await verifyReceipt(text.slice(text.indexOf('"input": ') + 9, text.indexOf('\n  "expected"')).replace(/,\s*$/, ""));
    const fullMs = performance.now() - t1;
    console.log(`walk ${MAX_CHAIN_ENTRIES} rows: ${walkMs.toFixed(1)} ms; full 10000-row receipt (parse+verify): ${fullMs.toFixed(1)} ms`);
    expect(walkMs).toBeLessThan(50);
  });
});
