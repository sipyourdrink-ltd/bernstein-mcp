/// <reference types="node" />
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verifyReceipt } from "../../src/verify/receipt.js";

const dir = join(process.cwd(), "vectors", "session");
const names = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

describe("session vectors", () => {
  it("has the three frozen vectors", () => {
    expect(names).toEqual(["session-segmented-2.json", "session-tampered.json", "session-valid.json"]);
  });
  for (const name of names) {
    it(`${name} verifies to its frozen expectation`, async () => {
      const vec = JSON.parse(readFileSync(join(dir, name), "utf8"));
      const v = await verifyReceipt(vec.input.receipt_text);
      expect({ verdict: v.verdict, failing_check: v.failing_check, divergent_step: v.divergent_step, receipt_sha256: v.receipt_sha256, summary: v.summary })
        .toEqual({ verdict: vec.expected.verdict, failing_check: vec.expected.failing_check, divergent_step: vec.expected.divergent_step, receipt_sha256: vec.expected.receipt_sha256, summary: vec.expected.summary });
      if (vec.expected.first_event) {
        expect(JSON.parse(vec.input.receipt_text).journal.events[0]).toMatchObject(vec.expected.first_event);
        expect(vec.expected.first_event.prev_receipt_sha256).toBe(vec.expected.segment_1_sha256);
      }
    });
  }
  it("session-valid carries no absolute path and no command text", () => {
    const text = JSON.parse(readFileSync(join(dir, "session-valid.json"), "utf8")).input.receipt_text;
    expect(text).not.toMatch(/\/(Users|home|tmp|private|work)\//);
    expect(text).not.toContain("git status");
    expect(text).not.toContain("npm test");
  });
});
