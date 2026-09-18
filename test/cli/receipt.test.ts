/// <reference types="node" />
import { describe, expect, it } from "vitest";
import { GENESIS, hashRow, type RowInput } from "../../cli/rows.js";
import { importKey } from "../../cli/keys.js";
import { buildReceipt } from "../../cli/receipt.js";
import { verifyReceipt } from "../../src/verify/receipt.js";
import { TEST_JWK } from "./fixtures/test-key.js";

async function sample() {
  let head = GENESIS;
  const rows: RowInput[] = [];
  for (const input of [
    { event: "session_started", agent: "claude-code", producer: "bernstein-attest 0.2.0", project: "demo", cwd_sha256: "c".repeat(64), ts: 1_700_000_000 },
    { event: "tool_call", tool: "Write", tool_use_id: "toolu_1", input_sha256: "a".repeat(64), output_sha256: "b".repeat(64), ok: true, path: "src/x.ts", ts: 1_700_000_001 },
    { event: "turn_ended", turn: 1, last_message_sha256: "d".repeat(64), ts: 1_700_000_002 },
  ]) {
    const r = hashRow(input, head); rows.push(r.row); head = r.head;
  }
  return buildReceipt({
    runId: "sess-1", rows, files: [{ path: "src/x.ts", stepId: "toolu_1", contentSha256: "e".repeat(64) }],
    agent: "claude-code", model: "unknown", key: await importKey(TEST_JWK), now: 1_700_000_003,
  });
}

describe("buildReceipt", () => {
  it("produces a receipt the verifier rates valid, with the expected summary", async () => {
    const sealed = await sample();
    const v = await verifyReceipt(sealed.text);
    expect(v.verdict).toBe("valid");
    expect(v.receipt_sha256).toBe(sealed.receiptSha256);
    expect(v.summary).toMatchObject({ run_id: "sess-1", schema_version: "1.1.0", hash_profile: "py-json-v1", journal_events: 3, spine_entries: 1, audit_events: null });
    expect(v.summary?.key_id).toBe(sealed.receipt.signing && (sealed.receipt.signing as any).public_key_jwk.kid);
    expect(sealed.receipt).toMatchObject({
      receipt_type: "https://bernstein.run/attestations/run-receipt/v1",
      producer: { name: "bernstein-attest", agent: "claude-code" },
      subject: { name: "session-receipt-sess-1" },
    });
    const spine = (sealed.receipt.spine as any).entries[0];
    expect(spine).toMatchObject({ v: 2, prev_hash: "", artifact_path: "src/x.ts", content_hash: "sha256:" + "e".repeat(64), actor: "claude-code", step_id: "toolu_1", model: "unknown", timestamp: 1_700_000_003 });
  });

  it("is byte-stable for the same input and key", async () => {
    const a = await sample(); const b = await sample();
    expect(a.text).toBe(b.text);
  });

  it("fails at the edited row when a journal row is tampered", async () => {
    const sealed = await sample();
    const doc = JSON.parse(sealed.text);
    doc.journal.events[1].path = "src/y.ts";
    const v = await verifyReceipt(JSON.stringify(doc));
    expect(v.verdict).toBe("invalid");
    expect(v.failing_check).toBe("journal_chain");
    expect(v.divergent_step).toBe(1);
  });

  it("fails the signature when the receipt is re-signed by another key", async () => {
    const sealed = await sample();
    const doc = JSON.parse(sealed.text);
    doc.signing.signature_b64 = Buffer.from(new Uint8Array(64)).toString("base64");
    const v = await verifyReceipt(JSON.stringify(doc));
    expect(v.failing_check).toBe("signature");
  });

  it("records a missing file as sha256:missing", async () => {
    let head = GENESIS;
    const r = hashRow({ event: "session_started", agent: "codex", producer: "p", project: "d", cwd_sha256: "c".repeat(64), ts: 1 }, head);
    const sealed = await buildReceipt({ runId: "s", rows: [r.row], files: [{ path: "gone.txt", stepId: "call_1", contentSha256: null }], agent: "codex", model: "gpt-5.5", key: await importKey(TEST_JWK), now: 2 });
    expect((sealed.receipt.spine as any).entries[0].content_hash).toBe("sha256:missing");
    expect((await verifyReceipt(sealed.text)).verdict).toBe("valid");
  });
});
