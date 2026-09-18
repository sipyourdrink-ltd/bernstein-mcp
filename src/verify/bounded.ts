// verifyReceipt behind the endpoint's limits. Row counts are read before
// anything is walked, so an oversized receipt costs a scan, not a chain
// walk. Both the MCP tools and /verify go through here.

import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "../limits.js";
import { verifyReceipt, type ReceiptVerification } from "./receipt.js";

export type ReceiptInput = string | Record<string, unknown>;

function count(haystack: string, needle: string): number {
  let n = 0;
  let i = -1;
  while ((i = haystack.indexOf(needle, i + 1)) !== -1) n++;
  return n;
}

/** Upper bound on the longest embedded chain, without parsing a string input. */
export function embeddedRowCount(receipt: ReceiptInput): number {
  if (typeof receipt !== "string") {
    const r = receipt as { journal?: { events?: unknown[] }; spine?: { entries?: unknown[] }; audit_range?: { events?: unknown[] } };
    return Math.max(r.journal?.events?.length ?? 0, r.spine?.entries?.length ?? 0, r.audit_range?.events?.length ?? 0);
  }
  // Every row of every chain carries one of these keys.
  return Math.max(count(receipt, '"event_hash"'), count(receipt, '"entry_hash"'), count(receipt, '"prev_hmac"'));
}

export function overLimits(detail: string): ReceiptVerification {
  return {
    verdict: "unverifiable",
    failing_check: "schema",
    divergent_step: null,
    checks: [{ name: "schema", outcome: "unverifiable", detail }],
    receipt_sha256: "",
    summary: null,
    binding: null,
    input_form: "string",
  };
}

export async function verifyReceiptBounded(receipt: ReceiptInput): Promise<ReceiptVerification> {
  const size = typeof receipt === "string" ? receipt.length : JSON.stringify(receipt).length;
  if (size > MAX_BODY_BYTES || embeddedRowCount(receipt) > MAX_CHAIN_ENTRIES) {
    return overLimits(
      `receipt exceeds this endpoint's limits (${MAX_BODY_BYTES} bytes, ${MAX_CHAIN_ENTRIES} rows per chain); run bernstein verify-receipt locally`,
    );
  }
  const v = await verifyReceipt(receipt);
  const s = v.summary;
  const longest = s ? Math.max(s.journal_events, s.spine_entries, s.audit_events ?? 0) : 0;
  if (longest > MAX_CHAIN_ENTRIES) {
    return overLimits(`embedded chain has ${longest} rows; this endpoint verifies up to ${MAX_CHAIN_ENTRIES} (run bernstein verify-receipt locally)`);
  }
  return v;
}
