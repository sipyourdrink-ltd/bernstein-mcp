// Plain-language narration of a verification result, for the
// explain_receipt tool and the /verify page. No new facts: everything
// here is read off the ReceiptVerification.

import type { ReceiptSummary, ReceiptVerification } from "./receipt.js";

const AGENT_NAMES: Record<string, string> = { "claude-code": "Claude Code", codex: "Codex CLI" };

/** One extra sentence for a session receipt (bernstein-attest); null when the receipt has no tool calls to report. */
function sessionLine(s: ReceiptSummary): string | null {
  if (s.tool_calls === null || !s.producer) return null;
  const agent = s.producer.match(/\(([^)]+)\)$/)?.[1] ?? "an agent";
  const label = s.producer.replace(/\s*\([^)]*\)$/, "");
  const n = s.tool_calls;
  const m = s.spine_entries;
  return `Session receipt from ${AGENT_NAMES[agent] ?? agent}, written by ${label}: ${n} tool call${n === 1 ? "" : "s"}, ${m} file${m === 1 ? "" : "s"} touched.`;
}

const WHAT_EACH_CHECK_MEANS: Record<string, string> = {
  schema: "the document has the shape of a bernstein run receipt",
  journal_chain: "every decision row hashes to the next one, from the first row to the last",
  journal_head: "the receipt's stated journal head and row count match the embedded rows",
  spine_chain: "every lineage entry (artifact, actor, step, model) hashes to the next one",
  spine_head: "the receipt's stated lineage head and entry count match the embedded entries",
  audit_range_head: "the embedded audit events hash to the stated head",
  audit_range_linkage: "each audit event links to the previous one's HMAC and the last one is the stated head",
  audit_range_hmac: "the HMAC values are authentic (needs the producing install's key)",
  subject_binding: "the signed subject equals the digest rebuilt from the recomputed heads",
  signature: "the Ed25519 signature verifies over that subject with the key the receipt carries",
};

export function explainReceipt(v: ReceiptVerification): string {
  const lines: string[] = [];
  const s = v.summary;

  if (v.verdict === "unverifiable") {
    const detail = v.checks[0]?.detail ?? "";
    lines.push(`This is not something the verifier can judge: ${detail}.`);
    lines.push("Nothing was recomputed. A bernstein run receipt is the JSON that `bernstein run-receipt` writes; pass that file's contents.");
    return lines.join("\n");
  }

  if (s) {
    const audit = s.audit_events === null ? "no audit range" : `${s.audit_events} audit event${s.audit_events === 1 ? "" : "s"}`;
    lines.push(
      `Run ${s.run_id} (schema ${s.schema_version}, ${s.hash_profile}) embeds ${s.journal_events} journal row${s.journal_events === 1 ? "" : "s"}, ` +
        `${s.spine_entries} lineage entr${s.spine_entries === 1 ? "y" : "ies"} and ${audit}.`,
    );
    const session = sessionLine(s);
    if (session) lines.push(session);
  }

  if (v.verdict === "valid") {
    lines.push("Every chain recomputes from the embedded rows, the signed subject equals the digest rebuilt from those recomputed heads, and the signature verifies.");
    lines.push("What that proves: the rows shown are exactly the rows that were signed; none was edited, reordered, dropped or appended after signing.");
    lines.push(
      `What it does not prove: that key ${s?.key_id || "(unnamed)"} belongs to who you think. The verifier trusts the key embedded in the receipt; ` +
        "compare it with the operator's published key before relying on the identity.",
    );
    const hmac = v.checks.find((c) => c.name === "audit_range_hmac");
    if (hmac?.outcome === "unverifiable") {
      lines.push("The audit range's HMAC values are keyed by the producing install and were not checked; their linkage and content hash were.");
    }
  } else {
    const failing = v.checks.find((c) => c.outcome === "fail");
    if (failing) {
      lines.push(`The first check to fail is ${failing.name} — ${WHAT_EACH_CHECK_MEANS[failing.name] ?? failing.name}.`);
      lines.push(`Detail: ${failing.detail}.`);
      if (v.divergent_step !== null) {
        lines.push(
          v.divergent_step === 0
            ? "Row 0 already fails: nothing before it can vouch for it."
            : `Rows 0–${v.divergent_step - 1} are intact; row ${v.divergent_step} is the first that no longer hashes to what its successor and the signature expect.`,
        );
      }
      if (failing.name === "signature" && v.checks.every((c) => c.name === "signature" || c.outcome !== "fail")) {
        lines.push("Every hash chain recomputes, so the rows are internally consistent; only the signature over them does not verify with the embedded key. Either the receipt was re-signed with a different key, the signature bytes were altered, or the receipt was assembled by hand.");
      }
    }
    const later = v.checks.filter((c) => c.outcome === "fail").slice(1).map((c) => c.name);
    if (later.length) lines.push(`Later checks that also fail: ${later.join(", ")} (expected once the chain has diverged).`);
    if (v.input_form === "object" && failing && failing.name !== "signature") {
      lines.push("The receipt was passed as a parsed object, which loses how numbers were spelled (1 vs 1.0, -0.0); if the file verifies locally, pass its contents as a string instead.");
    }
    lines.push("Treat the receipt as not attesting anything about this run.");
  }

  lines.push(`Receipt digest: sha256 ${v.receipt_sha256}.`);
  return lines.join("\n");
}
