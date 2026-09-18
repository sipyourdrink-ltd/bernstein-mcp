// The check ledger: one verification rendered as ten rows, the same
// order the verifier runs them. Used by the home page (golden receipt)
// and the verify page (the visitor's receipt).

import { explainReceipt } from "../verify/explain.js";
import type { ReceiptVerification } from "../verify/receipt.js";
import { escapeHtml } from "./shell.js";

const GLYPH: Record<string, string> = { ok: "✓", fail: "✗", unverifiable: "?", skipped: "–" };

export function renderLedger(v: ReceiptVerification, opts: { runLabel?: string; link?: boolean } = {}): string {
  const s = v.summary;
  const run = opts.runLabel ?? (s ? `run ${s.run_id} · ${s.journal_events} journal · ${s.spine_entries} spine${s.audit_events === null ? "" : ` · ${s.audit_events} audit`}` : "not a run receipt");
  const rows = v.checks
    .map(
      (c, i) =>
        `<li class="${c.outcome}" style="--i:${i}"><span class="g" aria-hidden="true">${GLYPH[c.outcome]}</span><span class="n">${escapeHtml(c.name)}<span class="sr"> ${c.outcome}</span></span><span class="d" title="${escapeHtml(c.detail)}">${escapeHtml(c.detail)}</span></li>`,
    )
    .join("\n");
  const digest = v.receipt_sha256
    ? opts.link
      ? `digest <a href="/verify/${v.receipt_sha256}">sha256:${v.receipt_sha256}</a>`
      : `digest sha256:${v.receipt_sha256}`
    : "no digest: the input is not a receipt";
  return `<div class="ledger" role="group" aria-label="verification ledger">
  <div class="ledger-head"><span class="run">${escapeHtml(run)}</span><span class="verdict ${v.verdict}">${v.verdict}</span></div>
  <ol>
${rows}
  </ol>
  <div class="ledger-foot">${digest}</div>
</div>`;
}

export function renderExplanation(v: ReceiptVerification): string {
  return `<ul class="explain">${explainReceipt(v)
    .split("\n")
    .map((line) => `<li>${escapeHtml(line)}</li>`)
    .join("")}</ul>`;
}
