// /verify — paste a receipt, read the ledger. Stateless: the page never
// stores a receipt. A verdict's address is /verify/<receipt digest>, so
// two people pasting the same bytes land on the same page; a receipt
// small enough to travel in the query string (?r=, base64url) renders
// the verdict straight from the link.

import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "../limits.js";
import type { ReceiptVerification } from "../verify/receipt.js";
import { renderExplanation, renderLedger } from "./ledger.js";
import { escapeHtml, page } from "./shell.js";

/** Receipts up to this many bytes get a self-contained share link. */
export const SHARE_LINK_MAX_BYTES = 6 * 1024;

export function base64UrlEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(text: string): string | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    return null;
  }
}

function form(opts: { expected?: string; prefill?: string; problem?: string }): string {
  const expected = opts.expected
    ? `<p class="note">this address names a receipt by its digest: <code>sha256:${escapeHtml(opts.expected)}</code>. paste the receipt and the page checks that the bytes match before it shows the verdict.</p>`
    : "";
  const problem = opts.problem ? `<p class="note" role="alert">${escapeHtml(opts.problem)}</p>` : "";
  return `
<form method="post" action="/verify" aria-labelledby="paste-label">
  ${expected}${problem}
  <label class="label" id="paste-label" for="receipt">paste the receipt json</label>
  <textarea id="receipt" name="receipt" spellcheck="false" autocomplete="off" placeholder='{"receipt_type": "https://bernstein.run/attestations/run-receipt/v1", "run_id": ...}' required>${escapeHtml(opts.prefill ?? "")}</textarea>
  <div class="formrow">
    <button class="btn" type="submit">verify</button>
    <span class="hint">up to ${(MAX_BODY_BYTES / 1024 / 1024).toFixed(0)} mb and ${MAX_CHAIN_ENTRIES} rows per chain · sent once, verified, discarded</span>
  </div>
</form>`;
}

function shareLink(receipt: string, v: ReceiptVerification): string {
  if (!v.receipt_sha256 || receipt.length > SHARE_LINK_MAX_BYTES) return "";
  return `<p class="hint" style="margin-top:12px">share: <a href="/verify/${v.receipt_sha256}?r=${base64UrlEncode(receipt)}">a link that carries the receipt itself</a> — anyone opening it sees this verdict recomputed, not remembered.</p>`;
}

export function renderVerifyForm(opts: { expected?: string; problem?: string } = {}): string {
  return page({
    title: "verify a run receipt",
    description: "Paste a bernstein run receipt; every chain is recomputed and the signature checked, nothing is stored.",
    current: "verify",
    body: `
<header class="pre"><span class="meta">stateless · keyless · nothing stored</span></header>
<h1><span>verify a <em>run receipt</em>.</span></h1>
<p class="lede">every hash chain the receipt carries is recomputed from the rows it embeds, the signed subject is rebuilt from those recomputed heads, and the ed25519 signature is checked with the key the receipt names. the verdict is a function of the bytes and nothing else.</p>
${form(opts)}`,
  });
}

export function renderVerdict(receipt: string, v: ReceiptVerification, opts: { expected?: string } = {}): string {
  const mismatch =
    opts.expected && v.receipt_sha256 && opts.expected !== v.receipt_sha256
      ? `<p class="note" role="alert">these bytes have digest <code>sha256:${escapeHtml(v.receipt_sha256)}</code>, not the <code>sha256:${escapeHtml(opts.expected)}</code> this address names. the verdict below is for what you pasted.</p>`
      : "";
  const canonical = v.receipt_sha256 ? `/verify/${v.receipt_sha256}` : "/verify";
  return page({
    title: `${v.verdict} · run receipt`,
    description: "Verification ledger for one bernstein run receipt.",
    current: "verify",
    body: `
<header class="pre"><span class="meta">verified just now · nothing stored</span></header>
<h1><span>${v.verdict === "valid" ? "every chain <em>recomputes</em>." : v.verdict === "invalid" ? "this receipt <em>does not hold</em>." : "not a receipt the verifier <em>can judge</em>."}</span></h1>
${mismatch}
<div class="grid">
  <section>
    ${renderLedger(v, { link: true })}
    ${shareLink(receipt, v)}
  </section>
  <aside>
    <p class="label">what this means</p>
    ${renderExplanation(v)}
    <p class="hint" style="margin-top:22px"><a href="${canonical}">this verdict's address</a> is the receipt's own digest. <a href="/verify">verify another →</a></p>
  </aside>
</div>`,
  });
}

/** Result the JSON variant of POST /verify returns. */
export function verdictJson(v: ReceiptVerification): Record<string, unknown> {
  return {
    verdict: v.verdict,
    failing_check: v.failing_check,
    divergent_step: v.divergent_step,
    receipt_sha256: v.receipt_sha256,
    checks: v.checks,
    summary: v.summary,
    verify_url: v.receipt_sha256 ? `https://mcp.bernstein.run/verify/${v.receipt_sha256}` : null,
  };
}
