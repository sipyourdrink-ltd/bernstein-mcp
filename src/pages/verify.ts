// /verify — paste a receipt, read the ledger. Stateless: the page never
// stores a receipt. A verdict's address is /verify/<receipt digest>, so
// two people pasting the same bytes land on the same page; a receipt
// small enough to travel in the query string (?r=, base64url) renders
// the verdict straight from the link.

import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "../limits.js";
import type { ReceiptVerification } from "../verify/receipt.js";
import { KEYS_PATH, type SignedVerdict } from "../verify/attest.js";
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
  // The digest travels with the post so the verdict page can say whether the bytes match it.
  const expectedField = opts.expected ? `<input type="hidden" name="expected" value="${escapeHtml(opts.expected)}">` : "";
  const problem = opts.problem ? `<p class="note" role="alert">${escapeHtml(opts.problem)}</p>` : "";
  return `
<form method="post" action="/verify" aria-labelledby="paste-label">
  ${expected}${problem}${expectedField}
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

export function renderVerifyForm(opts: { expected?: string; problem?: string; from?: string } = {}): string {
  const from = opts.from ? new URL(opts.from) : null;
  const fetching = from
    ? `<p class="note" id="from-note" data-from="${escapeHtml(from.toString())}">loading the receipt from <code>${escapeHtml(from.host)}</code>… the bytes are fetched by your browser and verified once; nothing is stored.</p>`
    : "";
  return page({
    title: "verify a run receipt",
    description: "Paste a bernstein run receipt; every chain is recomputed and the signature checked, nothing is stored.",
    current: "verify",
    body: `
<header class="pre"><span class="meta">stateless · keyless · nothing stored</span></header>
<h1><span>verify a <em>run receipt</em>.</span></h1>
<p class="lede">every hash chain the receipt carries is recomputed from the rows it embeds, the signed subject is rebuilt from those recomputed heads, and the ed25519 signature is checked with the key the receipt names. the verdict is a function of the bytes and nothing else.</p>
${fetching}${form(opts)}`,
    script: from ? FROM_SCRIPT : undefined,
  });
}

// Runs in the visitor's browser, never in the Worker. Reads the URL from the
// note's data attribute, pulls the bytes with the browser's own client,
// puts them in the textarea and submits the existing form. Any failure
// leaves the plain paste form behind with a one-line reason.
const FROM_SCRIPT = `(function(){
var note=document.getElementById("from-note");var ta=document.getElementById("receipt");var form=ta&&ta.form;
if(!note||!ta||!form)return;var url=note.getAttribute("data-from");var get=globalThis.fetch;
function fail(why){note.textContent="could not load the receipt from "+url+": "+why+". paste it instead.";}
get(url,{mode:"cors",credentials:"omit",redirect:"follow"}).then(function(r){
if(!r.ok)throw new Error("http "+r.status);var len=r.headers.get("content-length");
if(len&&Number(len)>${MAX_BODY_BYTES})throw new Error("larger than ${MAX_BODY_BYTES} bytes");return r.text();
}).then(function(t){if(t.length>${MAX_BODY_BYTES})throw new Error("larger than ${MAX_BODY_BYTES} bytes");ta.value=t;form.requestSubmit();
}).catch(function(e){fail(e&&e.message?e.message:String(e));});})();`;

function signedBlock(signed: SignedVerdict | null): string {
  if (!signed) return "";
  const kid = signed.signatures[0]?.keyid ?? "";
  const envelope = JSON.stringify(signed, null, 2);
  return `
    <details class="signed">
      <summary><span class="label" style="display:inline">signed verdict</span> <span class="hint">· key ${escapeHtml(kid.slice(0, 12))}…</span></summary>
      <p class="hint" style="margin:10px 0 8px">a dsse envelope over this ledger, signed by this verifier's ed25519 key. keep it with the receipt; check it offline against <a href="${KEYS_PATH}">${KEYS_PATH}</a>.</p>
      <pre class="envelope"><code>${escapeHtml(envelope)}</code></pre>
    </details>`;
}

const PAGE_SEAL_KEYS = "https://bernstein.run/.well-known/page-receipt/keys.json";

/** A page receipt (producer bernstein-page-seal): the page it names and when it was served, or null. */
export function pageOf(receipt: string, v: ReceiptVerification): { url: string; servedAt: number; bytes: number } | null {
  if (!v.summary?.producer?.startsWith("bernstein-page-seal")) return null;
  try {
    const r = JSON.parse(receipt) as { journal?: { events?: { host?: unknown; path?: unknown; served_at?: unknown; bytes?: unknown }[] } };
    const e = r.journal?.events?.[0];
    if (!e || typeof e.host !== "string" || typeof e.path !== "string" || typeof e.served_at !== "number" || typeof e.bytes !== "number") return null;
    return { url: `https://${e.host}${e.path}`, servedAt: e.served_at, bytes: e.bytes };
  } catch {
    return null;
  }
}

function utc(epoch: number): string {
  return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function pageExplanation(p: { url: string; servedAt: number; bytes: number }, v: ReceiptVerification): string {
  const lines =
    v.verdict === "valid"
      ? [
          `This is a receipt for one web page: <a href="${escapeHtml(p.url)}">${escapeHtml(p.url.replace(/^https:\/\//, ""))}</a>, as served at ${utc(p.servedAt)} (${p.bytes.toLocaleString("en")} bytes of HTML).`,
          "What it proves: the page's sha256 is recorded in the receipt, the receipt is signed, and not one byte of it has changed since it was signed.",
          `Whose key: <code>${escapeHtml(v.summary?.key_id ?? "")}</code>. Compare it with the site's published key at <a href="${PAGE_SEAL_KEYS}">bernstein.run/.well-known/page-receipt/keys.json</a>.`,
          "What it does not prove: that the page is correct — only that it is exactly the page that was signed. Nothing about you was read or stored to make this.",
        ]
      : ["This receipt names a web page, but it does not verify: something in it changed after it was signed, so it proves nothing about that page."];
  return `<ul class="explain">${lines.map((l) => `<li>${l}</li>`).join("")}</ul>`;
}

export function renderVerdict(receipt: string, v: ReceiptVerification, opts: { expected?: string; signed?: SignedVerdict | null } = {}): string {
  const pg = pageOf(receipt, v);
  const mismatch =
    opts.expected && v.receipt_sha256 && opts.expected !== v.receipt_sha256
      ? `<p class="note" role="alert">these bytes have digest <code>sha256:${escapeHtml(v.receipt_sha256)}</code>, not the <code>sha256:${escapeHtml(opts.expected)}</code> this address names. the verdict below is for what you pasted.</p>`
      : "";
  const canonical = v.receipt_sha256 ? `/verify/${v.receipt_sha256}` : "/verify";
  return page({
    title: `${v.verdict} · ${pg ? "page receipt" : "run receipt"}`,
    description: "Verification ledger for one bernstein run receipt.",
    current: "verify",
    body: `
<header class="pre"><span class="meta">verified just now · nothing stored</span></header>
<h1><span>${pg && v.verdict === "valid" ? "this page is <em>the one that was signed</em>." : v.verdict === "valid" ? "every chain <em>recomputes</em>." : v.verdict === "invalid" ? "this receipt <em>does not hold</em>." : "not a receipt the verifier <em>can judge</em>."}</span></h1>
${mismatch}
<div class="grid">
  <section>
    ${renderLedger(v, { link: true, runLabel: pg ? `page ${pg.url.replace(/^https:\/\//, "")} · served ${utc(pg.servedAt)}` : undefined })}
    ${shareLink(receipt, v)}
    ${signedBlock(opts.signed ?? null)}
  </section>
  <aside>
    <p class="label">what this means</p>
    ${pg ? pageExplanation(pg, v) : renderExplanation(v)}
    <p class="hint" style="margin-top:22px"><a href="${canonical}">this verdict's address</a> is the receipt's own digest. <a href="/verify">verify another →</a></p>
  </aside>
</div>`,
  });
}

/** Result the JSON variant of POST /verify returns. */
export function verdictJson(v: ReceiptVerification, signed: SignedVerdict | null = null): Record<string, unknown> {
  return {
    verdict: v.verdict,
    failing_check: v.failing_check,
    divergent_step: v.divergent_step,
    receipt_sha256: v.receipt_sha256,
    checks: v.checks,
    summary: v.summary,
    verify_url: v.receipt_sha256 ? `https://mcp.bernstein.run/verify/${v.receipt_sha256}` : null,
    signed_verdict: signed,
    keys_url: signed ? `https://mcp.bernstein.run${KEYS_PATH}` : null,
  };
}
