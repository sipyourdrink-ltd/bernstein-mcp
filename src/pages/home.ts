// GET / — install line, the tools, and one real verification of the
// golden receipt so the page shows what a verdict looks like.

import golden from "../../vectors/valid-short-with-audit-range.json";
import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "../limits.js";
import { verifyReceipt } from "../verify/receipt.js";
import { renderLedger } from "./ledger.js";
import { escapeHtml, page } from "./shell.js";

const INSTALL = {
  claude: "claude mcp add --transport http bernstein https://mcp.bernstein.run/mcp",
  json: '{ "mcpServers": { "bernstein": { "type": "http", "url": "https://mcp.bernstein.run/mcp" } } }',
  curl: `curl -s https://mcp.bernstein.run/mcp -H 'content-type: application/json' -H 'accept: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`,
};

const TOOLS: [string, string][] = [
  ["verify_receipt", "recompute every chain a run receipt embeds, rebuild the signed subject, check the signature. verdict + one line per check."],
  ["explain_receipt", "the same verification, narrated: what the run recorded, where it diverges, what the result does and does not prove."],
  ["verify_chain", "walk journal rows, lineage entries or audit events on their own and name the first broken link."],
  ["verify_trace_record", "TRACE v0.2 conformance checks on one Trust Record: schema, signature with the key it carries, and every profile rule. stateless, no account."],
  ["verify_delegation_chain", "walk a set of Trust Records from the leaf to the root and classify the delegation chain: verified, provenance-invalid, authorization-invalid or unverifiable."],
  ["explain_trace_mapping", "how a bernstein run maps onto a TRACE v0.2 Trust Record, claim by claim; pass a receipt to fill in what its journal answers."],
  ["list_presets", "the compliance presets this release ships and the switches each one turns on."],
  ["get_preset", "every field of one preset as bernstein resolves it."],
  ["list_adapters", "the agent adapters bundled with this release."],
  ["server_info", "version and request limits."],
];

const SCRIPT = `
(function(){
  var cmds=${JSON.stringify(INSTALL)};
  var tabs=document.querySelectorAll('.tab'),cmd=document.getElementById('cmd'),copy=document.getElementById('copy');
  var current='claude';
  function show(k){current=k;cmd.textContent=cmds[k];tabs.forEach(function(t){t.setAttribute('aria-selected',t.dataset.k===k?'true':'false')});}
  tabs.forEach(function(t){t.addEventListener('click',function(){show(t.dataset.k)})});
  copy.addEventListener('click',function(){
    navigator.clipboard.writeText(cmds[current]).then(function(){copy.textContent='copied';copy.classList.add('is-copied');setTimeout(function(){copy.textContent='copy';copy.classList.remove('is-copied')},1600)});
  });
})();`;

export async function renderHome(version: string): Promise<string> {
  const demo = await verifyReceipt(golden.input);
  const body = `
<header class="pre" role="note" aria-label="release status">
  <span class="stamp"><span class="pulse" aria-hidden="true"></span>${escapeHtml(version)} · read-only</span>
  <span class="meta">no account · no key · nothing stored</span>
</header>
<h1><span>paste a <em>run receipt</em>.</span><span>get a <em>verdict</em>.</span></h1>
<p class="lede">a stateless endpoint that recomputes every hash chain a bernstein run receipt carries and checks the signature with the key the receipt embeds. the same walk <code>bernstein verify-receipt</code> does, reachable from any mcp client or <a href="/verify">this page</a>.</p>

<div class="grid">
  <section aria-labelledby="install-label">
    <p class="label" id="install-label">add it to your agent</p>
    <div class="install">
      <div class="tabs" role="tablist">
        <button class="tab" role="tab" data-k="claude" aria-selected="true">claude code</button>
        <button class="tab" role="tab" data-k="json" aria-selected="false">mcp.json</button>
        <button class="tab" role="tab" data-k="curl" aria-selected="false">curl</button>
      </div>
      <div class="cmdrow"><pre class="cmd"><span class="prompt">$</span><span id="cmd">${escapeHtml(INSTALL.claude)}</span></pre><button class="copy" id="copy" type="button">copy</button></div>
    </div>

    <p class="label">tools</p>
    <table class="tools"><tbody>
${TOOLS.map(([n, d]) => `      <tr><td>${n}</td><td>${escapeHtml(d)}</td></tr>`).join("\n")}
    </tbody></table>

    <p class="label">limits</p>
    <p class="limits">${(MAX_BODY_BYTES / 1024 / 1024).toFixed(0)} mb per request · ${MAX_CHAIN_ENTRIES} rows per chain · 60 requests per minute per address<br>one log line per session (client name and version) · no receipt is ever written anywhere</p>
  </section>

  <aside aria-labelledby="demo-label">
    <p class="label" id="demo-label">a verified receipt, checked just now</p>
    ${renderLedger(demo, { link: false })}
    <p class="note" style="margin-top:18px">the audit range's hmac values are keyed by the producing install, so they read <em>unverifiable</em> here by design: their linkage and content hash were still recomputed. <a href="/verify">verify your own →</a></p>
  </aside>
</div>
`;
  return page({
    title: "bernstein mcp",
    description: "Stateless, read-only MCP endpoint that verifies bernstein run receipts and hash chains.",
    current: "home",
    body,
    script: SCRIPT,
  });
}
