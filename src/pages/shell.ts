// Shared HTML shell for the two pages the Worker serves. Tokens and voice
// follow bernstein.run: cream paper, Fraunces with italic accents, mono
// uppercase labels, staff-line dividers, lowercase copy. Fonts are served
// by this Worker (see /fonts), so a page loads nothing from a third party.

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

export const STYLE = `
:root{
  --bg-paper:oklch(96% 0.015 75);--bg-paper-2:oklch(94% 0.02 75);--bg-deep:oklch(20% 0.005 60);
  --ink:oklch(20% 0.005 60);--ink-soft:oklch(45% 0.005 60);--ink-faint:oklch(60% 0.005 60);
  --accent:oklch(55% 0.10 35);--accent-subtle:oklch(90% 0.04 35);
  --rule:oklch(85% 0.01 75);--rule-strong:oklch(70% 0.01 75);
  --ok:oklch(45% 0.08 145);--warn:oklch(55% 0.10 60);--bad:oklch(48% 0.15 25);
  --font-display:'Fraunces','Iowan Old Style','Charter',Georgia,serif;
  --font-body:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --font-mono:'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',Menlo,monospace;
  --radius:6px;
}
@font-face{font-family:'Fraunces';font-style:normal;font-weight:400 700;font-display:swap;src:url(/fonts/fraunces-latin.woff2) format('woff2')}
@font-face{font-family:'Fraunces';font-style:italic;font-weight:400 700;font-display:swap;src:url(/fonts/fraunces-latin-italic.woff2) format('woff2')}
@font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/jetbrains-mono-latin.woff2) format('woff2')}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg-paper);color:var(--ink);font-family:var(--font-body);font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--rule-strong);text-underline-offset:3px}
a:hover{text-decoration-color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
.nav{display:flex;align-items:baseline;justify-content:space-between;gap:16px;padding:22px 0 10px;flex-wrap:wrap}
.brand{font-family:var(--font-display);font-size:19px;letter-spacing:-0.01em;text-decoration:none}
.brand em{font-style:italic;color:var(--accent)}
.nav-links{display:flex;gap:18px;font-family:var(--font-mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-soft)}
.nav-links a{text-decoration:none}
.nav-links a:hover,.nav-links a[aria-current]{color:var(--ink)}
.staff{display:block;height:12px;margin:8px 0 0}
.staff svg{width:100%;height:12px;display:block}
.staff line{stroke:var(--rule);stroke-width:.5}
.pre{display:flex;align-items:center;gap:12px;flex-wrap:wrap;color:var(--ink-soft);margin:44px 0 20px}
.stamp{display:inline-flex;align-items:center;gap:8px;padding:4px 10px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--rule);border-radius:999px;background:var(--bg-paper-2)}
.stamp .pulse{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:pulse 2.4s infinite ease-out}
@keyframes pulse{0%{box-shadow:0 0 0 0 oklch(45% 0.08 145/.45)}70%{box-shadow:0 0 0 8px oklch(45% 0.08 145/0)}100%{box-shadow:0 0 0 0 oklch(45% 0.08 145/0)}}
.meta{font-family:var(--font-mono);font-size:11px;letter-spacing:.10em;text-transform:uppercase}
h1{font-family:var(--font-display);font-weight:400;font-size:clamp(34px,5.4vw,54px);line-height:1.04;letter-spacing:-.022em;margin:0 0 18px}
h1 span{display:block}
h1 em,h2 em,.lede em{font-style:italic;color:var(--accent)}
h2{font-family:var(--font-display);font-weight:400;font-size:26px;letter-spacing:-.015em;line-height:1.15;margin:0 0 14px}
.lede{font-size:17px;line-height:1.6;color:var(--ink-soft);max-width:56ch;margin:0 0 28px}
.lede code,p code,li code,td code{font-family:var(--font-mono);font-size:.88em;background:var(--bg-paper-2);padding:1px 5px;border-radius:3px}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:48px;align-items:start;margin-bottom:56px}
.grid>*{min-width:0}
.label{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.10em;text-transform:uppercase;color:var(--ink-soft);margin:0 0 10px}
.install{border:1px solid var(--rule);border-radius:var(--radius);background:var(--bg-paper);overflow:hidden;margin-bottom:24px}
.tabs{display:flex;border-bottom:1px solid var(--rule);font-family:var(--font-mono);font-size:11.5px}
.tab{padding:9px 14px;color:var(--ink-soft);border:0;border-right:1px solid var(--rule);background:transparent;cursor:pointer;font:inherit}
.tab:last-child{border-right:0}
.tab[aria-selected=true]{color:var(--ink);background:var(--bg-paper-2)}
.tab:hover{color:var(--ink)}
.cmdrow{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px}
.cmd{font-family:var(--font-mono);font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:0}
.cmd .prompt{color:var(--accent);margin-right:10px;user-select:none}
.copy{font-family:var(--font-mono);font-size:11px;color:var(--ink-soft);padding:5px 10px;border:1px solid var(--rule);border-radius:4px;background:var(--bg-paper);cursor:pointer;flex-shrink:0;transition:color 140ms,border-color 140ms}
.copy:hover{color:var(--ink);border-color:var(--ink)}
.copy.is-copied{color:var(--ok);border-color:var(--ok)}
.tools{width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px}
.tools td{padding:9px 0;border-top:1px solid var(--rule);vertical-align:top}
.tools td:first-child{font-family:var(--font-mono);font-size:12.5px;white-space:nowrap;padding-right:18px;width:1%}
.tools tr:last-child td{border-bottom:1px solid var(--rule)}
.limits{font-family:var(--font-mono);font-size:11px;letter-spacing:.06em;color:var(--ink-soft);line-height:1.9}
.ledger{border:1px solid var(--rule);border-radius:var(--radius);background:var(--bg-paper);overflow:hidden}
.ledger-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;border-bottom:1px solid var(--rule);background:var(--bg-paper-2)}
.ledger-head .run{font-family:var(--font-mono);font-size:11.5px;color:var(--ink-soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.verdict{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:4px 10px;border-radius:999px;border:1px solid currentColor;flex-shrink:0}
.verdict.valid{color:var(--ok)}
.verdict.invalid{color:var(--bad)}
.verdict.unverifiable{color:var(--warn)}
.ledger ol{list-style:none;margin:0;padding:6px 0}
.ledger li{display:grid;grid-template-columns:22px auto 1fr;gap:12px;align-items:baseline;padding:7px 16px;font-family:var(--font-mono);font-size:12.5px;animation:rise .5s ease-out both}
.ledger li:nth-child(n){animation-delay:calc(var(--i,0)*45ms)}
@keyframes rise{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
.ledger li .g{color:var(--ink-faint)}
.ledger li.ok .g{color:var(--ok)}
.ledger li.fail .g,.ledger li.fail .n{color:var(--bad)}
.ledger li.unverifiable .g{color:var(--warn)}
.ledger li .n{color:var(--ink)}
.ledger li.skipped .n{color:var(--ink-faint)}
.ledger li .d{color:var(--ink-soft);font-size:11px;text-align:right;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ledger-foot{padding:10px 16px;border-top:1px solid var(--rule);font-family:var(--font-mono);font-size:11px;color:var(--ink-soft);overflow-wrap:anywhere}
.ledger-foot a{color:var(--accent)}
.explain{margin:22px 0 0;padding:0;list-style:none;font-size:14.5px;color:var(--ink-soft);max-width:70ch}
.explain li{padding:8px 0;border-top:1px solid var(--rule);overflow-wrap:anywhere}
.explain li:first-child{color:var(--ink)}
textarea{width:100%;min-height:260px;padding:14px 16px;border:1px solid var(--rule);border-radius:var(--radius);background:var(--bg-paper);color:var(--ink);font-family:var(--font-mono);font-size:12.5px;line-height:1.5;resize:vertical}
textarea:focus{border-color:var(--rule-strong)}
.formrow{display:flex;align-items:center;gap:16px;margin:14px 0 40px;flex-wrap:wrap}
.btn{font-family:var(--font-mono);font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--bg-paper);background:var(--ink);border:1px solid var(--ink);border-radius:4px;padding:10px 18px;cursor:pointer}
.btn:hover{background:var(--accent);border-color:var(--accent)}
.hint{font-family:var(--font-mono);font-size:11px;color:var(--ink-soft)}
.signed{margin-top:18px;border-top:1px solid var(--rule);padding-top:12px}.signed summary{cursor:pointer;list-style:none}.signed summary::-webkit-details-marker{display:none}.envelope{font-family:var(--font-mono);font-size:11px;line-height:1.5;white-space:pre-wrap;word-break:break-all;color:var(--ink-soft);background:transparent;margin:0;max-height:260px;overflow:auto}
.note{border-left:2px solid var(--accent);padding:2px 0 2px 14px;color:var(--ink-soft);font-size:14px;max-width:70ch;margin:0 0 28px}
footer{padding:28px 0 40px;font-family:var(--font-mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft);display:flex;gap:18px;flex-wrap:wrap}
footer a{text-decoration:none}
footer a:hover{color:var(--ink)}
@media (max-width:820px){.grid{grid-template-columns:1fr;gap:32px}}
@media (max-width:520px){.wrap{padding:0 16px}.cmd{white-space:normal;overflow-wrap:anywhere}.ledger li{grid-template-columns:18px 1fr;gap:4px 8px}.ledger li .d{grid-column:2;text-align:left;white-space:normal}}
@media (prefers-reduced-motion:reduce){.ledger li{animation:none}.stamp .pulse{animation:none}}
`;

export const STAFF = `<div class="staff" aria-hidden="true"><svg viewBox="0 0 100 12" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg"><line x1="0" y1="1" x2="100" y2="1"/><line x1="0" y1="3.5" x2="100" y2="3.5"/><line x1="0" y1="6" x2="100" y2="6"/><line x1="0" y1="8.5" x2="100" y2="8.5"/><line x1="0" y1="11" x2="100" y2="11"/></svg></div>`;

export function page(opts: { title: string; description: string; current: "home" | "verify"; body: string; script?: string }): string {
  const link = (href: string, label: string, key: "home" | "verify") =>
    `<a href="${href}"${opts.current === key ? ' aria-current="page"' : ""}>${label}</a>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(opts.title)}</title>
<meta name="description" content="${escapeHtml(opts.description)}">
<meta name="color-scheme" content="light">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='14' fill='%23c9784f'/%3E%3C/svg%3E">
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
<nav class="nav" aria-label="site">
  <a class="brand" href="/">bernstein <em>mcp</em></a>
  <div class="nav-links">
    ${link("/", "install", "home")}
    ${link("/verify", "verify", "verify")}
    <a href="https://bernstein.run/">bernstein.run</a>
    <a href="https://github.com/sipyourdrink-ltd/bernstein-mcp">source</a>
  </div>
</nav>
${STAFF}
${opts.body}
${STAFF}
<footer>
  <span>apache-2.0</span>
  <a href="https://github.com/sipyourdrink-ltd/bernstein">bernstein on github</a>
  <a href="https://bernstein.run/">bernstein.run</a>
  <span>nothing stored · nothing fetched</span>
</footer>
</div>
${opts.script ? `<script>${opts.script}</script>` : ""}
</body>
</html>
`;
}
