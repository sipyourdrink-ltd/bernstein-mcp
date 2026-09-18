import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { handleHook, sealSession } from "./hook.js";
import { init, status, uninstall } from "./install.js";
import { loadOrCreateKey } from "./keys.js";
import { markdownBlock } from "./link.js";
import { keyPath, sessionDir } from "./paths.js";
import { readMeta, writeMeta, type Meta } from "./store.js";
import { PRODUCER_NAME, PRODUCER_VERSION } from "./version.js";
import { verifyReceipt } from "../src/verify/receipt.js";

const USAGE = `usage: bernstein-attest <command>
  init [--claude-code] [--codex] [--user|--project] [--dry-run]   register hooks (default: both agents, user scope)
  hook --agent <claude-code|codex>                                 called by the agent; reads the event on stdin
  seal [--agent a] [--session id]                                  seal the current segment now
  link [--agent a] [--session id]                                  print the verify link and a Markdown line
  verify <receipt.json>                                            verify a receipt offline
  status                                                           key, hooks, sessions
  uninstall [--user|--project] [--dry-run]                         remove the hooks (keeps the key and receipts)
`;

function flag(argv: string[], name: string): boolean {
  return argv.includes(name);
}
function value(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}
// Matches the resolution hook.ts uses for a session's project root, so `init`/`status`/
// `uninstall` target the same project a hook running in that same environment would.
function projectDir(): string {
  return process.env.CLAUDE_PROJECT_DIR || process.cwd();
}

function latestMeta(agent?: string, session?: string): Meta | null {
  const agents = agent ? [agent] : ["claude-code", "codex"];
  let best: { meta: Meta; mtime: number } | null = null;
  for (const a of agents) {
    let names: string[] = [];
    try { names = readdirSync(sessionDir(a)); } catch { continue; }
    for (const n of names.filter((f) => f.endsWith(".meta.json"))) {
      const id = n.slice(0, -".meta.json".length);
      if (session && id !== session) continue;
      const meta = readMeta(a, id);
      if (!meta) continue;
      const mtime = statSync(join(sessionDir(a), n)).mtimeMs;
      if (!best || mtime > best.mtime) best = { meta, mtime };
    }
  }
  return best?.meta ?? null;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];

  if (cmd === "--version" || cmd === "-v") {
    process.stdout.write(`${PRODUCER_NAME} ${PRODUCER_VERSION}\n`);
    return 0;
  }

  if (cmd === "hook") {
    const agent = value(argv, "--agent") === "codex" ? "codex" : "claude-code";
    let payload: unknown = null;
    try { payload = JSON.parse(await readStdin()); } catch { payload = null; }
    const r = await handleHook(agent, payload);
    if (r.stdout) process.stdout.write(r.stdout);
    return 0;
  }

  if (cmd === "init") {
    const both = !flag(argv, "--claude-code") && !flag(argv, "--codex");
    const dryRun = flag(argv, "--dry-run");
    const rep = await init({
      claudeCode: both || flag(argv, "--claude-code"),
      codex: both || flag(argv, "--codex"),
      scope: flag(argv, "--project") ? "project" : "user",
      projectDir: projectDir(),
      dryRun,
      bundleSource: process.argv[1],
    });
    process.stdout.write(`key: ${rep.keyId}${rep.keyCreated ? " (new)" : ""}\nbundle: ${rep.bundle}\n`);
    for (const c of rep.changes) {
      process.stdout.write(`${dryRun ? "would write" : "wrote"} ${c.file}${c.backup ? ` (backup ${c.backup})` : ""}\n${c.after}`);
    }
    if (!rep.changes.length) process.stdout.write("hooks already registered; nothing to change\n");
    for (const notice of rep.notices) process.stdout.write(`${notice}\n`);
    return 0;
  }

  if (cmd === "seal" || cmd === "link") {
    const meta = latestMeta(value(argv, "--agent"), value(argv, "--session"));
    if (!meta) { process.stderr.write("no session found\n"); return 1; }
    if (cmd === "seal") {
      const done = await sealSession(meta, { now: Math.floor(Date.now() / 1000), key: await loadOrCreateKey(keyPath()), force: true });
      writeMeta(meta);
      if (!done) { process.stderr.write("nothing to seal\n"); return 1; }
      process.stdout.write(`${done.projectFile}\n${done.stateFile}\n${meta.last_verify_url}\n`);
      return 0;
    }
    if (!meta.last_verify_url) { process.stderr.write("session has no receipt yet; run `bernstein-attest seal`\n"); return 1; }
    process.stdout.write(`${meta.last_verify_url}\n${markdownBlock({ url: meta.last_verify_url, toolCalls: meta.last_receipt_tool_calls, files: meta.last_receipt_files })}\n`);
    return 0;
  }

  if (cmd === "verify") {
    const file = argv[1];
    if (!file) { process.stderr.write(USAGE); return 2; }
    const v = await verifyReceipt(readFileSync(file, "utf8"));
    process.stdout.write(`${v.verdict}${v.failing_check ? ` (${v.failing_check}${v.divergent_step !== null ? ` at step ${v.divergent_step}` : ""})` : ""} sha256:${v.receipt_sha256}\n`);
    for (const c of v.checks) process.stdout.write(`  ${c.outcome.padEnd(12)} ${c.name}${c.detail ? ` — ${c.detail}` : ""}\n`);
    return v.verdict === "valid" ? 0 : 1;
  }

  if (cmd === "status") {
    const s = status(projectDir());
    process.stdout.write(`key: ${s.keyId ?? "(none yet)"}\nbundle: ${s.bundle ?? "(not installed)"}\n`);
    for (const h of s.hooks) process.stdout.write(`hooks: ${h.file} [${h.events.join(", ")}]\n`);
    for (const x of s.sessions) {
      const rows = x.rows === -1 ? "?" : String(x.rows);
      process.stdout.write(`session: ${x.agent} ${x.sessionId} rows=${rows} segment=${x.segment}${x.lastRunId ? ` receipt=${x.lastRunId}` : ""}\n`);
    }
    return 0;
  }

  if (cmd === "uninstall") {
    const dryRun = flag(argv, "--dry-run");
    const changes = uninstall({ scope: flag(argv, "--project") ? "project" : "user", projectDir: projectDir(), dryRun });
    for (const c of changes) process.stdout.write(`${dryRun ? "would write" : "wrote"} ${c.file}${c.backup ? ` (backup ${c.backup})` : ""}\n`);
    if (!changes.length) process.stdout.write("no hooks of ours found\n");
    return 0;
  }

  process.stderr.write(USAGE);
  return 2;
}

if (typeof require !== "undefined" && require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (err) => { process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`); process.exitCode = 1; },
  );
}
