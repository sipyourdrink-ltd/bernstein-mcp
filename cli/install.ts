// Registration edits other people's config files, so: read → merge →
// backup → atomic write, and never touch an entry we did not add. The
// bundle is copied to a stable path so the command line in the settings
// survives npm cache eviction.
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { keyIdOf, loadKeyFile, loadOrCreateKey } from "./keys.js";
import { bundlePath, claudeSettingsPath, codexHooksPath, keyPath, sessionDir } from "./paths.js";
import { readMeta, readRows } from "./store.js";

type Json = Record<string, unknown>;
type Entry = { matcher?: string; hooks: { type: "command"; command: string; timeout?: number }[] };
// Matches the exact shape `hookCommand` produces for either agent, regardless of the
// bundle's path — so identification does not depend on the bundle living under a
// "bernstein-attest" directory (tests exercise merge/removal with an arbitrary bundle path).
const OUR_COMMAND = /^node ".*" hook --agent (claude-code|codex)$/;
const CC_EVENTS: [string, string, number][] = [["PostToolUse", "*", 20], ["PostToolUseFailure", "*", 20], ["Stop", "", 30], ["SessionEnd", "", 5]];
const CODEX_EVENTS: [string, number][] = [["PostToolUse", 20], ["Stop", 30], ["SessionEnd", 3]];
const CODEX_TRUST_NOTICE = "Codex: run /hooks inside codex once to review and trust the new hooks.";

export function hookCommand(agent: "claude-code" | "codex", bundle: string): string {
  return `node "${bundle}" hook --agent ${agent}`;
}
const isOurs = (e: Entry) => e.hooks?.some((h) => typeof h.command === "string" && OUR_COMMAND.test(h.command));
const asObject = (v: unknown): Json => (v && typeof v === "object" && !Array.isArray(v) ? { ...(v as Json) } : {});

function merge(existing: unknown, entries: [string, Entry][]): Json {
  const out = asObject(existing);
  const hooks = asObject(out.hooks);
  for (const [event, entry] of entries) {
    const list = Array.isArray(hooks[event]) ? [...(hooks[event] as Entry[])] : [];
    if (!list.some(isOurs)) list.push(entry);
    hooks[event] = list;
  }
  out.hooks = hooks;
  return out;
}
export function mergeClaudeSettings(existing: unknown, bundle: string): Json {
  const cmd = hookCommand("claude-code", bundle);
  return merge(existing, CC_EVENTS.map(([ev, matcher, timeout]) => [ev, { matcher, hooks: [{ type: "command", command: cmd, timeout }] }]));
}
export function mergeCodexHooks(existing: unknown, bundle: string): Json {
  const cmd = hookCommand("codex", bundle);
  return merge(existing, CODEX_EVENTS.map(([ev, timeout]) => [ev, { hooks: [{ type: "command", command: cmd, timeout }] }]));
}
export function removeOurHooks(existing: unknown): Json {
  const out = asObject(existing);
  const hooks = asObject(out.hooks);
  for (const [event, list] of Object.entries(hooks)) {
    const kept = (Array.isArray(list) ? (list as Entry[]) : []).filter((e) => !isOurs(e));
    if (kept.length) hooks[event] = kept; else delete hooks[event];
  }
  if (Object.keys(hooks).length) out.hooks = hooks; else delete out.hooks;
  return out;
}

// Lenient read: a missing or unparsable file is just "nothing here". Used by status(),
// which is a read-only report and must never throw over a file it doesn't own writing to.
function readJson(file: string): unknown {
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; }
}
// Strict read for the write paths (init/uninstall): a missing file means "start from
// {}", but a file that exists and fails to parse must stop the run before any write or
// backup — silently replacing a corrupt config with only our hooks would destroy whatever
// was there (ours or someone else's).
function readConfigJson(file: string): unknown {
  let text: string;
  try { text = readFileSync(file, "utf8"); } catch { return undefined; }
  try { return JSON.parse(text); } catch {
    throw new Error(`${file} is not valid JSON; fix it by hand or move it aside, then rerun`);
  }
}
function stamp(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "");
}
function apply(file: string, next: Json, dryRun: boolean): InitReport["changes"][number] | null {
  const exists = existsSync(file);
  const beforeText = exists ? readFileSync(file, "utf8") : "";
  const after = JSON.stringify(next, null, 2) + "\n";
  if (beforeText && JSON.stringify(readJson(file)) === JSON.stringify(next)) return null;
  let backup: string | null = null;
  if (!dryRun) {
    mkdirSync(dirname(file), { recursive: true });
    if (exists) { backup = `${file}.bak-${stamp()}`; copyFileSync(file, backup); }
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, after);
    renameSync(tmp, file);
  }
  return { file, backup, before: beforeText, after };
}

export interface InitOptions { claudeCode: boolean; codex: boolean; scope: "user" | "project"; projectDir: string; dryRun: boolean; bundleSource: string }
export interface InitReport { keyId: string; keyCreated: boolean; bundle: string; changes: { file: string; backup: string | null; before: string; after: string }[]; notices: string[] }

export async function init(o: InitOptions): Promise<InitReport> {
  const bundle = bundlePath();
  const claudeFile = o.claudeCode ? claudeSettingsPath(o.scope, o.projectDir) : null;
  const codexFile = o.codex ? codexHooksPath(o.scope, o.projectDir) : null;
  // Read + validate every target config before touching disk anywhere. A malformed
  // file throws here, before the key is created or the bundle is copied, so a bad
  // settings.json aborts the whole run instead of leaving a partial install behind.
  const nextClaude = claudeFile ? mergeClaudeSettings(readConfigJson(claudeFile), bundle) : null;
  const nextCodex = codexFile ? mergeCodexHooks(readConfigJson(codexFile), bundle) : null;

  const had = await loadKeyFile(keyPath());
  const key = o.dryRun && !had ? null : await loadOrCreateKey(keyPath());
  if (!o.dryRun) {
    mkdirSync(dirname(bundle), { recursive: true });
    copyFileSync(o.bundleSource, bundle);
    chmodSync(bundle, 0o755);
  }
  const changes: InitReport["changes"] = [];
  const notices: string[] = [];
  if (claudeFile && nextClaude) {
    const c = apply(claudeFile, nextClaude, o.dryRun);
    if (c) changes.push(c);
  }
  if (codexFile && nextCodex) {
    const c = apply(codexFile, nextCodex, o.dryRun);
    if (c) {
      changes.push(c);
      if (!o.dryRun) notices.push(CODEX_TRUST_NOTICE);
    }
  }
  return { keyId: key?.keyId ?? "(created on first run)", keyCreated: !had && !o.dryRun, bundle, changes, notices };
}

export interface Status {
  keyId: string | null; bundle: string | null; hooks: { file: string; events: string[] }[];
  /** `rows` is -1 when the session's journal exists but a line failed to parse (e.g. a truncated write) — the session is still reported, just without a row count. */
  sessions: { agent: string; sessionId: string; rows: number; segment: number; lastRunId: string }[];
}

export function status(projectDir: string): Status {
  const out: Status = { keyId: null, bundle: existsSync(bundlePath()) ? bundlePath() : null, hooks: [], sessions: [] };
  const key = readJson(keyPath()) as { x?: string } | undefined;
  if (key?.x) out.keyId = keyIdOf(key.x);
  for (const file of [claudeSettingsPath("user"), claudeSettingsPath("project", projectDir), codexHooksPath("user"), codexHooksPath("project", projectDir)]) {
    const hooks = asObject(asObject(readJson(file)).hooks);
    const events = Object.entries(hooks).filter(([, list]) => Array.isArray(list) && (list as Entry[]).some(isOurs)).map(([ev]) => ev);
    if (events.length) out.hooks.push({ file, events });
  }
  for (const agent of ["claude-code", "codex"] as const) {
    let files: string[] = [];
    try { files = readdirSync(sessionDir(agent)); } catch { continue; }
    for (const f of files.filter((n) => n.endsWith(".meta.json"))) {
      const sessionId = f.replace(/\.meta\.json$/, "");
      try {
        const meta = readMeta(agent, sessionId);
        if (!meta) continue;
        let rows = -1;
        try { rows = readRows(meta).length; } catch { /* damaged journal segment; still report the session */ }
        out.sessions.push({ agent, sessionId: meta.session_id, rows, segment: meta.segment, lastRunId: meta.last_run_id });
      } catch {
        out.sessions.push({ agent, sessionId, rows: -1, segment: -1, lastRunId: "" });
      }
    }
  }
  return out;
}

export function uninstall(o: { scope: "user" | "project"; projectDir: string; dryRun: boolean }): InitReport["changes"] {
  const files = [claudeSettingsPath(o.scope, o.projectDir), codexHooksPath(o.scope, o.projectDir)];
  // Same validate-before-writing rule as init(): compute every target's next state
  // up front so a malformed file aborts before any write or backup happens.
  const nexts = files.map((file) => (existsSync(file) ? removeOurHooks(readConfigJson(file)) : null));
  const changes: InitReport["changes"] = [];
  files.forEach((file, i) => {
    const next = nexts[i];
    if (next === null) return;
    const c = apply(file, next, o.dryRun);
    if (c) changes.push(c);
  });
  return changes;
}
