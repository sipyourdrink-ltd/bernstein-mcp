// Registration edits other people's config files, so: read → merge →
// backup → atomic write, and never touch an entry we did not add. The
// bundle is copied to a stable path so the command line in the settings
// survives npm cache eviction.
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { keyIdOf, loadKeyFile, loadOrCreateKey } from "./keys.js";
import { bundlePath, claudeSettingsPath, codexHooksPath, keyPath, sessionDir } from "./paths.js";
import { readRows } from "./store.js";
import type { Meta } from "./store.js";

type Json = Record<string, unknown>;
type Entry = { matcher?: string; hooks: { type: "command"; command: string; timeout?: number }[] };
// Matches the exact shape `hookCommand` produces for either agent, regardless of the
// bundle's path — so identification does not depend on the bundle living under a
// "bernstein-attest" directory (tests exercise merge/removal with an arbitrary bundle path).
const OUR_COMMAND = /^node ".*" hook --agent (claude-code|codex)$/;
const CC_EVENTS: [string, string, number][] = [["PostToolUse", "*", 20], ["PostToolUseFailure", "*", 20], ["Stop", "", 30], ["SessionEnd", "", 5]];
const CODEX_EVENTS: [string, number][] = [["PostToolUse", 20], ["Stop", 30], ["SessionEnd", 3]];

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

function readJson(file: string): unknown {
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; }
}
function stamp(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "");
}
function apply(file: string, next: Json, dryRun: boolean): InitReport["changes"][number] | null {
  const beforeText = existsSync(file) ? readFileSync(file, "utf8") : "";
  const after = JSON.stringify(next, null, 2) + "\n";
  if (beforeText && JSON.stringify(readJson(file)) === JSON.stringify(next)) return null;
  let backup: string | null = null;
  if (!dryRun) {
    mkdirSync(dirname(file), { recursive: true });
    if (beforeText) { backup = `${file}.bak-${stamp()}`; copyFileSync(file, backup); }
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, after);
    renameSync(tmp, file);
  }
  return { file, backup, before: beforeText, after };
}

export interface InitOptions { claudeCode: boolean; codex: boolean; scope: "user" | "project"; projectDir: string; dryRun: boolean; bundleSource: string }
export interface InitReport { keyId: string; keyCreated: boolean; bundle: string; changes: { file: string; backup: string | null; before: string; after: string }[] }

export async function init(o: InitOptions): Promise<InitReport> {
  const had = await loadKeyFile(keyPath());
  const key = o.dryRun && !had ? null : await loadOrCreateKey(keyPath());
  const bundle = bundlePath();
  if (!o.dryRun) {
    mkdirSync(dirname(bundle), { recursive: true });
    copyFileSync(o.bundleSource, bundle);
    chmodSync(bundle, 0o755);
  }
  const changes: InitReport["changes"] = [];
  if (o.claudeCode) {
    const file = claudeSettingsPath(o.scope, o.projectDir);
    const c = apply(file, mergeClaudeSettings(readJson(file), bundle), o.dryRun);
    if (c) changes.push(c);
  }
  if (o.codex) {
    const file = codexHooksPath(o.scope, o.projectDir);
    const c = apply(file, mergeCodexHooks(readJson(file), bundle), o.dryRun);
    if (c) changes.push(c);
    if (!o.dryRun) console.log("Codex: run /hooks inside codex once to review and trust the new hooks.");
  }
  return { keyId: key?.keyId ?? "(created on first run)", keyCreated: !had && !o.dryRun, bundle, changes };
}

export interface Status { keyId: string | null; bundle: string | null; hooks: { file: string; events: string[] }[]; sessions: { agent: string; sessionId: string; rows: number; segment: number; lastRunId: string }[] }

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
      const meta = readJson(join(sessionDir(agent), f)) as Meta | undefined;
      if (!meta) continue;
      out.sessions.push({ agent, sessionId: meta.session_id, rows: readRows(meta).length, segment: meta.segment, lastRunId: meta.last_run_id });
    }
  }
  return out;
}

export function uninstall(o: { scope: "user" | "project"; projectDir: string; dryRun: boolean }): InitReport["changes"] {
  const changes: InitReport["changes"] = [];
  for (const file of [claudeSettingsPath(o.scope, o.projectDir), codexHooksPath(o.scope, o.projectDir)]) {
    if (!existsSync(file)) continue;
    const c = apply(file, removeOurHooks(readJson(file)), o.dryRun);
    if (c) changes.push(c);
  }
  return changes;
}
