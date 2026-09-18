// One hook process per event. Reads meta (a few hundred bytes), appends
// one row, rewrites meta; seals on Stop/SessionEnd or at the segment
// boundary. SessionEnd only appends/reseals when rows are unsealed since
// the last Stop; a receipt whose link was already shown never changes.
// Each handler runs under the session's lock, so parallel tool calls
// (one hook process each) extend one chain instead of forking it.
// Nothing here may throw past handleHook: every failure is one
// line in attest.log and an empty, exit-0 answer.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { keyPath, receiptsDir, SEGMENT_ROWS } from "./paths.js";
import { loadOrCreateKey, type AttestKey } from "./keys.js";
import { rawUrl, verifyUrl } from "./link.js";
import { normalise, type Agent, type HookEvent } from "./payload.js";
import { buildReceipt, type Sealed, type TouchedFile } from "./receipt.js";
import type { RowInput } from "./rows.js";
import { appendRow, logError, newMeta, readMeta, readRows, rollSegment, runId, withSessionLock, writeMeta, type Meta } from "./store.js";
import { PRODUCER_NAME, PRODUCER_VERSION } from "./version.js";

export interface HookResult { stdout: string; exitCode: 0 }
const NOTICE_INTERVAL_S = 600;
const MAX_HASHED_FILE_BYTES = 16 * 1024 * 1024;

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const digestOf = (v: unknown): string => sha256(typeof v === "string" ? v : JSON.stringify(v ?? null));

// The program name of a shell command: leading `VAR=value` assignments and a bare
// `env` are skipped, since their values are exactly what a receipt must not carry.
// A token that still holds `=`, `:` or `@` (a lone assignment, a URL, user@host) is
// dropped; the caller then leaves command_head out of the row.
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
export function commandHead(command: string): string {
  const tokens = command.trim().split(/\s+/).filter((t) => t.length > 0);
  let i = 0;
  while (i < tokens.length && (ENV_ASSIGNMENT.test(tokens[i]) || tokens[i] === "env")) i++;
  const token = tokens[i] ?? "";
  if (!token || /[=:@]/.test(token)) return "";
  return basename(token).slice(0, 32);
}

export function pathPolicy(projectRoot: string, candidate: string): { path: string } | { path_sha256: string } {
  const abs = resolve(projectRoot, candidate);
  const rel = relative(projectRoot, abs);
  if (rel && !rel.startsWith("..") && !isAbsolute(rel)) return { path: rel.split(sep).join("/") };
  return { path_sha256: sha256(abs) };
}

const CC_WRITE_TOOLS: Record<string, string> = { Write: "file_path", Edit: "file_path", MultiEdit: "file_path", NotebookEdit: "notebook_path" };

export function writePaths(agent: Agent, toolName: string, toolInput: unknown): string[] {
  const input = (toolInput && typeof toolInput === "object" ? toolInput : {}) as Record<string, unknown>;
  if (agent === "claude-code") {
    const key = CC_WRITE_TOOLS[toolName];
    return key && typeof input[key] === "string" ? [input[key] as string] : [];
  }
  if (toolName === "apply_patch" || toolName === "write_file") {
    const out: string[] = [];
    for (const v of Object.values(input)) {
      if (typeof v !== "string") continue;
      for (const m of v.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)) out.push(m[1].trim());
    }
    if (typeof input["path"] === "string") out.push(input["path"]);
    return [...new Set(out)];
  }
  return [];
}

function fileDigest(projectRoot: string, rel: string): string | null {
  const abs = join(projectRoot, rel);
  try {
    if (statSync(abs).size > MAX_HASHED_FILE_BYTES) return null;
    return sha256(readFileSync(abs));
  } catch { return null; }
}

function toolCallsIn(rows: RowInput[]): number {
  return rows.filter((r) => r.event === "tool_call").length;
}

export async function sealSession(meta: Meta, opts: { now: number; key: AttestKey; force?: boolean }): Promise<{ sealed: Sealed; runId: string; projectFile: string; stateFile: string } | null> {
  const lastIndex = meta.head.index - 1;
  if (!opts.force && lastIndex <= meta.sealed_index) return null;
  const rows = readRows(meta);
  if (rows.length === 0) return null;
  const files: TouchedFile[] = Object.entries(meta.files).map(([path, stepId]) => ({ path, stepId, contentSha256: fileDigest(meta.project_root, path) }));
  const id = runId(meta);
  const sealed = await buildReceipt({ runId: id, rows, files, agent: meta.agent, agentVersion: meta.agent_version, model: meta.model, key: opts.key, now: opts.now });
  const stateFile = join(receiptsDir(), `${id}.json`);
  const projectFile = join(meta.project_root, ".bernstein", "receipts", `${id}.json`);
  for (const f of [stateFile, projectFile]) {
    mkdirSync(join(f, ".."), { recursive: true });
    writeFileSync(f, sealed.text);
  }
  const from = rawUrl(meta.project_root, `.bernstein/receipts/${id}.json`);
  meta.sealed_index = lastIndex;
  meta.last_receipt_sha256 = sealed.receiptSha256;
  meta.last_run_id = id;
  meta.last_verify_url = verifyUrl(sealed.receiptSha256, from);
  meta.last_receipt_tool_calls = toolCallsIn(rows);
  meta.last_receipt_files = files.length;
  return { sealed, runId: id, projectFile, stateFile };
}

async function onTool(agent: Agent, ev: Extract<HookEvent, { kind: "tool" }>, now: () => number, env: NodeJS.ProcessEnv): Promise<string> {
  if (!ev.sessionId) throw new Error("payload without session_id");
  return withSessionLock(agent, ev.sessionId, async () => {
    let meta = readMeta(agent, ev.sessionId);
    if (!meta) {
      const root = env.CLAUDE_PROJECT_DIR || ev.cwd || process.cwd();
      meta = newMeta({ agent, session_id: ev.sessionId, project_root: root, project: basename(root), model: ev.model ?? env.ANTHROPIC_MODEL ?? "unknown" });
      appendRow(meta, { event: "session_started", agent, producer: `${PRODUCER_NAME} ${PRODUCER_VERSION}`, project: meta.project, ts: now() });
    }
    const row: RowInput = {
      event: "tool_call", tool: ev.toolName, tool_use_id: ev.toolUseId,
      input_sha256: digestOf(ev.toolInput), output_sha256: digestOf(ev.toolOutput), ok: ev.ok, ts: now(),
    };
    if (ev.agentId) row.agent_id = ev.agentId;
    if (ev.agentType) row.agent_type = ev.agentType;
    if (ev.toolName === "Bash" || ev.toolName === "shell") {
      const cmd = (ev.toolInput as { command?: unknown } | null)?.command;
      if (typeof cmd === "string") {
        const head = commandHead(cmd);
        if (head) row.command_head = head;
      }
    }
    const written = writePaths(agent, ev.toolName, ev.toolInput).map((p) => pathPolicy(meta!.project_root, p));
    if (written.length) {
      Object.assign(row, written[0]);
      const rest = written.slice(1).flatMap((w) => ("path" in w ? [w.path] : []));
      if (rest.length) row.paths_sha256 = sha256([...rest].sort().join("\n"));
      for (const w of written) if ("path" in w) meta.files[w.path] = ev.toolUseId;
    }
    appendRow(meta, row);
    writeMeta(meta);   // the head follows the journal at once; a seal failure below must not leave it behind
    if (meta.head.index >= SEGMENT_ROWS) {
      const key = await loadOrCreateKey(keyPath());
      const done = await sealSession(meta, { now: now(), key, force: true });
      if (done) { rollSegment(meta, done.sealed.receiptSha256, now()); writeMeta(meta); }
    }
    return "";
  });
}

async function onStop(agent: Agent, ev: Extract<HookEvent, { kind: "stop" }>, now: () => number): Promise<string> {
  if (!ev.sessionId) return "";
  return withSessionLock(agent, ev.sessionId, async () => {
    const meta = readMeta(agent, ev.sessionId);
    if (!meta) return "";                       // a turn with no tool calls: nothing to attest
    if (meta.head.index - 1 <= meta.sealed_index) return "";   // nothing new since the last seal: no-op
    meta.turn += 1;
    appendRow(meta, { event: "turn_ended", turn: meta.turn, last_message_sha256: sha256(ev.lastMessage), ts: now() });
    writeMeta(meta);
    const key = await loadOrCreateKey(keyPath());
    const t = now();
    const done = await sealSession(meta, { now: t, key });
    let out = "";
    if (done) {
      const filesKey = Object.keys(meta.files).sort().join("\n");
      if (t - meta.last_notice_ts >= NOTICE_INTERVAL_S || filesKey !== meta.last_notice_files) {
        const n = meta.last_receipt_tool_calls; const m = meta.last_receipt_files;
        out = JSON.stringify({ systemMessage: `Session receipt sealed: ${n} tool call${n === 1 ? "" : "s"}, ${m} file${m === 1 ? "" : "s"}. File: .bernstein/receipts/${done.runId}.json. Verify: ${meta.last_verify_url}. The link names the file as sealed at the end of this turn; right before you commit it or open a PR, run \`npx bernstein-attest link\` for the current one.` }) + "\n";
        meta.last_notice_ts = t; meta.last_notice_files = filesKey;
      }
    }
    writeMeta(meta);
    return out;
  });
}

async function onEnd(agent: Agent, ev: Extract<HookEvent, { kind: "end" }>, now: () => number): Promise<string> {
  if (!ev.sessionId) return "";
  return withSessionLock(agent, ev.sessionId, async () => {
    const meta = readMeta(agent, ev.sessionId);
    if (!meta) return "";
    if (meta.head.index - 1 <= meta.sealed_index) return "";   // already sealed by Stop: leave the shown receipt untouched
    appendRow(meta, { event: "session_ended", reason: ev.reason, ts: now() });
    writeMeta(meta);
    await sealSession(meta, { now: now(), key: await loadOrCreateKey(keyPath()) });
    writeMeta(meta);
    return "";
  });
}

export async function handleHook(agent: Agent, payload: unknown, opts: { now?: () => number; env?: NodeJS.ProcessEnv } = {}): Promise<HookResult> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const env = opts.env ?? process.env;
  try {
    const ev = normalise(agent, payload);
    switch (ev.kind) {
      case "tool": return { stdout: await onTool(agent, ev, now, env), exitCode: 0 };
      case "stop": return { stdout: await onStop(agent, ev, now), exitCode: 0 };
      case "end": return { stdout: await onEnd(agent, ev, now), exitCode: 0 };
      default: return { stdout: "", exitCode: 0 };
    }
  } catch (err) {
    logError(err);
    return { stdout: "", exitCode: 0 };
  }
}
