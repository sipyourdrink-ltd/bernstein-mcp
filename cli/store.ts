// The journal is an append-only JSONL per segment; meta.json is the head
// pointer so a hook never re-reads the log. Both are rewritten atomically
// (tmp + rename) except the log, which is append + fsync. Hook processes of
// one session run under withSessionLock so the read-head/append/write-head
// sequence of one never interleaves with another's.
import { appendFileSync, closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { logPath, sessionDir } from "./paths.js";
import { GENESIS, hashRow, type ChainHead, type RowInput } from "./rows.js";

export interface Meta {
  agent: "claude-code" | "codex"; session_id: string; project_root: string; project: string;
  model: string; agent_version?: string;
  segment: number; head: ChainHead; sealed_index: number;
  files: Record<string, string>;
  turn: number; last_notice_ts: number; last_notice_files: string;
  last_receipt_sha256: string; last_run_id: string; last_verify_url: string;
  /** Counts of the receipt named by last_run_id, so link/the notice describe the sealed file, not the live segment. */
  last_receipt_tool_calls: number; last_receipt_files: number;
  prev_receipt_sha256: string;
}

export function newMeta(init: Pick<Meta, "agent" | "session_id" | "project_root" | "project" | "model" | "agent_version">): Meta {
  return {
    ...init, segment: 1, head: { ...GENESIS }, sealed_index: -1, files: {}, turn: 0,
    last_notice_ts: 0, last_notice_files: "", last_receipt_sha256: "", last_run_id: "", last_verify_url: "",
    last_receipt_tool_calls: 0, last_receipt_files: 0, prev_receipt_sha256: "",
  };
}

const metaPath = (agent: string, sessionId: string) => join(sessionDir(agent), `${sessionId}.meta.json`);
export const journalPath = (meta: Meta) => join(sessionDir(meta.agent), `${meta.session_id}.s${meta.segment}.jsonl`);
export const runId = (meta: Meta) => (meta.segment === 1 ? meta.session_id : `${meta.session_id}-s${meta.segment}`);

// A meta file can predate a field added to Meta later (e.g. last_receipt_tool_calls);
// spreading the parse over newMeta's defaults fills anything the file lacks instead of
// leaving it undefined, so an older session doesn't turn into "undefined tool calls".
export function readMeta(agent: string, sessionId: string): Meta | null {
  let parsed: Partial<Meta>;
  try { parsed = JSON.parse(readFileSync(metaPath(agent, sessionId), "utf8")) as Partial<Meta>; } catch { return null; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const defaults = newMeta({
    agent: parsed.agent as Meta["agent"], session_id: parsed.session_id as string, project_root: parsed.project_root as string,
    project: parsed.project as string, model: parsed.model as string, agent_version: parsed.agent_version,
  });
  return { ...defaults, ...parsed };
}

export function writeMeta(meta: Meta): void {
  const path = metaPath(meta.agent, meta.session_id);
  mkdirSync(sessionDir(meta.agent), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(meta), { mode: 0o600 });
  renameSync(tmp, path);
}

export function appendRow(meta: Meta, input: RowInput): RowInput {
  const { row, head } = hashRow(input, meta.head);
  mkdirSync(sessionDir(meta.agent), { recursive: true, mode: 0o700 });
  const fd = openSync(journalPath(meta), "a", 0o600);
  try {
    appendFileSync(fd, JSON.stringify(row) + "\n");
    fsyncSync(fd);
  } finally { closeSync(fd); }
  meta.head = head;
  return row;
}

export function readRows(meta: Meta): RowInput[] {
  let text: string;
  try { text = readFileSync(journalPath(meta), "utf8"); } catch { return []; }
  return text.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l) as RowInput);
}

export function rollSegment(meta: Meta, prevReceiptSha256: string, ts: number): RowInput {
  meta.segment += 1;
  meta.head = { ...GENESIS };
  meta.sealed_index = -1;
  meta.files = {};
  meta.prev_receipt_sha256 = prevReceiptSha256;
  return appendRow(meta, { event: "segment_started", segment: meta.segment, prev_receipt_sha256: prevReceiptSha256, ts });
}

const LOCK_STALE_MS = 10_000;
const LOCK_SLICE_MS = 2;
const LOCK_BUDGET_MS = 3_000;
const sleeper = new Int32Array(new SharedArrayBuffer(4));
export const sessionLockPath = (agent: string, sessionId: string) => join(sessionDir(agent), `${sessionId}.lock`);

/**
 * Runs fn while holding the session's lock directory. mkdir is atomic, so EEXIST
 * means another hook process holds it: wait in 2 ms slices (a blocking
 * Atomics.wait, not a timer) and retry until the budget runs out. A lock older
 * than ten seconds belongs to a hook that died holding it and is broken.
 */
export async function withSessionLock<T>(agent: string, sessionId: string, fn: () => Promise<T>, budgetMs = LOCK_BUDGET_MS): Promise<T> {
  const lock = sessionLockPath(agent, sessionId);
  mkdirSync(sessionDir(agent), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + budgetMs;
  for (;;) {
    try { mkdirSync(lock, { mode: 0o700 }); break; }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      let stale = false;
      try { stale = Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS; } catch { continue; }   // released between attempts
      if (stale) { rmSync(lock, { recursive: true, force: true }); continue; }
      if (Date.now() >= deadline) throw new Error(`session lock timeout: ${lock}`);
      Atomics.wait(sleeper, 0, 0, LOCK_SLICE_MS);
    }
  }
  try { return await fn(); }
  finally { rmSync(lock, { recursive: true, force: true }); }
}

export function logError(err: unknown): void {
  try {
    mkdirSync(join(logPath(), ".."), { recursive: true, mode: 0o700 });
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    appendFileSync(logPath(), `${new Date().toISOString()} ${msg}\n`, { mode: 0o600 });
  } catch { /* the log is best-effort; a hook must never fail over it */ }
}
