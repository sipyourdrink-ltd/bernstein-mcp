// The journal is an append-only JSONL per segment; meta.json is the head
// pointer so a hook never re-reads the log. Both are rewritten atomically
// (tmp + rename) except the log, which is append + fsync.
import { appendFileSync, closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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

export function readMeta(agent: string, sessionId: string): Meta | null {
  try { return JSON.parse(readFileSync(metaPath(agent, sessionId), "utf8")) as Meta; } catch { return null; }
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

export function logError(err: unknown): void {
  try {
    mkdirSync(join(logPath(), ".."), { recursive: true, mode: 0o700 });
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    appendFileSync(logPath(), `${new Date().toISOString()} ${msg}\n`, { mode: 0o600 });
  } catch { /* the log is best-effort; a hook must never fail over it */ }
}
