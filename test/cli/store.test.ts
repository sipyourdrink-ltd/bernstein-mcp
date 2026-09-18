/// <reference types="node" />
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keyPath, sessionDir, SEGMENT_ROWS, statePath } from "../../cli/paths.js";
import { appendRow, journalPath, newMeta, readMeta, readRows, rollSegment, runId, sessionLockPath, withSessionLock, writeMeta } from "../../cli/store.js";
import { walkJournal } from "../../src/verify/chains.js";
import { toJsonObject } from "../../cli/rows.js";

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "attest-home-")); process.env.BERNSTEIN_ATTEST_HOME = home; });
afterEach(() => { delete process.env.BERNSTEIN_ATTEST_HOME; rmSync(home, { recursive: true, force: true }); });

describe("paths", () => {
  it("live under BERNSTEIN_ATTEST_HOME", () => {
    expect(keyPath()).toBe(join(home, ".config", "bernstein-attest", "key.jwk"));
    expect(statePath()).toBe(join(home, ".local", "state", "bernstein-attest"));
    expect(sessionDir("codex")).toBe(join(statePath(), "sessions", "codex"));
    expect(SEGMENT_ROWS).toBe(2000);
  });
});

describe("store", () => {
  it("appends hashed rows, persists meta, and reads the chain back intact", () => {
    const meta = newMeta({ agent: "claude-code", session_id: "abc", project_root: "/p", project: "p", model: "unknown" });
    const r0 = appendRow(meta, { event: "session_started", agent: "claude-code", producer: "x", project: "p", cwd_sha256: "c".repeat(64), ts: 1 });
    const r1 = appendRow(meta, { event: "tool_call", tool: "Bash", tool_use_id: "t1", input_sha256: "a".repeat(64), output_sha256: "b".repeat(64), ok: true, command_head: "ls", ts: 2 });
    writeMeta(meta);
    expect(r0.index).toBe(0); expect(r1.index).toBe(1);
    expect(meta.head.index).toBe(2);
    expect(readMeta("claude-code", "abc")).toEqual(meta);
    expect(readMeta("claude-code", "nope")).toBeNull();
    const lines = readFileSync(journalPath(meta), "utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1])).toEqual(r1);
    const rows = readRows(meta);
    expect(walkJournal(rows.map(toJsonObject)).divergentIndex).toBeNull();
    expect(runId(meta)).toBe("abc");
  });

  it("rolls to a fresh chain in a new file with a segment_started row", () => {
    const meta = newMeta({ agent: "codex", session_id: "s", project_root: "/p", project: "p", model: "m" });
    appendRow(meta, { event: "session_started", agent: "codex", producer: "x", project: "p", cwd_sha256: "c".repeat(64), ts: 1 });
    meta.files["a.txt"] = "call_1";
    const first = journalPath(meta);
    const row = rollSegment(meta, "f".repeat(64), 5);
    expect(meta.segment).toBe(2);
    expect(runId(meta)).toBe("s-s2");
    expect(meta.files).toEqual({});
    expect(meta.sealed_index).toBe(-1);
    expect(row).toMatchObject({ event: "segment_started", segment: 2, prev_receipt_sha256: "f".repeat(64), index: 0, prev_hash: "" });
    expect(journalPath(meta)).not.toBe(first);
    expect(existsSync(first)).toBe(true);
    expect(readRows(meta)).toHaveLength(1);
  });

  it("fills defaults for fields an older meta file lacks", () => {
    const meta = newMeta({ agent: "claude-code", session_id: "old", project_root: "/p", project: "p", model: "m" });
    meta.last_run_id = "old";
    meta.last_verify_url = "https://mcp.bernstein.run/verify/x";
    writeMeta(meta);
    const path = join(sessionDir("claude-code"), "old.meta.json");
    const raw = JSON.parse(readFileSync(path, "utf8"));
    delete raw.last_receipt_tool_calls;
    delete raw.last_receipt_files;
    writeFileSync(path, JSON.stringify(raw));
    const read = readMeta("claude-code", "old");
    expect(read?.last_receipt_tool_calls).toBe(0);
    expect(read?.last_receipt_files).toBe(0);
    expect(read?.last_run_id).toBe("old");
    expect(read?.last_verify_url).toBe("https://mcp.bernstein.run/verify/x");
    expect(read?.project_root).toBe("/p");
  });

  it("treats a meta file holding valid JSON that isn't an object as malformed", () => {
    mkdirSync(sessionDir("claude-code"), { recursive: true });
    writeFileSync(join(sessionDir("claude-code"), "null-meta.meta.json"), "null");
    expect(readMeta("claude-code", "null-meta")).toBeNull();
  });
});

describe("withSessionLock", () => {
  // The wait is a blocking Atomics.wait, so the contending holder has to be another
  // process (as in production: one process per hook event). The child takes the lock,
  // holds it 30 ms, leaves a marker as it releases; our body must start after that.
  it("serialises with a holder in another process", async () => {
    const lock = sessionLockPath("claude-code", "s1");
    const marker = join(home, "released");
    mkdirSync(sessionDir("claude-code"), { recursive: true });
    const holder = spawn(process.execPath, ["-e", `
      const fs = require("node:fs");
      fs.mkdirSync(${JSON.stringify(lock)});
      process.stdout.write("held\\n");
      setTimeout(() => { fs.writeFileSync(${JSON.stringify(marker)}, ""); fs.rmSync(${JSON.stringify(lock)}, { recursive: true }); }, 30);
    `], { stdio: ["ignore", "pipe", "inherit"] });
    await new Promise<void>((r) => holder.stdout.once("data", () => r()));
    expect(existsSync(lock)).toBe(true);
    const sawRelease = await withSessionLock("claude-code", "s1", async () => existsSync(marker));
    expect(sawRelease).toBe(true);
    expect(existsSync(lock)).toBe(false);
    await new Promise<void>((r) => holder.once("exit", () => r()));
  });

  it("releases the lock when the body throws", async () => {
    await expect(withSessionLock("codex", "s2", async () => { throw new Error("boom"); })).rejects.toThrow("boom");
    expect(existsSync(sessionLockPath("codex", "s2"))).toBe(false);
  });

  it("breaks a lock older than ten seconds", async () => {
    const lock = sessionLockPath("claude-code", "s3");
    mkdirSync(lock, { recursive: true });
    const old = (Date.now() - 20_000) / 1000;
    utimesSync(lock, old, old);
    expect(await withSessionLock("claude-code", "s3", async () => 42)).toBe(42);
    expect(existsSync(lock)).toBe(false);
  });

  it("gives up on a fresh foreign lock once the budget is spent", async () => {
    const lock = sessionLockPath("claude-code", "s4");
    mkdirSync(lock, { recursive: true });
    const t0 = Date.now();
    await expect(withSessionLock("claude-code", "s4", async () => 0, 100)).rejects.toThrow(`session lock timeout: ${lock}`);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(90);
    expect(existsSync(lock)).toBe(true);   // a lock we did not take is not ours to remove
  });
});
