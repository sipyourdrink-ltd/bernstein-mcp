/// <reference types="node" />
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { commandHead, handleHook, pathPolicy, writePaths } from "../../cli/hook.js";
import { normalise } from "../../cli/payload.js";
import { markdownBlock, verifyUrl } from "../../cli/link.js";
import { keyPath, receiptsDir, SEGMENT_ROWS } from "../../cli/paths.js";
import { readMeta, readRows } from "../../cli/store.js";
import { PRODUCER_VERSION } from "../../cli/version.js";
import { verifyReceipt } from "../../src/verify/receipt.js";
import { TEST_JWK } from "./fixtures/test-key.js";

const fx = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8"));
let home: string; let project: string; let t = 1_700_000_000;
const now = () => t++;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "attest-home-"));
  project = mkdtempSync(join(tmpdir(), "attest-proj-"));
  mkdirSync(join(project, "src"), { recursive: true });
  writeFileSync(join(project, "src", "app.ts"), "export const a = 2;\n");
  process.env.BERNSTEIN_ATTEST_HOME = home;
  mkdirSync(join(home, ".config", "bernstein-attest"), { recursive: true });
  writeFileSync(keyPath(), JSON.stringify(TEST_JWK), { mode: 0o600 });
});
afterEach(() => { delete process.env.BERNSTEIN_ATTEST_HOME; rmSync(home, { recursive: true, force: true }); rmSync(project, { recursive: true, force: true }); });

/** Rewrites fixture paths onto the temp project so the path policy sees real files. */
function inProject(p: any) {
  const s = JSON.stringify(p).replaceAll("/work/demo", project);
  return JSON.parse(s);
}

describe("normalise", () => {
  it("maps both agents' PostToolUse and Stop payloads onto one shape", () => {
    const cc = normalise("claude-code", fx("cc-posttooluse-write"));
    expect(cc).toMatchObject({ kind: "tool", sessionId: "cc-sess-1", toolName: "Write", toolUseId: "toolu_01A", ok: true });
    const fail = normalise("claude-code", fx("cc-posttoolusefailure-bash"));
    expect(fail).toMatchObject({ kind: "tool", toolName: "Bash", ok: false });
    const cx = normalise("codex", fx("codex-posttooluse-apply-patch"));
    expect(cx).toMatchObject({ kind: "tool", sessionId: "cx-sess-1", toolName: "apply_patch", model: "gpt-5.5", ok: true });
    expect(normalise("codex", fx("codex-stop"))).toMatchObject({ kind: "stop", lastMessage: "Patched src/app.ts." });
    expect(normalise("claude-code", fx("cc-sessionend"))).toMatchObject({ kind: "end", reason: "other" });
    expect(normalise("claude-code", { hook_event_name: "PreToolUse", session_id: "x" })).toEqual({ kind: "ignore" });
    expect(normalise("claude-code", "not json")).toEqual({ kind: "ignore" });
  });
});

describe("helpers", () => {
  it("keeps paths inside the project, hashes the rest", () => {
    expect(pathPolicy("/work/demo", "/work/demo/src/a.ts")).toEqual({ path: "src/a.ts" });
    expect(pathPolicy("/work/demo", "src/a.ts")).toEqual({ path: "src/a.ts" });
    expect(pathPolicy("/work/demo", "/work/demo/../secret.txt")).toEqual({ path_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(pathPolicy("/work/demo", "/etc/passwd")).toEqual({ path_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });
  it("reduces a command to its first token", () => {
    expect(commandHead("/usr/bin/git status --short")).toBe("git");
    expect(commandHead("  npm test")).toBe("npm");
    expect(commandHead("x".repeat(50) + " y")).toHaveLength(32);
    expect(commandHead("")).toBe("");
  });
  it("finds the files a call wrote", () => {
    expect(writePaths("claude-code", "Write", { file_path: "/w/a.ts", content: "" })).toEqual(["/w/a.ts"]);
    expect(writePaths("claude-code", "NotebookEdit", { notebook_path: "/w/n.ipynb" })).toEqual(["/w/n.ipynb"]);
    expect(writePaths("claude-code", "Read", { file_path: "/w/a.ts" })).toEqual([]);
    expect(writePaths("claude-code", "Bash", { command: "echo > x" })).toEqual([]);
    expect(writePaths("codex", "apply_patch", fx("codex-posttooluse-apply-patch").tool_input)).toEqual(["src/app.ts", "docs/note.md"]);
  });
  it("builds the verify link and the Markdown block", () => {
    expect(verifyUrl("ab".repeat(32), null)).toBe(`https://mcp.bernstein.run/verify/${"ab".repeat(32)}`);
    expect(verifyUrl("ab".repeat(32), "https://raw.githubusercontent.com/o/r/main/.bernstein/receipts/x.json"))
      .toBe(`https://mcp.bernstein.run/verify/${"ab".repeat(32)}?from=https%3A%2F%2Fraw.githubusercontent.com%2Fo%2Fr%2Fmain%2F.bernstein%2Freceipts%2Fx.json`);
    expect(markdownBlock({ url: "https://mcp.bernstein.run/verify/x", toolCalls: 3, files: 1 }))
      .toBe("Session receipt: [verify](https://mcp.bernstein.run/verify/x) · 3 tool calls · 1 file · signed");
  });
});

describe("handleHook end to end", () => {
  it("journals a Claude Code session and seals a valid receipt on Stop", async () => {
    for (const name of ["cc-posttooluse-write", "cc-posttooluse-bash", "cc-posttooluse-mcp", "cc-posttoolusefailure-bash"]) {
      const r = await handleHook("claude-code", inProject(fx(name)), { now });
      expect(r).toEqual({ stdout: "", exitCode: 0 });
    }
    const stop = await handleHook("claude-code", inProject(fx("cc-stop")), { now });
    const msg = JSON.parse(stop.stdout);
    expect(msg.systemMessage).toMatch(/^Session receipt sealed: 4 tool calls, 1 file\. File: \.bernstein\/receipts\/cc-sess-1\.json\. Verify: https:\/\/mcp\.bernstein\.run\/verify\/[0-9a-f]{64}/);
    const meta = readMeta("claude-code", "cc-sess-1")!;
    const rows = readRows(meta);
    expect(rows.map((r) => r.event)).toEqual(["session_started", "tool_call", "tool_call", "tool_call", "tool_call", "turn_ended"]);
    expect(rows[1]).toMatchObject({ tool: "Write", path: "src/app.ts", ok: true });
    expect(rows[2]).toMatchObject({ tool: "Bash", command_head: "git", ok: true });
    expect(rows[2]).not.toHaveProperty("path");
    expect(rows[3]).toMatchObject({ tool: "mcp__bernstein__verify_receipt", agent_id: "agent-7", agent_type: "Explore" });
    expect(rows[4]).toMatchObject({ tool: "Bash", command_head: "npm", ok: false });
    expect(JSON.stringify(rows)).not.toContain("git status --short");
    expect(JSON.stringify(rows)).not.toContain(project);
    const file = join(project, ".bernstein", "receipts", "cc-sess-1.json");
    expect(existsSync(file)).toBe(true);
    expect(existsSync(join(receiptsDir(), "cc-sess-1.json"))).toBe(true);
    const v = await verifyReceipt(readFileSync(file, "utf8"));
    expect(v.verdict).toBe("valid");
    expect(v.summary?.producer).toBe(`bernstein-attest ${PRODUCER_VERSION} (claude-code)`);
    expect(v.summary?.tool_calls).toBe(4);
    const { explainReceipt } = await import("../../src/verify/explain.js");
    expect(explainReceipt(v)).toContain(`Session receipt from Claude Code, written by bernstein-attest ${PRODUCER_VERSION}: 4 tool calls, 1 file touched.`);
    expect(v.summary?.spine_entries).toBe(1);
    expect(meta.sealed_index).toBe(5);
    // A second Stop with nothing new: no reseal, no message.
    const again = await handleHook("claude-code", inProject(fx("cc-stop")), { now });
    expect(again.stdout).toBe("");
    // SessionEnd appends session_ended and reseals silently.
    const end = await handleHook("claude-code", inProject(fx("cc-sessionend")), { now });
    expect(end.stdout).toBe("");
    const v2 = await verifyReceipt(readFileSync(file, "utf8"));
    expect(v2.summary?.journal_events).toBe(7);
    expect(v2.verdict).toBe("valid");
  });

  it("journals a Codex session, tracking apply_patch files and the model", async () => {
    await handleHook("codex", inProject(fx("codex-posttooluse-apply-patch")), { now });
    await handleHook("codex", inProject(fx("codex-posttooluse-shell")), { now });
    const stop = await handleHook("codex", inProject(fx("codex-stop")), { now });
    expect(JSON.parse(stop.stdout).systemMessage).toContain("2 tool calls, 2 files");
    const file = join(project, ".bernstein", "receipts", "cx-sess-1.json");
    const doc = JSON.parse(readFileSync(file, "utf8"));
    expect(doc.producer).toMatchObject({ name: "bernstein-attest", agent: "codex" });
    expect(doc.spine.entries.map((e: any) => [e.artifact_path, e.model, e.content_hash.startsWith("sha256:")])).toEqual([["src/app.ts", "gpt-5.5", true], ["docs/note.md", "gpt-5.5", true]]);
    expect(doc.spine.entries[1].content_hash).toBe("sha256:missing");
    expect((await verifyReceipt(readFileSync(file, "utf8"))).verdict).toBe("valid");
  });

  it("throttles the notice to once per 10 minutes unless the file set changed", async () => {
    await handleHook("claude-code", inProject(fx("cc-posttooluse-bash")), { now });
    expect(JSON.parse((await handleHook("claude-code", inProject(fx("cc-stop")), { now })).stdout).systemMessage).toBeDefined();
    await handleHook("claude-code", inProject(fx("cc-posttooluse-bash")), { now });
    expect((await handleHook("claude-code", inProject(fx("cc-stop")), { now })).stdout).toBe("");
    await handleHook("claude-code", inProject(fx("cc-posttooluse-write")), { now });   // new file → notice again
    expect((await handleHook("claude-code", inProject(fx("cc-stop")), { now })).stdout).not.toBe("");
    t += 601;
    await handleHook("claude-code", inProject(fx("cc-posttooluse-bash")), { now });
    expect((await handleHook("claude-code", inProject(fx("cc-stop")), { now })).stdout).not.toBe("");
  });

  it("rolls into a second segment at 2000 rows and both receipts verify", async () => {
    const bash = inProject(fx("cc-posttooluse-bash"));
    for (let i = 0; i < SEGMENT_ROWS - 1; i++) await handleHook("claude-code", { ...bash, tool_use_id: `t${i}` }, { now });
    let meta = readMeta("claude-code", "cc-sess-1")!;
    expect(meta.segment).toBe(2);
    expect(meta.prev_receipt_sha256).toMatch(/^[0-9a-f]{64}$/);
    // Right after the rollover and before the next Stop, meta.last_verify_url still
    // names segment 1's receipt (2000 rows, 1999 of them tool calls, no files touched
    // by a Bash-only run) — the snapshot counts must describe that receipt, not the
    // fresh segment 2 journal, which so far holds only its one segment_started row.
    expect(meta.last_receipt_tool_calls).toBe(SEGMENT_ROWS - 1);
    expect(meta.last_receipt_files).toBe(0);
    expect(readRows(meta)).toHaveLength(1);
    const seg1 = readFileSync(join(project, ".bernstein", "receipts", "cc-sess-1.json"), "utf8");
    const v1 = await verifyReceipt(seg1);
    expect(v1.verdict).toBe("valid");
    expect(v1.summary?.journal_events).toBe(SEGMENT_ROWS);
    expect(v1.receipt_sha256).toBe(meta.prev_receipt_sha256);
    await handleHook("claude-code", inProject(fx("cc-stop")), { now });
    meta = readMeta("claude-code", "cc-sess-1")!;
    const seg2 = readFileSync(join(project, ".bernstein", "receipts", "cc-sess-1-s2.json"), "utf8");
    const v2 = await verifyReceipt(seg2);
    expect(v2.verdict).toBe("valid");
    expect(v2.summary?.run_id).toBe("cc-sess-1-s2");
    expect(JSON.parse(seg2).journal.events[0]).toMatchObject({ event: "segment_started", segment: 2, prev_receipt_sha256: v1.receipt_sha256 });
  }, 60_000);

  it("never throws: a payload that cannot be journaled is logged and exits 0", async () => {
    const r = await handleHook("claude-code", { hook_event_name: "PostToolUse", session_id: "", cwd: project, tool_name: "Bash", tool_input: null, tool_use_id: "x" }, { now });
    expect(r).toEqual({ stdout: "", exitCode: 0 });
  });

  it("stays under budget with a 100 KB tool output", async () => {
    const big = inProject(fx("cc-posttooluse-bash"));
    big.tool_response.stdout = "x".repeat(100 * 1024);
    await handleHook("claude-code", big, { now }); // warm: creates the session
    const t0 = performance.now();
    await handleHook("claude-code", { ...big, tool_use_id: "t-big" }, { now });
    expect(performance.now() - t0).toBeLessThan(50);
  });
});
