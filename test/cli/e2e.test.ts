/// <reference types="node" />
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyReceipt } from "../../src/verify/receipt.js";
import { TEST_JWK } from "./fixtures/test-key.js";

const BUNDLE = join(process.cwd(), "cli", "dist", "attest.js");
const fx = (name: string) => readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8");
let home: string; let project: string;

beforeAll(() => {
  execFileSync("node", ["scripts/build-cli.mjs"], { stdio: "ignore" });
  home = mkdtempSync(join(tmpdir(), "attest-home-"));
  project = mkdtempSync(join(tmpdir(), "attest-proj-"));
  mkdirSync(join(home, ".config", "bernstein-attest"), { recursive: true });
  writeFileSync(join(home, ".config", "bernstein-attest", "key.jwk"), JSON.stringify(TEST_JWK));
});
afterAll(() => { rmSync(home, { recursive: true, force: true }); rmSync(project, { recursive: true, force: true }); });

const run = (args: string[], input = "") =>
  spawnSync("node", [BUNDLE, ...args], { input, encoding: "utf8", env: { ...process.env, BERNSTEIN_ATTEST_HOME: home, CLAUDE_PROJECT_DIR: project } });

describe("bundle", () => {
  it("is one file with no external requires", () => {
    const src = readFileSync(BUNDLE, "utf8");
    expect(src.startsWith("#!/usr/bin/env node")).toBe(true);
    expect(src).not.toMatch(/require\("(?!node:)[a-z@][^"]*"\)/);
  });
  it("hook: journals from stdin, seals on Stop, exits 0 on garbage", () => {
    const write = fx("cc-posttooluse-write").replaceAll("/work/demo", project);
    expect(run(["hook", "--agent", "claude-code"], write)).toMatchObject({ status: 0, stdout: "", stderr: "" });
    const stop = run(["hook", "--agent", "claude-code"], fx("cc-stop").replaceAll("/work/demo", project));
    expect(stop.status).toBe(0);
    expect(JSON.parse(stop.stdout).systemMessage).toContain("Session receipt sealed: 1 tool call, 1 file.");
    expect(existsSync(join(project, ".bernstein", "receipts", "cc-sess-1.json"))).toBe(true);
    expect(run(["hook", "--agent", "claude-code"], "{not json")).toMatchObject({ status: 0, stdout: "" });
  });
  it("verify: rates the sealed receipt valid and a tampered copy invalid", () => {
    const file = join(project, ".bernstein", "receipts", "cc-sess-1.json");
    expect(run(["verify", file])).toMatchObject({ status: 0 });
    expect(run(["verify", file]).stdout).toMatch(/^valid/);
    const bad = join(project, "bad.json");
    writeFileSync(bad, readFileSync(file, "utf8").replace('"ok": true', '"ok": false'));
    expect(run(["verify", bad])).toMatchObject({ status: 1 });
  });
  it("link and status read the same session back", () => {
    const link = run(["link"]);
    expect(link.stdout).toMatch(/^https:\/\/mcp\.bernstein\.run\/verify\/[0-9a-f]{64}/m);
    expect(link.stdout).toContain("Session receipt: [verify](");
    expect(run(["status"]).stdout).toContain("cc-sess-1");
  });
  it("init --dry-run --project prints the merged settings without writing", () => {
    const r = run(["init", "--claude-code", "--project", "--dry-run"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('"PostToolUse"');
    expect(existsSync(join(project, ".claude", "settings.json"))).toBe(false);
  });
  it("eight concurrent hook processes of one session leave one unbroken chain", async () => {
    const home2 = mkdtempSync(join(tmpdir(), "attest-home-"));
    const project2 = mkdtempSync(join(tmpdir(), "attest-proj-"));
    mkdirSync(join(home2, ".config", "bernstein-attest"), { recursive: true });
    writeFileSync(join(home2, ".config", "bernstein-attest", "key.jwk"), JSON.stringify(TEST_JWK));
    const env = { ...process.env, BERNSTEIN_ATTEST_HOME: home2, CLAUDE_PROJECT_DIR: project2 };
    const hook = (input: string) => new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      const child = execFile("node", [BUNDLE, "hook", "--agent", "claude-code"], { env, encoding: "utf8" }, (err, stdout, stderr) => (err ? reject(err) : resolve({ stdout, stderr })));
      child.stdin!.end(input);
    });
    try {
      const base = JSON.parse(fx("cc-posttooluse-bash").replaceAll("/work/demo", project2));
      const results = await Promise.all(Array.from({ length: 8 }, (_, i) => hook(JSON.stringify({ ...base, tool_use_id: `par-${i}` }))));
      for (const r of results) expect(r).toEqual({ stdout: "", stderr: "" });
      const stop = await hook(fx("cc-stop").replaceAll("/work/demo", project2));
      expect(stop.stderr).toBe("");
      const file = join(project2, ".bernstein", "receipts", "cc-sess-1.json");
      const v = await verifyReceipt(readFileSync(file, "utf8"));
      expect(v.verdict).toBe("valid");
      expect(v.summary?.tool_calls).toBe(8);
      const events = JSON.parse(readFileSync(file, "utf8")).journal.events as { index: number }[];
      expect(events.map((e) => e.index)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const log = join(home2, ".local", "state", "bernstein-attest", "attest.log");
      expect(existsSync(log) ? readFileSync(log, "utf8") : "").toBe("");
    } finally {
      rmSync(home2, { recursive: true, force: true });
      rmSync(project2, { recursive: true, force: true });
    }
  }, 30_000);
  it("a hook round trip stays under 250 ms wall clock", () => {
    const write = fx("cc-posttooluse-bash").replaceAll("/work/demo", project);
    const t0 = performance.now();
    run(["hook", "--agent", "claude-code"], write);
    expect(performance.now() - t0).toBeLessThan(250);
  });
});
