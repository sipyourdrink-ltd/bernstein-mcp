/// <reference types="node" />
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hookCommand, init, mergeClaudeSettings, mergeCodexHooks, removeOurHooks, status, uninstall } from "../../cli/install.js";
import { bundlePath, claudeSettingsPath, codexHooksPath, keyPath } from "../../cli/paths.js";

let home: string; let project: string; let bundleSrc: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "attest-home-"));
  project = mkdtempSync(join(tmpdir(), "attest-proj-"));
  process.env.BERNSTEIN_ATTEST_HOME = home;
  bundleSrc = join(project, "attest-src.js");
  writeFileSync(bundleSrc, "#!/usr/bin/env node\nconsole.log('stub')\n");
});
afterEach(() => { delete process.env.BERNSTEIN_ATTEST_HOME; rmSync(home, { recursive: true, force: true }); rmSync(project, { recursive: true, force: true }); });

describe("merge", () => {
  it("adds our four Claude Code hooks next to existing ones and is idempotent", () => {
    const existing = { permissions: { allow: ["Bash"] }, hooks: { PostToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo other" }] }] } };
    const once = mergeClaudeSettings(existing, "/b/attest.js");
    const twice = mergeClaudeSettings(once, "/b/attest.js");
    expect(twice).toEqual(once);
    expect(once.permissions).toEqual({ allow: ["Bash"] });
    const hooks = once.hooks as Record<string, any[]>;
    expect(hooks.PostToolUse).toHaveLength(2);
    expect(hooks.PostToolUse[0].hooks[0].command).toBe("echo other");
    expect(hooks.PostToolUse[1]).toEqual({ matcher: "*", hooks: [{ type: "command", command: hookCommand("claude-code", "/b/attest.js"), timeout: 20 }] });
    expect(hooks.PostToolUseFailure[0].matcher).toBe("*");
    expect(hooks.Stop[0]).toEqual({ matcher: "", hooks: [{ type: "command", command: hookCommand("claude-code", "/b/attest.js"), timeout: 30 }] });
    expect(hooks.SessionEnd[0].hooks[0].timeout).toBe(5);
    expect(hookCommand("claude-code", "/b/attest.js")).toBe('node "/b/attest.js" hook --agent claude-code');
  });
  it("adds the three Codex hooks with the 3 s SessionEnd cap", () => {
    const out = mergeCodexHooks(undefined, "/b/attest.js") as any;
    expect(Object.keys(out.hooks)).toEqual(["PostToolUse", "Stop", "SessionEnd"]);
    expect(out.hooks.SessionEnd[0].hooks[0]).toEqual({ type: "command", command: hookCommand("codex", "/b/attest.js"), timeout: 3 });
    expect(out.hooks.PostToolUse[0]).not.toHaveProperty("matcher");
  });
  it("removes only our entries", () => {
    const merged = mergeClaudeSettings({ hooks: { Stop: [{ matcher: "", hooks: [{ type: "command", command: "say done" }] }] } }, "/b/attest.js");
    const stripped = removeOurHooks(merged) as any;
    expect(stripped.hooks.Stop).toEqual([{ matcher: "", hooks: [{ type: "command", command: "say done" }] }]);
    expect(stripped.hooks.PostToolUse).toBeUndefined();
  });
});

describe("init / status / uninstall", () => {
  it("creates the key, copies the bundle, registers hooks with a backup, and reports", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(claudeSettingsPath("user"), JSON.stringify({ model: "opus" }));
    const rep = await init({ claudeCode: true, codex: true, scope: "user", projectDir: project, dryRun: false, bundleSource: bundleSrc });
    expect(rep.keyCreated).toBe(true);
    expect(rep.keyId).toMatch(/^bernstein-attest-/);
    expect(statSync(keyPath()).mode & 0o777).toBe(0o600);
    expect(readFileSync(bundlePath(), "utf8")).toContain("stub");
    expect(statSync(bundlePath()).mode & 0o111).not.toBe(0);
    const settings = JSON.parse(readFileSync(claudeSettingsPath("user"), "utf8"));
    expect(settings.model).toBe("opus");
    expect(settings.hooks.Stop[0].hooks[0].command).toBe(hookCommand("claude-code", bundlePath()));
    expect(readdirSync(join(home, ".claude")).some((f) => /^settings\.json\.bak-\d{8}T\d{6}$/.test(f))).toBe(true);
    expect(JSON.parse(readFileSync(codexHooksPath("user"), "utf8")).hooks.Stop).toHaveLength(1);
    expect(rep.changes.map((c) => c.file)).toEqual([claudeSettingsPath("user"), codexHooksPath("user")]);
    const again = await init({ claudeCode: true, codex: true, scope: "user", projectDir: project, dryRun: false, bundleSource: bundleSrc });
    expect(again.keyCreated).toBe(false);
    expect(again.changes).toEqual([]);
    const st = status(project);
    expect(st.keyId).toBe(rep.keyId);
    expect(st.hooks.map((h) => h.events)).toEqual([["PostToolUse", "PostToolUseFailure", "Stop", "SessionEnd"], ["PostToolUse", "Stop", "SessionEnd"]]);
    const removed = uninstall({ scope: "user", projectDir: project, dryRun: false });
    expect(removed).toHaveLength(2);
    expect(JSON.parse(readFileSync(claudeSettingsPath("user"), "utf8"))).toEqual({ model: "opus" });
    expect(existsSync(keyPath())).toBe(true);
  });
  it("dry-run writes nothing and shows the result", async () => {
    const rep = await init({ claudeCode: true, codex: false, scope: "project", projectDir: project, dryRun: true, bundleSource: bundleSrc });
    expect(existsSync(claudeSettingsPath("project", project))).toBe(false);
    expect(existsSync(bundlePath())).toBe(false);
    expect(rep.changes[0].after).toContain('"Stop"');
    expect(rep.changes[0].backup).toBeNull();
  });
});
