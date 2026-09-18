/// <reference types="node" />
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hookCommand, init, mergeClaudeSettings, mergeCodexHooks, removeOurHooks, status, uninstall } from "../../cli/install.js";
import { bundlePath, claudeSettingsPath, codexHooksPath, keyPath } from "../../cli/paths.js";
import { appendRow, journalPath, newMeta, writeMeta } from "../../cli/store.js";

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
    expect(rep.notices).toEqual(["Codex: run /hooks inside codex once to review and trust the new hooks."]);
    const again = await init({ claudeCode: true, codex: true, scope: "user", projectDir: project, dryRun: false, bundleSource: bundleSrc });
    expect(again.keyCreated).toBe(false);
    expect(again.changes).toEqual([]);
    expect(again.notices).toEqual([]);
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
    expect(existsSync(join(project, ".claude", "settings.json"))).toBe(false);
    expect(existsSync(join(project, ".claude", "settings.local.json"))).toBe(false);
    expect(existsSync(bundlePath())).toBe(false);
    expect(rep.changes[0].after).toContain('"Stop"');
    expect(rep.changes[0].backup).toBeNull();
    expect(rep.notices).toEqual([]);
  });
  it("project scope: Claude Code hooks go to the personal settings file, Codex hooks to .codex/hooks.json with a notice", async () => {
    // The hook command names a file under the home directory, so it must not land in the
    // file a project commits; Claude Code keeps personal settings in settings.local.json.
    expect(claudeSettingsPath("project", "/p")).toBe(join("/p", ".claude", "settings.local.json"));
    expect(claudeSettingsPath("user")).toBe(join(home, ".claude", "settings.json"));
    expect(codexHooksPath("project", "/p")).toBe(join("/p", ".codex", "hooks.json"));
    const rep = await init({ claudeCode: true, codex: true, scope: "project", projectDir: project, dryRun: false, bundleSource: bundleSrc });
    expect(rep.changes.map((c) => c.file)).toEqual([join(project, ".claude", "settings.local.json"), join(project, ".codex", "hooks.json")]);
    expect(existsSync(join(project, ".claude", "settings.json"))).toBe(false);
    expect(JSON.parse(readFileSync(join(project, ".claude", "settings.local.json"), "utf8")).hooks.Stop[0].hooks[0].command).toBe(hookCommand("claude-code", bundlePath()));
    expect(rep.notices).toEqual([
      "Codex: run /hooks inside codex once to review and trust the new hooks.",
      "Codex: .codex/hooks.json names a file under your home directory; keep it out of version control.",
    ]);
    expect(status(project).hooks.map((h) => h.file)).toEqual([join(project, ".claude", "settings.local.json"), join(project, ".codex", "hooks.json")]);
    const again = await init({ claudeCode: true, codex: true, scope: "project", projectDir: project, dryRun: false, bundleSource: bundleSrc });
    expect(again.changes).toEqual([]);
    expect(again.notices).toEqual([]);
    const removed = uninstall({ scope: "project", projectDir: project, dryRun: false });
    expect(removed.map((c) => c.file)).toEqual([join(project, ".claude", "settings.local.json"), join(project, ".codex", "hooks.json")]);
    expect(JSON.parse(readFileSync(join(project, ".claude", "settings.local.json"), "utf8"))).toEqual({});
    expect(existsSync(join(project, ".claude", "settings.json"))).toBe(false);
  });
  it("refuses to touch a settings file that isn't valid JSON", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const bad = '{"permissions": {"allow": ["Bash"]},}'; // trailing comma
    writeFileSync(claudeSettingsPath("user"), bad);
    await expect(init({ claudeCode: true, codex: false, scope: "user", projectDir: project, dryRun: false, bundleSource: bundleSrc }))
      .rejects.toThrow(/not valid JSON/);
    expect(readFileSync(claudeSettingsPath("user"), "utf8")).toBe(bad);
    expect(readdirSync(join(home, ".claude")).some((f) => f.includes(".bak-"))).toBe(false);
  });
  it("keeps reporting other sessions when one journal is damaged", () => {
    const meta = newMeta({ agent: "claude-code", session_id: "dead-beef", project_root: project, project: "p", model: "m" });
    appendRow(meta, { event: "session_started", agent: "claude-code", producer: "x", project: "p", cwd_sha256: "c".repeat(64), ts: 1 });
    writeMeta(meta);
    appendFileSync(journalPath(meta), '{"truncated'); // no trailing newline, no closing brace
    expect(() => status(project)).not.toThrow();
    const st = status(project);
    expect(st.sessions).toContainEqual({ agent: "claude-code", sessionId: "dead-beef", rows: -1, segment: 1, lastRunId: "" });
  });
});
