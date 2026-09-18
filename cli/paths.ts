import { homedir } from "node:os";
import { join } from "node:path";

/** `BERNSTEIN_ATTEST_HOME` relocates every file the tool touches (tests, containers). */
export function homeDir(): string {
  return process.env.BERNSTEIN_ATTEST_HOME || homedir();
}
export const SEGMENT_ROWS = 2000;
export const keyPath = () => join(homeDir(), ".config", "bernstein-attest", "key.jwk");
export const statePath = () => join(homeDir(), ".local", "state", "bernstein-attest");
export const bundlePath = () => join(homeDir(), ".local", "share", "bernstein-attest", "attest.js");
export const logPath = () => join(statePath(), "attest.log");
export const sessionDir = (agent: string) => join(statePath(), "sessions", agent);
export const receiptsDir = () => join(statePath(), "receipts");
export function claudeSettingsPath(scope: "user" | "project", projectDir = process.cwd()): string {
  return scope === "user" ? join(homeDir(), ".claude", "settings.json") : join(projectDir, ".claude", "settings.json");
}
export function codexHooksPath(scope: "user" | "project", projectDir = process.cwd()): string {
  return scope === "user" ? join(homeDir(), ".codex", "hooks.json") : join(projectDir, ".codex", "hooks.json");
}
