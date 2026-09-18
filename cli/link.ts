import { execFileSync } from "node:child_process";
import { VERIFIER_URL } from "../src/verify/attest.js";

export function verifyUrl(receiptSha256: string, from: string | null): string {
  const base = `${VERIFIER_URL}/verify/${receiptSha256}`;
  return from ? `${base}?from=${encodeURIComponent(from)}` : base;
}

function git(root: string, args: string[]): string | null {
  try { return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 2000 }).trim(); } catch { return null; }
}

/** GitHub raw URL of a file on the current branch, or null when the project is not a GitHub checkout. */
export function rawUrl(projectRoot: string, relFile: string): string | null {
  const remote = git(projectRoot, ["remote", "get-url", "origin"]);
  const branch = git(projectRoot, ["rev-parse", "--abbrev-ref", "HEAD"]);
  if (!remote || !branch || branch === "HEAD") return null;
  const m = remote.match(/github\.com[:/]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!m) return null;
  return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${encodeURIComponent(branch)}/${relFile.split("/").map(encodeURIComponent).join("/")}`;
}

export function markdownBlock(a: { url: string; toolCalls: number; files: number }): string {
  const n = (k: number, w: string) => `${k} ${w}${k === 1 ? "" : "s"}`;
  return `Session receipt: [verify](${a.url}) · ${n(a.toolCalls, "tool call")} · ${n(a.files, "file")} · signed`;
}
