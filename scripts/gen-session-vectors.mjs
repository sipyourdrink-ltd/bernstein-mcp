#!/usr/bin/env node
// Regenerates vectors/session/*.json from the hook fixtures with a fixed
// key and a fixed clock. Run after any change to the receipt shape:
//   node scripts/gen-session-vectors.mjs && npx vitest run test/cli/session-vectors.test.ts
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";

const root = new URL("..", import.meta.url).pathname;
const out = join(root, "vectors", "session");
mkdirSync(out, { recursive: true });

// Bundle the hook once so this script needs no ts loader. Entry points are
// given explicit `out` names so both land flat in `tmp` (esbuild's default
// naming would otherwise mirror each entry's source directory under the
// lowest common ancestor of the two entry points, i.e. cli/hook.js and
// src/verify/receipt.js).
const tmp = mkdtempSync(join(tmpdir(), "gen-vectors-"));
await build({
  entryPoints: [
    { in: join(root, "cli", "hook.ts"), out: "hook" },
    { in: join(root, "src", "verify", "receipt.ts"), out: "receipt" },
  ],
  outdir: tmp,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  logLevel: "silent",
});
const { handleHook } = await import(join(tmp, "hook.js"));
const { verifyReceipt } = await import(join(tmp, "receipt.js"));

const TEST_JWK = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A" };
const fx = (name) => readFileSync(join(root, "test", "cli", "fixtures", `${name}.json`), "utf8");
const SEGMENT_ROWS = 2000; // mirrors cli/paths.ts

async function session(steps) {
  const home = mkdtempSync(join(tmpdir(), "vec-home-"));
  // The project directory must be a FIXED path, not a fresh mkdtemp one:
  // the Write fixture's tool_input.file_path / tool_response.filePath carry
  // "/work/demo", which gets replaceAll'd to this project path below, and
  // that raw (pre-pathPolicy) JSON is what input_sha256/output_sha256 hash.
  // A random mkdtemp suffix there would leak into those digests — and, via
  // the journal's hash chain, into every event_hash after it — even though
  // the row's own displayed "path" field is already project-relative. The
  // basename must also be the fixed string "demo": it lands verbatim in
  // the session_started row's "project" field.
  //
  // This must also be the same absolute path on every host that regenerates
  // these vectors — os.tmpdir() varies per machine/user (e.g. macOS's
  // /var/folders/...), and since that path is part of the hashed tool
  // input, a run on CI or another laptop would otherwise rewrite every
  // hash with no way to tell "receipt shape changed" from "machine
  // changed". Windows is not a supported generator host.
  const project = "/tmp/bernstein-attest-vectors/demo";
  rmSync(project, { recursive: true, force: true });
  mkdirSync(join(project, "src"), { recursive: true });
  writeFileSync(join(project, "src", "app.ts"), "export const a = 2;\n");
  mkdirSync(join(home, ".config", "bernstein-attest"), { recursive: true });
  writeFileSync(join(home, ".config", "bernstein-attest", "key.jwk"), JSON.stringify(TEST_JWK));
  process.env.BERNSTEIN_ATTEST_HOME = home;
  let t = 1_700_000_000;
  const now = () => t++;
  // Only CLAUDE_PROJECT_DIR is passed — not a spread of process.env — so
  // the machine's own ANTHROPIC_MODEL can never leak into meta.model (it
  // falls back to "unknown", which is what session-valid's summary pins).
  const env = { CLAUDE_PROJECT_DIR: project };
  for (const [name, patch] of steps) {
    const payload = JSON.parse(fx(name).replaceAll("/work/demo", project));
    await handleHook("claude-code", { ...payload, ...patch }, { now, env });
  }
  const read = (id) => readFileSync(join(project, ".bernstein", "receipts", `${id}.json`), "utf8");
  const done = () => { rmSync(home, { recursive: true, force: true }); rmSync(project, { recursive: true, force: true }); };
  return { read, done };
}

async function expected(text, extra = {}) {
  const v = await verifyReceipt(text);
  return { verdict: v.verdict, failing_check: v.failing_check, divergent_step: v.divergent_step, receipt_sha256: v.receipt_sha256, summary: v.summary, ...extra };
}

function emit(name, description, receipt_text, exp) {
  writeFileSync(join(out, `${name}.json`), JSON.stringify({ name, description, input: { receipt_text }, expected: exp }, null, 2) + "\n");
  console.log(`${name}: ${exp.verdict} ${exp.receipt_sha256}`);
}

{
  const s = await session([["cc-posttooluse-write", {}], ["cc-posttooluse-bash", {}], ["cc-posttooluse-mcp", {}], ["cc-posttoolusefailure-bash", {}], ["cc-stop", {}], ["cc-sessionend", {}]]);
  const text = s.read("cc-sess-1");
  emit("session-valid", "Claude Code session: Write, Bash, MCP call, one failed Bash, Stop, SessionEnd", text, await expected(text));
  const tampered = text.replace('"ok": true', '"ok": false');
  if (tampered === text) throw new Error("tamper did not apply");
  emit("session-tampered", "session-valid with the first tool_call's ok flag flipped", tampered, await expected(tampered));
  s.done();
}
{
  const steps = [];
  for (let i = 0; i < SEGMENT_ROWS; i++) steps.push(["cc-posttooluse-bash", { tool_use_id: `t${i}` }]);
  steps.push(["cc-stop", {}]);
  const s = await session(steps);
  const seg1 = await verifyReceipt(s.read("cc-sess-1"));
  const text = s.read("cc-sess-1-s2");
  const first = JSON.parse(text).journal.events[0];
  emit("session-segmented-2", "second segment of a 2001-row session; its first row names the first segment's receipt", text, await expected(text, { first_event: { event: first.event, segment: first.segment, prev_receipt_sha256: first.prev_receipt_sha256 }, segment_1_sha256: seg1.receipt_sha256 }));
  s.done();
}
rmSync(tmp, { recursive: true, force: true });
