// One self-contained CommonJS file: `npx bernstein-attest` runs it from the
// npm cache and `init` copies it to ~/.local/share/bernstein-attest/attest.js,
// where there is no package.json and no node_modules.
import { build } from "esbuild";
import { chmodSync } from "node:fs";

await build({
  entryPoints: ["cli/main.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  outfile: "cli/dist/attest.js",
  banner: { js: "#!/usr/bin/env node" },
  legalComments: "none",
  logLevel: "info",
});
chmodSync("cli/dist/attest.js", 0o755);
