import { readFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vitest/config";

// Wrangler's default module rules treat "*.txt" as a Text module: the
// import's default export is the file's raw contents as a string (no `?raw`
// suffix). Vite's own default asset handling would instead turn an
// unsuffixed "*.txt" import into a URL string, so this plugin teaches
// vitest the same convention wrangler already uses, with `enforce: "pre"`
// so it runs ahead of Vite's built-in asset plugin.
function rawTextModules(): Plugin {
  return {
    name: "wrangler-module-rules",
    enforce: "pre",
    load(id) {
      if (id.endsWith(".txt")) {
        const content = readFileSync(id, "utf-8");
        return `export default ${JSON.stringify(content)};`;
      }
      if (id.endsWith(".woff2")) {
        // Data module: default export is the file's bytes as an ArrayBuffer.
        const b64 = readFileSync(id).toString("base64");
        return `const b = atob(${JSON.stringify(b64)}); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); export default u.buffer;`;
      }
      return undefined;
    },
  };
}

export default defineConfig({
  plugins: [rawTextModules()],
  test: {
    include: ["test/**/*.test.ts"],
    watch: false,
  },
});
