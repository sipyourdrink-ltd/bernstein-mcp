import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { VERIFIER_URL } from "../src/verify/attest.js";

const read = (name: string) => JSON.parse(readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url).href), "utf8"));

describe("registry manifest", () => {
  it("server.json advertises this deployment and tracks the package version", () => {
    const server = read("server.json");
    const pkg = read("package.json");
    expect(server.name).toBe("io.github.sipyourdrink-ltd/bernstein-mcp");
    expect(server.version).toBe(pkg.version);
    expect(server.remotes).toEqual([{ type: "streamable-http", url: `${VERIFIER_URL}/mcp` }]);
    expect(server.packages).toBeUndefined();
    expect(server.description.length).toBeLessThanOrEqual(100);
  });

  it("root, server.json and the CLI share one version", () => {
    const root = JSON.parse(readFileSync("package.json", "utf8"));
    const server = JSON.parse(readFileSync("server.json", "utf8"));
    const cli = JSON.parse(readFileSync("cli/package.json", "utf8"));
    expect(server.version).toBe(root.version);
    expect(cli.version).toBe(root.version);
    expect(cli.name).toBe("bernstein-attest");
    expect(cli.bin).toEqual({ "bernstein-attest": "dist/attest.js" });
    expect(cli.files).toEqual(["dist"]);
  });
});
