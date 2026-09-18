/// <reference types="node" />
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { PRODUCER_NAME, PRODUCER_VERSION } from "../../cli/version.js";

describe("cli version", () => {
  it("names the producer and tracks cli/package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../cli/package.json", import.meta.url), "utf8"));
    expect(PRODUCER_NAME).toBe("bernstein-attest");
    expect(PRODUCER_VERSION).toBe(pkg.version);
    expect(pkg.bin).toEqual({ "bernstein-attest": "dist/attest.js" });
    expect(pkg.files).toEqual(["dist"]);
    expect(pkg.dependencies).toBeUndefined();
  });
});
