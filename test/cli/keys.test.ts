/// <reference types="node" />
import { describe, expect, it } from "vitest";
import { mkdtempSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyFile, importKey, loadKeyFile, loadOrCreateKey, sign } from "../../cli/keys.js";
import { jwkThumbprint } from "../../src/verify/attest.js";
import { TEST_JWK } from "./fixtures/test-key.js";

describe("attest key", () => {
  it("generates a 0600 JWK file and reloads the same public key", async () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-key-"));
    const path = join(dir, "sub", "key.jwk");
    const made = await generateKeyFile(path);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const jwk = JSON.parse(readFileSync(path, "utf8"));
    expect(jwk).toMatchObject({ kty: "OKP", crv: "Ed25519" });
    expect(typeof jwk.d).toBe("string");
    const back = await loadKeyFile(path);
    expect(back?.publicJwk).toEqual(made.publicJwk);
    expect(made.publicJwk.kid).toBe(jwkThumbprint(made.publicJwk.x));
    expect(made.keyId).toMatch(/^bernstein-attest-[0-9a-f]{8}$/);
    expect(await loadOrCreateKey(path)).toMatchObject({ keyId: made.keyId });
  });

  it("returns null for a missing or malformed file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-key-"));
    expect(await loadKeyFile(join(dir, "none.jwk"))).toBeNull();
    const bad = join(dir, "bad.jwk");
    require("node:fs").writeFileSync(bad, "{}");
    expect(await loadKeyFile(bad)).toBeNull();
  });

  it("signs with a signature WebCrypto verifies against the public JWK", async () => {
    const key = await importKey(TEST_JWK);
    const msg = new TextEncoder().encode("DSSEv1 …");
    const sigB64 = await sign(key, msg);
    const sig = Uint8Array.from(Buffer.from(sigB64, "base64"));
    expect(sig.length).toBe(64);
    const pub = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: TEST_JWK.x }, { name: "Ed25519" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, msg)).toBe(true);
  });
});
