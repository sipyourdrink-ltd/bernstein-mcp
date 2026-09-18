// One Ed25519 key per machine, generated on first use and never sent
// anywhere: the public half travels inside every receipt (trust on first
// use, exactly like a bernstein install's key). WebCrypto only, so the
// signature construction is the same code path the verifier checks.
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { jwkThumbprint } from "../src/verify/attest.js";
import { sha256HexOfString } from "../src/verify/chains.js";
import { bytesToBase64 } from "../src/verify/receipt.js";

export interface PrivateJwk { kty: "OKP"; crv: "Ed25519"; x: string; d: string }
export interface AttestKey {
  privateKey: CryptoKey;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string; kid: string; alg: "EdDSA" };
  keyId: string;
}

export function keyIdOf(x: string): string {
  return "bernstein-attest-" + sha256HexOfString(x).slice(0, 8);
}

export async function importKey(jwk: PrivateJwk): Promise<AttestKey> {
  const privateKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, { name: "Ed25519" }, false, ["sign"]);
  return {
    privateKey,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: jwkThumbprint(jwk.x), alg: "EdDSA" },
    keyId: keyIdOf(jwk.x),
  };
}

export async function generateKeyFile(path: string): Promise<AttestKey> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const exported = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as { x?: string; d?: string };
  if (!exported.x || !exported.d) throw new Error("key export failed");
  const jwk: PrivateJwk = { kty: "OKP", crv: "Ed25519", x: exported.x, d: exported.d };
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(jwk) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return importKey(jwk);
}

export async function loadKeyFile(path: string): Promise<AttestKey | null> {
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch { return null; }
  try {
    const jwk = JSON.parse(text) as Partial<PrivateJwk>;
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || typeof jwk.d !== "string") return null;
    return await importKey(jwk as PrivateJwk);
  } catch { return null; }
}

export async function loadOrCreateKey(path: string): Promise<AttestKey> {
  return (await loadKeyFile(path)) ?? generateKeyFile(path);
}

export async function sign(key: AttestKey, message: Uint8Array): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, message as BufferSource));
  return bytesToBase64(sig);
}
