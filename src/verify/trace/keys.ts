// The `cnf.jwk` confirmation key of a Trust Record: import, verify, identify.
//
// Supported: OKP/Ed25519 (EdDSA), EC/P-256 (ES256), EC/P-384 (ES384). JWS
// ECDSA signatures are raw r||s, which is the form WebCrypto's ECDSA verify
// takes. Anything else is reported as a key type this verifier cannot
// check, never as a forgery.

import { base64ToBytes, bytesToBase64 } from "../receipt.js";
import { fromParsed, jcs, utf8, JsonNumber, type JsonObject, type JsonValue } from "../pyjson.js";
import { sha256Hex } from "../chains.js";

/** RFC 7517 private members: a public JWK must carry none of them. */
export const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] as const;

export type KeyKind = "Ed25519" | "P-256" | "P-384";

export interface SupportedKey {
  kind: KeyKind;
  alg: "EdDSA" | "ES256" | "ES384";
  jwk: { kty: string; crv: string; x: string; y?: string };
}

export function isObject(v: JsonValue | undefined): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof JsonNumber);
}

/** The JWK at `record.cnf.jwk`, or null when the path is not an object. */
export function recordJwk(record: JsonObject): JsonObject | null {
  const cnf = record["cnf"];
  if (!isObject(cnf)) return null;
  const jwk = cnf["jwk"];
  return isObject(jwk) ? jwk : null;
}

/** Names the private member a JWK carries, or null when it is public-only. */
export function privateMember(jwk: JsonObject): string | null {
  for (const m of PRIVATE_JWK_MEMBERS) if (m in jwk) return m;
  return null;
}

/** A short label for an unsupported key ("RSA", "EC/secp256k1", "OKP/X25519", …). */
export function keyLabel(jwk: JsonObject): string {
  const kty = typeof jwk["kty"] === "string" ? jwk["kty"] : "?";
  const crv = typeof jwk["crv"] === "string" ? jwk["crv"] : null;
  return crv ? `${kty}/${crv}` : kty;
}

/** Classifies the key; null when it is not one of the three supported types. */
export function supportedKey(jwk: JsonObject): SupportedKey | null {
  const kty = jwk["kty"];
  const crv = jwk["crv"];
  const x = jwk["x"];
  const y = jwk["y"];
  if (typeof x !== "string") return null;
  if (kty === "OKP" && crv === "Ed25519") return { kind: "Ed25519", alg: "EdDSA", jwk: { kty, crv, x } };
  if (kty === "EC" && typeof y === "string") {
    if (crv === "P-256") return { kind: "P-256", alg: "ES256", jwk: { kty, crv, x, y } };
    if (crv === "P-384") return { kind: "P-384", alg: "ES384", jwk: { kty, crv, x, y } };
  }
  return null;
}

/** RFC 7638 thumbprint over the required members only ({crv,kty,x[,y]}), base64url. */
export function thumbprint(key: SupportedKey): string {
  const members: Record<string, string> = { crv: key.jwk.crv, kty: key.jwk.kty, x: key.jwk.x };
  if (key.jwk.y !== undefined) members["y"] = key.jwk.y;
  const digest = sha256Hex(utf8(jcs(fromParsed(members))));
  const bytes = new Uint8Array(digest.match(/../g)!.map((h) => parseInt(h, 16)));
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Key identity over key material only: (kty, crv, x, y). `kid` and other members are ignored. */
export function jwkIdentity(jwk: unknown): string {
  const j = (jwk && typeof jwk === "object" && !Array.isArray(jwk) ? jwk : {}) as Record<string, unknown>;
  const pick = (k: string) => (typeof j[k] === "string" ? (j[k] as string) : null);
  return JSON.stringify([pick("kty"), pick("crv"), pick("x"), pick("y")]);
}

async function importPublicKey(key: SupportedKey): Promise<CryptoKey> {
  const jwk: JsonWebKey = { kty: key.jwk.kty, crv: key.jwk.crv, x: key.jwk.x, ext: true };
  if (key.jwk.y !== undefined) jwk.y = key.jwk.y;
  const algorithm = key.kind === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: key.kind };
  return crypto.subtle.importKey("jwk", jwk, algorithm, false, ["verify"]);
}

export type SignatureOutcome = { outcome: "ok" | "fail" | "unverifiable"; detail: string };

/**
 * Checks `record.signature` (base64url, no padding) with the key at
 * `record.cnf.jwk` over `jcs(record without "signature")`.
 * "unverifiable" covers an unsigned record and a key type not supported
 * here; "fail" is a signature that does not verify or cannot be decoded.
 */
export async function verifySignature(record: JsonObject): Promise<SignatureOutcome> {
  const jwk = recordJwk(record);
  if (!jwk) return { outcome: "fail", detail: "cnf.jwk missing or not an object" };
  const key = supportedKey(jwk);
  if (!key) return { outcome: "unverifiable", detail: `key type ${keyLabel(jwk)} is not verified here (supported: OKP/Ed25519, EC/P-256, EC/P-384)` };
  const sig = record["signature"];
  if (sig === undefined) return { outcome: "unverifiable", detail: "unsigned record; nothing to verify" };
  if (typeof sig !== "string" || !/^[A-Za-z0-9_-]+$/.test(sig)) return { outcome: "fail", detail: "signature is not base64url" };
  const body: JsonObject = {};
  for (const [k, v] of Object.entries(record)) {
    if (k !== "signature") Object.defineProperty(body, k, { value: v, enumerable: true, writable: true, configurable: true });
  }
  const message = utf8(jcs(body));
  try {
    const sigBytes = base64ToBytes(sig, true);
    const cryptoKey = await importPublicKey(key);
    const params = key.kind === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: key.kind === "P-256" ? "SHA-256" : "SHA-384" };
    const ok = await crypto.subtle.verify(params, cryptoKey, sigBytes as BufferSource, message as BufferSource);
    return ok
      ? { outcome: "ok", detail: `${key.alg} over RFC 8785 canonical record without signature; key ${thumbprint(key)} (from cnf.jwk, trust-on-first-use)` }
      : { outcome: "fail", detail: `${key.alg} signature does not verify over the canonical record with the cnf.jwk key` };
  } catch (exc) {
    return { outcome: "fail", detail: `signature material unusable: ${(exc as Error).message}` };
  }
}
