// Key extraction from Agent Manifest v0.2 COSE protected header.
//
// The COSE envelope carries the algorithm (alg, label 1) and key identifier
// (kid, label 4) in the protected header. The kid is the SHA-256 of the
// raw public key bytes, matching v0.1's signature.key_id.

import { base64ToBytes } from "../receipt.js";
import { type JsonObject } from "../pyjson.js";

/** RFC 7517 private members: a public JWK must carry none of them. */
export const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] as const;

export type KeyKind = "Ed25519" | "P-256" | "P-384";

export interface SupportedKey {
  kind: KeyKind;
  alg: "EdDSA" | "ES256" | "ES384";
  jwk: { kty: string; crv: string; x: string; y?: string };
  kid: string; // hex string of SHA-256 of public key bytes
}

export interface CoseHeader {
  alg: number;
  kid: Uint8Array;
  content_type: string;
  typ: string;
}

/** COSE algorithm identifiers */
export const ALG_EDDSA = -8;
export const ALG_ED25519 = -19;
export const ALG_ML_DSA_65 = -49;

export function isEd25519Alg(alg: number): boolean {
  return alg === ALG_EDDSA || alg === ALG_ED25519;
}

export function isMlDsa65Alg(alg: number): boolean {
  return alg === ALG_ML_DSA_65;
}

export function algName(alg: number): string {
  switch (alg) {
    case ALG_EDDSA:
    case ALG_ED25519:
      return "Ed25519";
    case ALG_ML_DSA_65:
      return "ML-DSA-65";
    default:
      return String(alg);
  }
}

/** Extract protected header from COSE_Sign1 or COSE_Sign body. */
export function extractProtectedHeader(coseBytes: Uint8Array): CoseHeader {
  const { decode } = require("cbor2");
  const decoded = decode(coseBytes);

  if (decoded.tag !== 18 && decoded.tag !== 98) {
    throw new Error(`not a tagged COSE_Sign1 (18) or COSE_Sign (98): tag ${decoded.tag}`);
  }

  const body = decoded.value;
  if (!Array.isArray(body) || body.length !== 4) {
    throw new Error("COSE body is not a 4-element array");
  }

  const protectedBytes = body[0];
  if (!(protectedBytes instanceof Uint8Array)) {
    throw new Error("COSE protected header is not a byte string");
  }

  const protectedHeader = decode(protectedBytes);
  if (!protectedHeader || typeof protectedHeader !== "object") {
    throw new Error("COSE protected header is not a map");
  }

  const alg = protectedHeader[1];
  const kid = protectedHeader[4];
  const content_type = protectedHeader[3];
  const typ = protectedHeader[16];

  if (typeof alg !== "number") {
    throw new Error("COSE protected header missing alg (label 1)");
  }
  if (!(kid instanceof Uint8Array)) {
    throw new Error("COSE protected header missing kid (label 4) or not a byte string");
  }
  if (typeof content_type !== "string" || content_type !== "application/agent-manifest+json") {
    throw new Error("COSE protected header missing or wrong content type (label 3)");
  }
  if (typeof typ !== "string" || typ !== "application/agent-manifest+cose") {
    throw new Error("COSE protected header missing or wrong typ (label 16)");
  }

  return {
    alg,
    kid,
    content_type,
    typ,
  };
}

/** Convert kid bytes to hex string. */
export function kidToHex(kid: Uint8Array): string {
  return Array.from(kid).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A short label for an unsupported key. */
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
  if (kty === "OKP" && crv === "Ed25519") return { kind: "Ed25519", alg: "EdDSA", jwk: { kty, crv, x }, kid: "" };
  if (kty === "EC" && typeof y === "string") {
    if (crv === "P-256") return { kind: "P-256", alg: "ES256", jwk: { kty, crv, x, y }, kid: "" };
    if (crv === "P-384") return { kind: "P-384", alg: "ES384", jwk: { kty, crv, x, y }, kid: "" };
  }
  return null;
}

/** Compute kid from JWK public key bytes. */
export function computeKid(jwk: { kty: string; crv: string; x: string; y?: string }): string {
  // The kid is SHA-256 of raw public key bytes.
  // For Ed25519: raw 32-byte public key
  // For EC: uncompressed point 0x04 || x || y
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    const xBytes = base64ToBytes(jwk.x, true);
    if (xBytes.length !== 32) {
      throw new Error(`Ed25519 public key x coordinate must be 32 bytes, got ${xBytes.length}`);
    }
    const { sha256 } = require("@noble/hashes/sha2.js");
    const hash: Uint8Array = sha256(xBytes);
    return Array.from(hash).map((b: number) => b.toString(16).padStart(2, "0")).join("");
  }
  if (jwk.kty === "EC" && jwk.y) {
    const xBytes = base64ToBytes(jwk.x, true);
    const yBytes = base64ToBytes(jwk.y, true);
    const point = new Uint8Array(1 + xBytes.length + yBytes.length);
    point[0] = 0x04; // uncompressed
    point.set(xBytes, 1);
    point.set(yBytes, 1 + xBytes.length);
    const { sha256 } = require("@noble/hashes/sha2.js");
    const hash: Uint8Array = sha256(point);
    return Array.from(hash).map((b: number) => b.toString(16).padStart(2, "0")).join("");
  }
  throw new Error(`Cannot compute kid for key type ${jwk.kty}/${jwk.crv}`);
}

async function importPublicKey(key: SupportedKey): Promise<CryptoKey> {
  const jwk: JsonWebKey = { kty: key.jwk.kty, crv: key.jwk.crv, x: key.jwk.x, ext: true };
  if (key.jwk.y !== undefined) jwk.y = key.jwk.y;
  const algorithm = key.kind === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: key.kind };
  return crypto.subtle.importKey("jwk", jwk, algorithm, false, ["verify"]);
}

export type SignatureOutcome = { outcome: "ok" | "fail" | "unverifiable"; detail: string };

/**
 * Verify a COSE signature entry against the embedded key.
 */
export async function verifyCoseSignature(
  alg: number,
  kidHex: string,
  toBeSigned: Uint8Array,
  signature: Uint8Array,
  embeddedKey: SupportedKey | null
): Promise<SignatureOutcome> {
  // Check if the embedded key matches the kid
  if (embeddedKey) {
    const computedKid = computeKid(embeddedKey.jwk);
    if (computedKid !== kidHex) {
      return { outcome: "fail", detail: `embedded key kid mismatch: expected ${kidHex}, got ${computedKid}` };
    }
  }

  // Check algorithm matches
  if (isEd25519Alg(alg)) {
    if (embeddedKey && embeddedKey.kind !== "Ed25519") {
      return { outcome: "fail", detail: `algorithm ${algName(alg)} requires Ed25519 key` };
    }
  } else if (isMlDsa65Alg(alg)) {
    return { outcome: "unverifiable", detail: "ML-DSA-65 verification not supported in this build" };
  } else {
    return { outcome: "unverifiable", detail: `unsupported algorithm ${algName(alg)}` };
  }

  if (!embeddedKey) {
    return { outcome: "unverifiable", detail: "no key embedded in manifest; signature cannot be verified" };
  }

  try {
    const cryptoKey = await importPublicKey(embeddedKey);
    const params = embeddedKey.kind === "Ed25519"
      ? { name: "Ed25519" }
      : { name: "ECDSA", hash: embeddedKey.kind === "P-256" ? "SHA-256" : "SHA-384" };
    const ok = await crypto.subtle.verify(params, cryptoKey, signature as BufferSource, toBeSigned as BufferSource);
    return ok
      ? { outcome: "ok", detail: `${algName(alg)} signature verified with embedded key (kid ${kidHex})` }
      : { outcome: "fail", detail: `${algName(alg)} signature does not verify with embedded key` };
  } catch (exc) {
    return { outcome: "fail", detail: `signature verification error: ${(exc as Error).message}` };
  }
}
