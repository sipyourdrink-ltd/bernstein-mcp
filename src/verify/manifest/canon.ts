// COSE payload canonicalization and digest for Agent Manifest v0.2.
//
// The v0.2 manifest uses a COSE envelope (COSE_Sign1 tag 18 or COSE_Sign tag 98).
// The payload is RFC 8785 (JCS) canonical JSON. The signature is verified over the
// payload bytes exactly as received — the verifier MUST NOT re-canonicalize.
// This module provides helpers to extract the COSE payload and compute its digest.

import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { jcs, utf8, type JsonValue } from "../pyjson.js";

export type DigestAlgorithm = "sha256" | "sha384";

export const DIGEST_ALGORITHMS: readonly DigestAlgorithm[] = ["sha256", "sha384"];

export function isDigestAlgorithm(alg: string): alg is DigestAlgorithm {
  return alg === "sha256" || alg === "sha384";
}

function hashHex(alg: DigestAlgorithm, data: Uint8Array): string {
  return bytesToHex(alg === "sha256" ? sha256(data) : sha384(data));
}

/** `<alg>:<hex>` over the RFC 8785 canonical form of the manifest payload. */
export function payloadDigest(payload: JsonValue, alg: DigestAlgorithm): string {
  return `${alg}:${hashHex(alg, utf8(jcs(payload)))}`;
}

/** Decode a COSE_Sign1 or COSE_Sign envelope and return the raw payload bytes. */
export function decodeCosePayload(coseBytes: Uint8Array): Uint8Array {
  const { decode } = require("cbor2");
  const decoded = decode(coseBytes);

  // Expect tagged COSE_Sign1 (18) or COSE_Sign (98)
  if (decoded.tag !== 18 && decoded.tag !== 98) {
    throw new Error(`not a tagged COSE_Sign1 (18) or COSE_Sign (98): tag ${decoded.tag}`);
  }

  const body = decoded.value;
  // COSE_Sign1: [protected, unprotected, payload, signature]
  // COSE_Sign: [body_protected, unprotected, payload, [signatures...]]
  if (!Array.isArray(body) || body.length !== 4) {
    throw new Error("COSE body is not a 4-element array");
  }

  const payload = body[2];
  if (!(payload instanceof Uint8Array)) {
    throw new Error("COSE payload is not a byte string");
  }

  return payload;
}

/** Parse the COSE payload bytes as JSON. */
export function parseCosePayload(payloadBytes: Uint8Array): JsonValue {
  const text = new TextDecoder("utf-8").decode(payloadBytes);
  return JSON.parse(text);
}

/** Compute the manifest hash that hardware attestation binds (sha256 over COSE payload bytes). */
export function manifestHashInReport(payloadBytes: Uint8Array): string {
  return `sha256:${bytesToHex(sha256(payloadBytes))}`;
}
