// RFC 8785 digests of a TRACE v0.2 Trust Record.
//
// The delegation profile names a parent by the digest of its COMPLETE
// record, signature included, over the RFC 8785 (JCS) canonical form. JCS
// orders object keys by UTF-16 code unit; a canonicalizer that sorts by
// code point agrees everywhere except on keys outside the Basic
// Multilingual Plane. `jcsCodePointOrder` exists only so that divergence
// can be named in a diagnostic — no verdict is ever computed from it.

import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { jcs, jcsCodePointOrder, utf8, JsonNumber, type JsonValue } from "../pyjson.js";

export { jcsCodePointOrder };

export type DigestAlgorithm = "sha256" | "sha384";

export const DIGEST_ALGORITHMS: readonly DigestAlgorithm[] = ["sha256", "sha384"];

export function isDigestAlgorithm(alg: string): alg is DigestAlgorithm {
  return alg === "sha256" || alg === "sha384";
}

function hashHex(alg: DigestAlgorithm, data: Uint8Array): string {
  return bytesToHex(alg === "sha256" ? sha256(data) : sha384(data));
}

/** `<alg>:<hex>` over `jcs(record)` — the complete record, signature included. */
export function traceDigest(record: JsonValue, alg: DigestAlgorithm): string {
  return `${alg}:${hashHex(alg, utf8(jcs(record)))}`;
}

/** The same digest with keys in code-point order. Diagnostic only. */
export function traceDigestCodePointOrder(record: JsonValue, alg: DigestAlgorithm): string {
  return `${alg}:${hashHex(alg, utf8(jcsCodePointOrder(record)))}`;
}

/** True when any object key anywhere in `value` contains a surrogate code unit (a character outside the BMP). */
export function hasNonBmpKey(value: JsonValue): boolean {
  if (value === null || typeof value !== "object" || value instanceof JsonNumber) return false;
  if (Array.isArray(value)) return value.some(hasNonBmpKey);
  for (const k of Object.keys(value)) {
    for (let i = 0; i < k.length; i++) {
      const c = k.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdfff) return true;
    }
    if (hasNonBmpKey(value[k])) return true;
  }
  return false;
}
