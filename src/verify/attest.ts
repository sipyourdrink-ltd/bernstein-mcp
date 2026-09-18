// The verdict as a signed statement.
//
// Every verification this endpoint performs is a pure function of the
// receipt bytes, so the verdict can be handed on as evidence: the statement
// below names the receipt by digest, carries the verdict and every check,
// and is signed with this deployment's Ed25519 key in a DSSE envelope. A
// reviewer, a CI job or an auditor can keep the envelope and check it
// offline against the public key served at /.well-known/bernstein-mcp/keys.json
// — the same PAE construction the run receipt itself uses.
//
// The `appraisal` block uses the EAR status vocabulary (draft-ietf-rats-ar4si)
// that TRACE v0.2 records adopt for verifier outcomes, so a TRACE-aware
// consumer reads the outcome without a mapping table. The statement is not a
// TRACE Trust Record: that format describes a running workload, not the
// outcome of checking one artifact.

import { bytesToBase64, pae, type ReceiptVerification } from "./receipt.js";
import { fromParsed, jcs, utf8 } from "./pyjson.js";
import { sha256Hex } from "./chains.js";

export const VERDICT_STATEMENT_TYPE = "https://bernstein.run/attestations/verdict/v1";
export const VERDICT_PAYLOAD_TYPE = "application/vnd.bernstein.verdict+json";
export const VERIFIER_URL = "https://mcp.bernstein.run";
export const KEYS_PATH = "/.well-known/bernstein-mcp/keys.json";

/** One DSSE envelope: base64 payload, one Ed25519 signature keyed by JWK thumbprint. */
export interface SignedVerdict {
  payloadType: typeof VERDICT_PAYLOAD_TYPE;
  payload: string;
  signatures: { keyid: string; sig: string }[];
}

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use: "sig";
  alg: "EdDSA";
}

export interface Signer {
  key: CryptoKey;
  publicJwk: PublicJwk;
}

/** RFC 7638 thumbprint of an Ed25519 public JWK, base64url. */
export function jwkThumbprint(x: string): string {
  const canonical = jcs(fromParsed({ crv: "Ed25519", kty: "OKP", x }));
  const digest = sha256Hex(utf8(canonical));
  const bytes = new Uint8Array(digest.match(/../g)!.map((h) => parseInt(h, 16)));
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let cached: { secret: string; signer: Promise<Signer | null> } | null = null;

/**
 * Load the signing key from the `VERDICT_SIGNING_KEY` secret (a private
 * Ed25519 JWK). Absent or malformed → null, and verdicts go out unsigned;
 * the endpoint never fails a verification over its own key. Cached per
 * isolate — importing a key is not free and the secret does not change
 * between requests.
 */
export function loadSigner(secret: string | undefined): Promise<Signer | null> {
  if (!secret) return Promise.resolve(null);
  if (cached && cached.secret === secret) return cached.signer;
  const signer = importSigner(secret).catch(() => null);
  cached = { secret, signer };
  return signer;
}

async function importSigner(secret: string): Promise<Signer | null> {
  const jwk = JSON.parse(secret) as { kty?: string; crv?: string; x?: string; d?: string };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || typeof jwk.d !== "string") return null;
  const key = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, { name: "Ed25519" }, false, ["sign"]);
  const publicJwk: PublicJwk = { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: jwkThumbprint(jwk.x), use: "sig", alg: "EdDSA" };
  return { key, publicJwk };
}

/** The statement bytes: JCS-canonical JSON, so any party re-serialises identically. */
export function verdictStatement(v: ReceiptVerification, issuedAt: number, verifierVersion: string): Record<string, unknown> {
  const status = v.verdict === "valid" ? "affirming" : v.verdict === "invalid" ? "contraindicated" : "none";
  return {
    statement_type: VERDICT_STATEMENT_TYPE,
    verifier: VERIFIER_URL,
    verifier_version: verifierVersion,
    issued_at: issuedAt,
    receipt_sha256: v.receipt_sha256,
    verdict: v.verdict,
    failing_check: v.failing_check,
    divergent_step: v.divergent_step,
    checks: v.checks,
    summary: v.summary,
    appraisal: {
      status,
      verifier: VERIFIER_URL,
      timestamp: issuedAt,
      policy_ref: `${VERIFIER_URL}/#checks`,
    },
  };
}

export async function signVerdict(
  v: ReceiptVerification,
  signer: Signer,
  verifierVersion: string,
  now: () => number = () => Math.floor(Date.now() / 1000),
): Promise<SignedVerdict> {
  const statement = verdictStatement(v, now(), verifierVersion);
  const payload = utf8(jcs(fromParsed(statement)));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, signer.key, pae(VERDICT_PAYLOAD_TYPE, payload) as BufferSource));
  return {
    payloadType: VERDICT_PAYLOAD_TYPE,
    payload: bytesToBase64(payload),
    signatures: [{ keyid: signer.publicJwk.kid, sig: bytesToBase64(signature) }],
  };
}
