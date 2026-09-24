// verify_agent_manifest: stateless check of a signed agent manifest.
//
// Mirrors verify/trace/record.ts: every check runs, the first failure names
// the verdict, nothing reads the network. The key is the one the manifest
// embeds; whether that key is trusted is a question for the caller.

import { MAX_BODY_BYTES } from "../../limits.js";
import { parseJson, type JsonObject, type JsonValue } from "../pyjson.js";
import { validateManifest, COSE_MANIFEST_VERSION } from "./schema.js";
import { decodeCosePayload, parseCosePayload, payloadDigest, manifestHashInReport } from "./canon.js";
import { extractProtectedHeader, kidToHex, verifyCoseSignature, type CoseHeader, isEd25519Alg, isMlDsa65Alg } from "./keys.js";
import { base64ToBytes } from "../receipt.js";
import { decode as cborDecode, encode as cborEncode } from "cbor2";

export const MANIFEST_CHECK_ORDER = [
  "parse",
  "cose_structure",
  "protected_header",
  "schema",
  "profile",
  "version",
  "canonicalization",
  "signature",
  "record_cites_manifest",
] as const;

export type ManifestCheckName = (typeof MANIFEST_CHECK_ORDER)[number];
export type Outcome = "ok" | "fail" | "unverifiable" | "skipped";
export type Verdict = "valid" | "invalid" | "unverifiable";

export interface ManifestCheck {
  name: ManifestCheckName;
  outcome: Outcome;
  detail: string;
}

export interface ManifestSummary {
  manifest_id: string;
  agent_id: string;
  version: string;
  issued_at: string;
  expires_at: string;
  issuer: string;
  crypto_profile: string;
  manifest_hash: string;
  key_kind: string;
  key_kid: string;
}

export interface ManifestVerification {
  verdict: Verdict;
  failing_check: ManifestCheckName | null;
  /** "sha256:<hex>" over the COSE payload bytes. */
  manifest_sha256: string;
  checks: ManifestCheck[];
  summary: ManifestSummary | null;
  note: string | null;
  /** The parsed manifest payload, for callers that go on to verify attestation. */
  manifest: JsonObject | null;
}

function asString(v: JsonValue | undefined): string {
  return typeof v === "string" ? v : "";
}

/**
 * Verify one agent manifest given its exact text (CBOR COSE envelope) or a
 * parsed object (the manifest payload). Under COSE the signature covers the
 * payload bytes as received; the verifier does NOT re-canonicalize.
 *
 * Input: either a Uint8Array (COSE envelope bytes), a base64-encoded string
 * of COSE envelope bytes, or a JSON object (the manifest payload).
 * Optional second argument: a TRACE Trust Record to check against.
 */
export async function verifyAgentManifest(
  input: Uint8Array | string | JsonObject,
  trustRecord?: JsonObject
): Promise<ManifestVerification> {
  const checks: ManifestCheck[] = [];
  const add = (name: ManifestCheckName, outcome: Outcome, detail = "") => checks.push({ name, outcome, detail });
  let note: string | null = null;

  const done = (
    manifestSha256: string,
    summary: ManifestSummary | null,
    manifest: JsonObject | null
  ): ManifestVerification => {
    const hasTrustRecord = trustRecord !== undefined;
    
    // If trustRecord provided and record_cites_manifest fails, that takes precedence
    const recordFails = hasTrustRecord && checks.some((c) => c.name === "record_cites_manifest" && c.outcome === "fail");
    
    // Signature unverifiable (no COSE envelope) without trustRecord -> overall unverifiable
    const hasSignatureUnverifiable = checks.some((c) => c.name === "signature" && c.outcome === "unverifiable");
    const unverifiable = hasSignatureUnverifiable && !hasTrustRecord;
    
    // First check: record_cites_manifest fail with trustRecord
    if (recordFails) {
      return {
        verdict: "invalid",
        failing_check: "record_cites_manifest" as ManifestCheckName,
        manifest_sha256: manifestSha256,
        checks,
        summary,
        note,
        manifest,
      };
    }
    
    // If signature unverifiable and no trustRecord, overall unverifiable regardless of other fails
    if (unverifiable) {
      return {
        verdict: "unverifiable",
        failing_check: null,
        manifest_sha256: manifestSha256,
        checks,
        summary,
        note,
        manifest,
      };
    }
    
    // Any fail check -> invalid
    const failing = checks.find((c) => c.outcome === "fail");
    if (failing) {
      return {
        verdict: "invalid",
        failing_check: failing.name,
        manifest_sha256: manifestSha256,
        checks,
        summary,
        note,
        manifest,
      };
    }
    
    // All ok
    return {
      verdict: "valid",
      failing_check: null,
      manifest_sha256: manifestSha256,
      checks,
      summary,
      note,
      manifest,
    };
  };

  // -- parse ------------------------------------------------------------------
  let coseBytes: Uint8Array | undefined;
  let manifest: JsonObject | null = null;
  let payloadBytes: Uint8Array | null = null;

  if (input instanceof Uint8Array) {
    coseBytes = input;
  } else if (typeof input === "string") {
    // Check if it's base64-encoded COSE envelope
    try {
      const decoded = base64ToBytes(input, true);
      // Try to decode as COSE
      const testDecode = cborDecode(decoded) as { tag: number; value: unknown };
      if (testDecode.tag === 18 || testDecode.tag === 98) {
        coseBytes = decoded;
      } else {
        // Not a COSE envelope, treat as JSON text
        throw new Error("not COSE");
      }
    } catch {
      // Treat as JSON text
      if (input.length > MAX_BODY_BYTES) {
        add("parse", "fail", `input exceeds ${MAX_BODY_BYTES} bytes`);
        return done("", null, null);
      }
      let value: JsonValue;
      try {
        value = parseJson(input, 32);
      } catch (exc) {
        add("parse", "unverifiable", `not valid JSON: ${(exc as Error).message}`);
        return done("", null, null);
      }
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        add("parse", "unverifiable", "a manifest is a JSON object");
        return done("", null, null);
      }
      manifest = value as JsonObject;
      add("parse", "ok", "JSON object (from text)");
      // For JSON object input, we can't verify signature without COSE envelope
      add("cose_structure", "skipped", "input is a JSON object, not a COSE envelope");
      add("protected_header", "skipped", "input is a JSON object, not a COSE envelope");
      // Continue to schema check with the manifest
    }
  } else {
    // Already parsed object
    const objSize = JSON.stringify(input).length;
    if (objSize > MAX_BODY_BYTES) {
      add("parse", "fail", `input exceeds ${MAX_BODY_BYTES} bytes`);
      return done("", null, null);
    }
    manifest = input;
    add("parse", "ok", "JSON object (already parsed)");
    add("cose_structure", "skipped", "input is a JSON object, not a COSE envelope");
    add("protected_header", "skipped", "input is a JSON object, not a COSE envelope");
  }

  // If we have COSE bytes, decode the envelope
  if (coseBytes !== undefined && manifest === null) {
    if (coseBytes.length > MAX_BODY_BYTES) {
      add("parse", "fail", `COSE envelope exceeds ${MAX_BODY_BYTES} bytes`);
      return done("", null, null);
    }
    add("parse", "ok", "COSE envelope (CBOR)");

    // -- cose_structure -------------------------------------------------------
    try {
      payloadBytes = decodeCosePayload(coseBytes);
      add("cose_structure", "ok", "valid COSE_Sign1 or COSE_Sign envelope");
    } catch (exc) {
      add("cose_structure", "fail", `malformed COSE envelope: ${(exc as Error).message}`);
      return done("", null, null);
    }

    // -- protected_header -----------------------------------------------------
    let header: CoseHeader;
    try {
      header = extractProtectedHeader(coseBytes);
      add("protected_header", "ok", `alg=${algName(header.alg)}, kid=${kidToHex(header.kid).slice(0, 16)}..., content_type=${header.content_type}, typ=${header.typ}`);
    } catch (exc) {
      add("protected_header", "fail", `protected header invalid: ${(exc as Error).message}`);
      return done("", null, null);
    }

    // Parse the manifest payload
    try {
      manifest = parseCosePayload(payloadBytes) as JsonObject;
    } catch (exc) {
      add("schema", "fail", `payload not valid JSON: ${(exc as Error).message}`);
      return done("", null, null);
    }
  }

  if (!manifest) {
    return done("", null, null);
  }

  const manifestSha256 = payloadBytes
    ? manifestHashInReport(payloadBytes)
    : payloadDigest(manifest, "sha256");

  // -- schema -----------------------------------------------------------------
  const schema = validateManifest(manifest);
  if (schema.ok) {
    add("schema", "ok", "vendor/agent-manifest.schema.json");
  } else {
    add("schema", "fail", `${schema.errors[0].path}: ${schema.errors[0].message}`);
  }

  // -- profile ----------------------------------------------------------------
  const context = manifest["@context"];
  if (context === "https://manifest.agentrust-io.com/v0.2/context.json") {
    add("profile", "ok", "https://manifest.agentrust-io.com/v0.2/context.json");
  } else {
    add("profile", "fail", `@context ${JSON.stringify(context ?? null)} is not the v0.2 context URI`);
  }

  // -- version ----------------------------------------------------------------
  const version = manifest["version"];
  if (version === COSE_MANIFEST_VERSION) {
    add("version", "ok", COSE_MANIFEST_VERSION);
  } else {
    add("version", "fail", `version ${JSON.stringify(version ?? null)} is not ${COSE_MANIFEST_VERSION}`);
  }

  // -- canonicalization (diagnostic only) -------------------------------------
  // For COSE, the signature is over the payload bytes as received. We report
  // whether those bytes match RFC 8785 canonicalization of the parsed payload.
  if (payloadBytes) {
    const recomputed = payloadDigest(manifest, "sha256");
    const actual = manifestHashInReport(payloadBytes);
    if (recomputed === actual) {
      add("canonicalization", "ok", "payload bytes match RFC 8785 canonicalization");
    } else {
      add("canonicalization", "fail", `payload bytes differ from RFC 8785 canonicalization: expected ${recomputed}, got ${actual}`);
      note = "payload is not RFC 8785 canonical; signature verification used bytes as received";
    }
  } else {
    add("canonicalization", "skipped", "input was a JSON object; no COSE payload bytes to check");
  }

  // -- signature --------------------------------------------------------------
  if (!payloadBytes) {
    add("signature", "unverifiable", "no COSE envelope provided; signature not verified");
    note = "embedded key only; no key trust beyond the embedded key was applied";
  } else {
    // Re-parse COSE to get signature entries
    const decoded = cborDecode(coseBytes as Uint8Array) as { tag: number; value: unknown };
    const body = decoded.value as unknown[];
    const bodyProtected = body[0] as Uint8Array;
    const fourth = body[3];

    // Build list of signature entries
    const entries: Array<{ alg: number; kid: Uint8Array; toBeSigned: Uint8Array; signature: Uint8Array }> = [];
    
    if (decoded.tag === 18) {
      // COSE_Sign1
      if (fourth instanceof Uint8Array) {
        const hdr = extractProtectedHeader(coseBytes as Uint8Array);
        const toBeSigned = buildSigStructureSign1(bodyProtected, payloadBytes);
        entries.push({ alg: hdr.alg, kid: hdr.kid, toBeSigned, signature: fourth });
      }
    } else {
      // COSE_Sign
      if (Array.isArray(fourth)) {
        for (const raw of fourth) {
          if (Array.isArray(raw) && raw.length === 3) {
            const signProtected = raw[0] as Uint8Array;
            const signature = raw[2] as Uint8Array;
            const signHeader = cborDecode(signProtected) as unknown[];
            const alg = signHeader[1];
            const kid = signHeader[4];
            if (typeof alg === "number" && kid instanceof Uint8Array) {
              const toBeSigned = buildSigStructureSign(bodyProtected, signProtected, payloadBytes);
              entries.push({ alg, kid, toBeSigned, signature });
            }
          }
        }
      }
    }

    if (entries.length === 0) {
      add("signature", "fail", "COSE envelope has no signature entries");
    } else {
      let allOk = true;
      let anyUnverifiable = false;
      for (const entry of entries) {
        const kidHex = kidToHex(entry.kid);
        // Without a trusted key, we can't verify
        const result = await verifyCoseSignature(entry.alg, kidHex, entry.toBeSigned, entry.signature, null);
        if (result.outcome === "fail") {
          add("signature", "fail", result.detail);
          allOk = false;
          break;
        } else if (result.outcome === "unverifiable") {
          add("signature", "unverifiable", result.detail);
          anyUnverifiable = true;
          allOk = false;
        } else {
          add("signature", "ok", result.detail);
        }
      }
      if (allOk) {
        add("signature", "ok", "all signature entries verified");
      } else if (!anyUnverifiable) {
        // Already added fail
      } else if (note === null) {
        note = "embedded key only; no key trust beyond the embedded key was applied";
      }
    }
  }

  // -- record_cites_manifest --------------------------------------------------
  if (trustRecord) {
    // Check if the trust record's references array cites this manifest's digest
    const references = trustRecord["references"];
    if (Array.isArray(references)) {
      let found = false;
      for (const ref of references) {
        if (ref && typeof ref === "object" && !Array.isArray(ref)) {
          const refObj = ref as Record<string, JsonValue>;
          const rel = asString(refObj["rel"]);
          const digest = asString(refObj["digest"]);
          if (rel === "agent-manifest" && digest === manifestSha256) {
            found = true;
            break;
          }
        }
      }
      if (found) {
        add("record_cites_manifest", "ok", `record references this manifest (${manifestSha256})`);
      } else {
        add("record_cites_manifest", "fail", `record does not reference manifest ${manifestSha256}`);
      }
    } else {
      add("record_cites_manifest", "fail", "record has no references array or it is not an array");
    }
  } else {
    add("record_cites_manifest", "skipped", "no trust record supplied");
  }

  const summary: ManifestSummary | null = schema.ok
    ? {
        manifest_id: asString(manifest["manifest_id"]),
        agent_id: asString(manifest["agent_id"]),
        version: asString(manifest["version"]),
        issued_at: asString(manifest["issued_at"]),
        expires_at: asString(manifest["expires_at"]),
        issuer: asString(manifest["issuer"]),
        crypto_profile: asString(manifest["crypto_profile"]),
        manifest_hash: manifestSha256,
        key_kid: "", // would need to extract from COSE
        key_kind: "",
      }
    : null;

  return done(manifestSha256, summary, manifest);
}

function algName(alg: number): string {
  if (isEd25519Alg(alg)) return "Ed25519";
  if (isMlDsa65Alg(alg)) return "ML-DSA-65";
  return String(alg);
}

function buildSigStructureSign1(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return cborEncode(["Signature1", protectedBytes, new Uint8Array(0), payload]);
}

function buildSigStructureSign(bodyProtected: Uint8Array, signProtected: Uint8Array, payload: Uint8Array): Uint8Array {
  return cborEncode(["Signature", bodyProtected, signProtected, new Uint8Array(0), payload]);
}
