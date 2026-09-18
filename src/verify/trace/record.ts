// Conformance checks over one TRACE v0.2 Trust Record.
//
// Mirrors the style of verify/receipt.ts: every check runs, the first
// failure names the verdict, and nothing here reads the network. The key
// is the one the record carries in `cnf.jwk` (trust-on-first-use); whether
// that key is trusted is a question for the delegation-chain walk.

import { MAX_JSON_DEPTH } from "../../limits.js";
import { fromParsed, parseJson, JsonNumber, type JsonObject, type JsonValue } from "../pyjson.js";
import { hasNonBmpKey, traceDigest, traceDigestCodePointOrder } from "./canon.js";
import { isObject, keyLabel, privateMember, recordJwk, supportedKey, thumbprint, verifySignature } from "./keys.js";
import { validateTraceRecord } from "./schema.js";

export const TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2";

export const TRACE_CHECK_ORDER = [
  "parse",
  "schema",
  "profile",
  "subject",
  "runtime",
  "policy",
  "cnf_key",
  "signature",
  "appraisal",
  "delegation",
  "references",
  "canonicalization",
] as const;

export type TraceCheckName = (typeof TRACE_CHECK_ORDER)[number];
export type Outcome = "ok" | "fail" | "unverifiable" | "skipped";
export type Verdict = "valid" | "invalid" | "unverifiable";

export interface TraceCheck {
  name: TraceCheckName;
  outcome: Outcome;
  detail: string;
}

export interface TraceRecordSummary {
  subject: string;
  eat_profile: string;
  iat: number;
  model_id: string;
  provider: string;
  data_class: string;
  key_thumbprint: string;
  has_delegation: boolean;
  references: number;
  tool_calls: number | null;
}

export interface TraceRecordVerification {
  verdict: Verdict;
  failing_check: TraceCheckName | null;
  /** "sha256:<hex>" over the RFC 8785 form of the complete record, signature included; "" when the input is not a JSON object. */
  record_sha256: string;
  checks: TraceCheck[];
  summary: TraceRecordSummary | null;
  note: string | null;
  /** The parsed record, for callers that go on to walk a chain. */
  record: JsonObject | null;
}

const URI_RE = /^[a-z][a-z0-9+.-]*:/;
const DIGEST_RE = /^sha(256|384):([0-9a-f]+)$/;

/** True for `sha256:<64 hex>` or `sha384:<96 hex>`. */
export function isWellFormedDigest(v: JsonValue | undefined): boolean {
  if (typeof v !== "string") return false;
  const m = DIGEST_RE.exec(v);
  return m !== null && m[2].length === (m[1] === "256" ? 64 : 96);
}

function asString(v: JsonValue | undefined): string {
  return typeof v === "string" ? v : "";
}

function asInt(v: JsonValue | undefined): number | null {
  return v instanceof JsonNumber && Number.isInteger(v.value) ? v.value : null;
}

/**
 * Verify one record given its exact text (preferred) or a parsed object.
 * Under RFC 8785 a number's spelling does not change the digest, so a
 * parsed object loses nothing here — unlike a run receipt.
 */
export async function verifyTraceRecord(input: string | unknown): Promise<TraceRecordVerification> {
  const checks: TraceCheck[] = [];
  const add = (name: TraceCheckName, outcome: Outcome, detail = "") => checks.push({ name, outcome, detail });
  let note: string | null = null;
  const done = (record_sha256: string, summary: TraceRecordSummary | null, record: JsonObject | null): TraceRecordVerification => {
    const failing = checks.find((c) => c.outcome === "fail");
    const unverifiable = checks.some((c) => c.outcome === "unverifiable");
    return {
      verdict: failing ? "invalid" : unverifiable ? "unverifiable" : "valid",
      failing_check: failing ? failing.name : null,
      record_sha256,
      checks,
      summary,
      note,
      record,
    };
  };

  // -- parse ------------------------------------------------------------------
  let value: JsonValue;
  try {
    value = typeof input === "string" ? parseJson(input, MAX_JSON_DEPTH) : fromParsed(input);
  } catch (exc) {
    add("parse", "unverifiable", `not valid JSON: ${(exc as Error).message}`);
    return done("", null, null);
  }
  if (!isObject(value)) {
    add("parse", "unverifiable", "a Trust Record is a JSON object");
    return done("", null, null);
  }
  const record = value;
  add("parse", "ok", typeof input === "string" ? "JSON object (from text)" : "JSON object (already parsed)");
  const recordSha256 = traceDigest(record, "sha256");

  // -- schema -----------------------------------------------------------------
  const schema = validateTraceRecord(record);
  if (schema.ok) add("schema", "ok", "vendor/trace-claim.json (draft 2020-12)");
  else add("schema", "fail", `${schema.errors[0].path}: ${schema.errors[0].message}`);

  // -- profile ----------------------------------------------------------------
  const profile = record["eat_profile"];
  if (profile === TRACE_PROFILE) add("profile", "ok", TRACE_PROFILE);
  else add("profile", "fail", `eat_profile ${JSON.stringify(profile ?? null)} is not ${TRACE_PROFILE}`);

  // -- subject ----------------------------------------------------------------
  const subject = asString(record["subject"]);
  if (URI_RE.test(subject)) {
    add("subject", "ok", subject.startsWith("spiffe://") ? "spiffe URI" : `URI with scheme ${subject.split(":")[0]}`);
  } else {
    add("subject", "fail", `subject ${JSON.stringify(record["subject"] ?? null)} is not a URI with a scheme`);
  }

  // -- runtime ----------------------------------------------------------------
  const runtime = record["runtime"];
  if (!isObject(runtime)) {
    add("runtime", "fail", "runtime missing or not an object");
  } else if (runtime["platform"] === "software-only") {
    const m = asString(runtime["measurement"]);
    const zero = /^sha(256|384):0+$/.test(m) && isWellFormedDigest(m);
    if (zero) add("runtime", "ok", "software-only with the all-zero measurement");
    else add("runtime", "fail", "software-only runtime claims a measurement");
  } else {
    add("runtime", "ok", `platform ${JSON.stringify(runtime["platform"] ?? null)}: hardware measurement not evaluated here`);
  }

  // -- policy -----------------------------------------------------------------
  const policy = record["policy"];
  if (!isObject(policy)) {
    add("policy", "fail", "policy missing or not an object");
  } else if (typeof policy["enforcement_mode"] !== "string") {
    add("policy", "fail", "policy.enforcement_mode missing");
  } else if (!isWellFormedDigest(policy["bundle_hash"])) {
    add("policy", "fail", "policy.bundle_hash is not sha256:<64 hex> or sha384:<96 hex>");
  } else {
    add("policy", "ok", `enforcement_mode ${policy["enforcement_mode"]}`);
  }

  // -- cnf_key ----------------------------------------------------------------
  const jwk = recordJwk(record);
  let keyThumbprint = "";
  if (!jwk) {
    add("cnf_key", "fail", "cnf.jwk missing or not an object");
  } else {
    const priv = privateMember(jwk);
    const key = supportedKey(jwk);
    if (key) keyThumbprint = thumbprint(key);
    if (priv !== null) {
      add("cnf_key", "fail", `record carries a private key member (${priv}); TRACE requires the public JWK only`);
    } else if (key) {
      add("cnf_key", "ok", `${keyLabel(jwk)} public key, thumbprint ${keyThumbprint}`);
    } else {
      add("cnf_key", "ok", `${keyLabel(jwk)} public key (not a type verified here)`);
    }
  }

  // -- signature --------------------------------------------------------------
  const sig = await verifySignature(record);
  add("signature", sig.outcome, sig.detail);
  if (sig.outcome === "unverifiable") note = sig.detail;

  // -- appraisal --------------------------------------------------------------
  const appraisal = record["appraisal"];
  if (!isObject(appraisal)) {
    add("appraisal", "fail", "appraisal missing or not an object");
  } else if (typeof appraisal["status"] !== "string") {
    add("appraisal", "fail", "appraisal.status missing");
  } else if (!URI_RE.test(asString(appraisal["verifier"]))) {
    add("appraisal", "fail", "appraisal.verifier is not a URI with a scheme");
  } else {
    add("appraisal", "ok", `status ${appraisal["status"]}`);
  }

  // -- delegation -------------------------------------------------------------
  const delegation = record["delegation"];
  if (delegation === undefined) {
    add("delegation", "skipped", "no delegation block: a root (non-delegated) execution");
  } else if (!isObject(delegation)) {
    add("delegation", "fail", "delegation is not an object");
  } else if (!isWellFormedDigest(delegation["parent_record_hash"])) {
    add("delegation", "fail", "delegation.parent_record_hash is not sha256:<64 hex> or sha384:<96 hex>");
  } else if (typeof delegation["credential_id"] !== "string" || delegation["credential_id"] === "") {
    add("delegation", "fail", "delegation.credential_id missing or empty");
  } else {
    add("delegation", "ok", `links to parent ${delegation["parent_record_hash"]} under ${delegation["credential_id"]}; the chain itself is checked by verify_delegation_chain`);
  }

  // -- references -------------------------------------------------------------
  const references = record["references"];
  let referenceCount = 0;
  if (references === undefined) {
    add("references", "skipped", "no references block");
  } else if (!Array.isArray(references)) {
    add("references", "fail", "references is not an array");
  } else {
    referenceCount = references.length;
    let problem: string | null = null;
    for (const [i, ref] of references.entries()) {
      if (!isObject(ref)) {
        problem = `references[${i}] is not an object`;
      } else {
        for (const field of ["rel", "id", "resolver"]) {
          if (typeof ref[field] !== "string" || ref[field] === "") problem = `references[${i}].${field} missing or empty`;
        }
        if (problem === null && ref["digest"] !== undefined && !isWellFormedDigest(ref["digest"])) problem = `references[${i}].digest is not sha256:<64 hex> or sha384:<96 hex>`;
      }
      if (problem !== null) break;
    }
    if (problem !== null) add("references", "fail", problem);
    else add("references", "ok", `${references.length} reference(s); resolvers are URIs only, nothing is fetched`);
  }

  // -- canonicalization (diagnostic only) ---------------------------------------
  if (hasNonBmpKey(record)) {
    const codePoint = traceDigestCodePointOrder(record, "sha256");
    if (codePoint !== recordSha256) {
      const detail = `key order differs between RFC 8785 (UTF-16 code units) and code-point sort: rfc8785=${recordSha256} code_point=${codePoint}; parent links must use the rfc8785 value`;
      add("canonicalization", "ok", detail);
      note = detail;
    } else {
      add("canonicalization", "ok", "a key outside the BMP is present but both orderings agree");
    }
  } else {
    add("canonicalization", "skipped", "all keys within the BMP; both orderings agree");
  }

  const model = record["model"];
  const toolTranscript = record["tool_transcript"];
  const summary: TraceRecordSummary | null = schema.ok
    ? {
        subject,
        eat_profile: asString(profile),
        iat: asInt(record["iat"]) ?? 0,
        model_id: isObject(model) ? asString(model["model_id"]) : "",
        provider: isObject(model) ? asString(model["provider"]) : "",
        data_class: asString(record["data_class"]),
        key_thumbprint: keyThumbprint,
        has_delegation: delegation !== undefined,
        references: referenceCount,
        tool_calls: isObject(toolTranscript) ? asInt(toolTranscript["call_count"]) : null,
      }
    : null;
  return done(recordSha256, summary, record);
}
