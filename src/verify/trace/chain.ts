// The delegation-chain walk of the TRACE A2A delegation profile.
//
// A port of the reference walk in the trace-spec repository
// (tests/test_delegation_vectors.py): ten rules, each with a code, a
// severity, a class and the path it runs on; the walk starts at the leaf
// and follows `delegation.parent_record_hash` towards the root. Two
// orderings carry weight: `parent_not_found` never fires for a link whose
// digest algorithm this verifier does not compute, and a provenance
// failure outranks an authorization failure in the classification.
//
// Every record is indexed by the digest of its COMPLETE canonical form,
// signature included, under every supported algorithm. Nothing here reads
// the network; the record set is the whole universe.

import { MAX_TRACE_RECORDS } from "../../limits.js";
import { JsonNumber, type JsonObject, type JsonValue } from "../pyjson.js";
import { isDigestAlgorithm, traceDigest, traceDigestCodePointOrder, type DigestAlgorithm } from "./canon.js";
import { isObject, jwkIdentity, recordJwk, verifySignature } from "./keys.js";

export interface Credential {
  issuer?: string;
  holder?: string;
  not_before?: number;
  not_after?: number;
}

export interface ChainContext {
  /** Digest of the record under appraisal; absent → the record no other record names as parent. */
  leaf?: string;
  /** Carried for completeness; no rule reads it (windows are judged at each hop's own iat). */
  now?: number;
  max_depth?: number;
  supported_digest_algorithms?: string[];
  data_class_lattice?: string[];
  trusted_root_keys?: unknown[];
  credentials?: Record<string, Credential>;
}

export const CHAIN_DEFAULTS = {
  max_depth: 8,
  supported_digest_algorithms: ["sha256"],
  data_class_lattice: [] as string[],
  trusted_root_keys: [] as unknown[],
  credentials: {} as Record<string, Credential>,
};

export type Classification = "verified" | "provenance-invalid" | "authorization-invalid" | "unverifiable";

export interface WalkHop {
  record_sha256: string;
  subject: string;
  depth: number;
  delegation: { parent_record_hash: string; credential_id: string } | null;
  codes: string[];
}

export interface BrokenLink {
  record_sha256: string;
  code: string;
  detail: string;
}

export interface ChainVerification {
  classification: Classification;
  codes: string[];
  failures: string[];
  warnings: string[];
  depth: number;
  walk: WalkHop[];
  first_broken_link: BrokenLink | null;
  note: string | null;
}

type Severity = "failure" | "warning";
type RuleClass = "provenance" | "authorization" | "unverifiable";
type Path = "record" | "root" | "resolve" | "link";

interface Hop {
  record: JsonObject;
  context: Required<Omit<ChainContext, "leaf" | "now">>;
  index: Map<string, JsonObject>;
  depth: number;
  parent: JsonObject | null;
  signatureInvalid: boolean;
}

interface Rule {
  code: string;
  severity: Severity;
  klass: RuleClass;
  path: Path;
  check: (hop: Hop) => boolean;
}

/** One line per code, for `first_broken_link.detail`. */
export const CODE_DETAIL: Record<string, string> = {
  record_signature_invalid: "the record's signature does not verify with the key it carries in cnf.jwk (or that key is not a type verified here)",
  root_key_untrusted: "the root record's cnf.jwk is not in context.trusted_root_keys (identity = kty, crv, x, y)",
  depth_exceeded: "the walk passed context.max_depth before reaching a root",
  digest_algorithm_unsupported: "the link's digest algorithm is not in context.supported_digest_algorithms; the link was not read",
  parent_not_found: "no record in the set has the digest named by delegation.parent_record_hash",
  credential_unknown: "delegation.credential_id is not a key of context.credentials (exact, case-sensitive match)",
  credential_issuer_mismatch: "the credential's issuer is not the parent record's subject",
  credential_holder_mismatch: "the credential's holder is not this record's subject",
  credential_window: "this record's iat lies outside the credential's [not_before, not_after] window",
  data_class_widened: "this record's data_class ranks above the parent's in context.data_class_lattice",
  leaf_not_found: "context.leaf names no record in the set under a supported digest algorithm",
  leaf_ambiguous: "context.leaf is absent and the set has no single record that no other record names as parent",
  too_many_records: `more than ${MAX_TRACE_RECORDS} records; run the walk locally`,
  record_not_object: "every record must be a JSON object",
};

function delegationOf(record: JsonObject): JsonObject | null {
  const d = record["delegation"];
  return isObject(d) ? d : null;
}

function str(v: JsonValue | undefined): string {
  return typeof v === "string" ? v : "";
}

function linkAlgorithm(hop: Hop): string {
  return str(delegationOf(hop.record)?.["parent_record_hash"]).split(":", 1)[0];
}

function linkDigest(hop: Hop): string {
  return str(delegationOf(hop.record)?.["parent_record_hash"]);
}

function credentialOf(hop: Hop): Credential | null {
  const id = delegationOf(hop.record)?.["credential_id"];
  if (typeof id !== "string") return null;
  const creds = hop.context.credentials;
  return Object.prototype.hasOwnProperty.call(creds, id) ? creds[id] : null;
}

function num(v: JsonValue | undefined): number | null {
  return v instanceof JsonNumber ? v.value : null;
}

const RULES: readonly Rule[] = [
  // -- every record on the chain ----------------------------------------------
  { code: "record_signature_invalid", severity: "failure", klass: "provenance", path: "record", check: (h) => h.signatureInvalid },
  // -- the record with no delegation block ---------------------------------------
  {
    code: "root_key_untrusted",
    severity: "failure",
    klass: "provenance",
    path: "root",
    check: (h) => {
      const trusted = new Set(h.context.trusted_root_keys.map(jwkIdentity));
      return !trusted.has(jwkIdentity(recordJwk(h.record) ?? {}));
    },
  },
  // -- following a link, before the parent is known -------------------------------
  { code: "depth_exceeded", severity: "failure", klass: "authorization", path: "resolve", check: (h) => h.depth > h.context.max_depth },
  {
    code: "digest_algorithm_unsupported",
    severity: "warning",
    klass: "unverifiable",
    path: "resolve",
    check: (h) => !h.context.supported_digest_algorithms.includes(linkAlgorithm(h)),
  },
  {
    code: "parent_not_found",
    severity: "failure",
    klass: "provenance",
    path: "resolve",
    // Guarded on support: a link this verifier cannot compute is unread, not broken.
    check: (h) => h.context.supported_digest_algorithms.includes(linkAlgorithm(h)) && !h.index.has(linkDigest(h)),
  },
  // -- the hop, once its parent has been resolved ----------------------------------
  { code: "credential_unknown", severity: "failure", klass: "authorization", path: "link", check: (h) => credentialOf(h) === null },
  {
    code: "credential_issuer_mismatch",
    severity: "failure",
    klass: "authorization",
    path: "link",
    check: (h) => {
      const cred = credentialOf(h);
      return cred !== null && cred.issuer !== str(h.parent?.["subject"]);
    },
  },
  {
    code: "credential_holder_mismatch",
    severity: "failure",
    klass: "authorization",
    path: "link",
    check: (h) => {
      const cred = credentialOf(h);
      return cred !== null && cred.holder !== str(h.record["subject"]);
    },
  },
  {
    code: "credential_window",
    severity: "failure",
    klass: "authorization",
    path: "link",
    check: (h) => {
      const cred = credentialOf(h);
      if (cred === null) return false;
      // Judged at the hop's own iat, never at context.now.
      const iat = num(h.record["iat"]);
      return !(iat !== null && typeof cred.not_before === "number" && typeof cred.not_after === "number" && cred.not_before <= iat && iat <= cred.not_after);
    },
  },
  {
    code: "data_class_widened",
    severity: "failure",
    klass: "authorization",
    path: "link",
    check: (h) => {
      const lattice = h.context.data_class_lattice;
      const mine = lattice.indexOf(str(h.record["data_class"]));
      const parents = lattice.indexOf(str(h.parent?.["data_class"]));
      // A class outside the supplied ordering is not comparable.
      if (mine < 0 || parents < 0) return false;
      return mine > parents;
    },
  },
];

function evaluate(hop: Hop, path: Path): { failures: string[]; warnings: string[] } {
  const failures: string[] = [];
  const warnings: string[] = [];
  for (const rule of RULES) {
    if (rule.path === path && rule.check(hop)) (rule.severity === "failure" ? failures : warnings).push(rule.code);
  }
  return { failures, warnings };
}

function refused(code: string, detail?: string): ChainVerification {
  return {
    classification: "unverifiable",
    codes: [code],
    failures: [],
    warnings: [code],
    depth: 0,
    walk: [],
    first_broken_link: { record_sha256: "", code, detail: detail ?? CODE_DETAIL[code] ?? code },
    note: null,
  };
}

function hopView(record: JsonObject, depth: number, codes: string[]): WalkHop {
  const d = delegationOf(record);
  return {
    record_sha256: traceDigest(record, "sha256"),
    subject: str(record["subject"]),
    depth,
    delegation: d ? { parent_record_hash: str(d["parent_record_hash"]), credential_id: str(d["credential_id"]) } : null,
    codes,
  };
}

/** Walk `records` from the leaf towards the root under `context`. */
export async function verifyDelegationChain(records: JsonValue[], context: ChainContext): Promise<ChainVerification> {
  if (records.length > MAX_TRACE_RECORDS) return refused("too_many_records");
  if (!records.every(isObject)) return refused("record_not_object");
  const set = records as JsonObject[];

  const supported = (context.supported_digest_algorithms ?? CHAIN_DEFAULTS.supported_digest_algorithms).filter(isDigestAlgorithm);
  const ctx: Hop["context"] = {
    max_depth: typeof context.max_depth === "number" ? context.max_depth : CHAIN_DEFAULTS.max_depth,
    supported_digest_algorithms: supported,
    data_class_lattice: Array.isArray(context.data_class_lattice) ? context.data_class_lattice.map(String) : CHAIN_DEFAULTS.data_class_lattice,
    trusted_root_keys: Array.isArray(context.trusted_root_keys) ? context.trusted_root_keys : CHAIN_DEFAULTS.trusted_root_keys,
    credentials: context.credentials && typeof context.credentials === "object" ? context.credentials : CHAIN_DEFAULTS.credentials,
  };

  const index = new Map<string, JsonObject>();
  for (const alg of supported) for (const r of set) index.set(traceDigest(r, alg), r);

  let leafDigest: string;
  if (typeof context.leaf === "string") {
    leafDigest = context.leaf;
  } else {
    const named = new Set(set.map((r) => str(delegationOf(r)?.["parent_record_hash"])));
    const candidates = set.filter((r) => !supported.some((alg) => named.has(traceDigest(r, alg))));
    if (candidates.length !== 1) return refused("leaf_ambiguous", `${CODE_DETAIL["leaf_ambiguous"]} (${candidates.length} candidates)`);
    leafDigest = traceDigest(candidates[0], supported[0] ?? "sha256");
  }
  const leaf = index.get(leafDigest);
  if (!leaf) return refused("leaf_not_found");

  const failures: string[] = [];
  const warnings: string[] = [];
  const walk: WalkHop[] = [];
  const signatureCache = new Map<JsonObject, boolean>();
  const signatureInvalid = async (r: JsonObject): Promise<boolean> => {
    let v = signatureCache.get(r);
    if (v === undefined) {
      v = (await verifySignature(r)).outcome !== "ok";
      signatureCache.set(r, v);
    }
    return v;
  };

  let current = leaf;
  let depth = 0;
  const visited = new Set<JsonObject>();
  const danglingLinks: string[] = [];

  for (;;) {
    const hopCodes: string[] = [];
    const take = (r: { failures: string[]; warnings: string[] }) => {
      failures.push(...r.failures);
      warnings.push(...r.warnings);
      hopCodes.push(...r.failures, ...r.warnings);
    };
    const hop: Hop = { record: current, context: ctx, index, depth, parent: null, signatureInvalid: await signatureInvalid(current) };
    const hopDepth = depth;

    take(evaluate(hop, "record"));

    if (delegationOf(current) === null && !("delegation" in current)) {
      take(evaluate(hop, "root"));
      walk.push(hopView(current, hopDepth, hopCodes));
      break;
    }

    depth += 1;
    hop.depth = depth;
    take(evaluate(hop, "resolve"));

    let parent: JsonObject | null = null;
    if (ctx.supported_digest_algorithms.includes(linkAlgorithm(hop))) {
      parent = index.get(linkDigest(hop)) ?? null;
      if (parent === null) danglingLinks.push(linkDigest(hop));
    }
    if (parent === null) {
      walk.push(hopView(current, hopDepth, hopCodes));
      break;
    }

    hop.parent = parent;
    take(evaluate(hop, "link"));
    walk.push(hopView(current, hopDepth, hopCodes));

    // Not a conformance rule: a cycle needs a hash collision. Here so the walk terminates on any input.
    if (visited.has(parent)) break;
    visited.add(parent);
    current = parent;
  }

  const provenance = new Set(RULES.filter((r) => r.klass === "provenance").map((r) => r.code));
  const classification: Classification = failures.some((c) => provenance.has(c))
    ? "provenance-invalid"
    : failures.length > 0
      ? "authorization-invalid"
      : warnings.length > 0
        ? "unverifiable"
        : "verified";

  const firstBroken = walk.find((h) => h.codes.length > 0);
  const first_broken_link: BrokenLink | null = firstBroken
    ? { record_sha256: firstBroken.record_sha256, code: firstBroken.codes[0], detail: CODE_DETAIL[firstBroken.codes[0]] ?? firstBroken.codes[0] }
    : null;

  // Supplementary-plane diagnostic: does the dangling link resolve under code-point key order?
  let note: string | null = null;
  if (danglingLinks.length > 0) {
    const shortcut = new Map<string, JsonObject>();
    for (const alg of supported) for (const r of set) shortcut.set(traceDigestCodePointOrder(r, alg), r);
    for (const link of danglingLinks) {
      const hit = shortcut.get(link);
      if (hit) {
        const alg = (link.split(":", 1)[0] || "sha256") as DigestAlgorithm;
        note = `parent link ${link} resolves only under code-point key order; RFC 8785 orders keys by UTF-16 code units, so the producer's canonicalizer took the code-point shortcut on a key outside the BMP (rfc8785 digest of that parent: ${traceDigest(hit, alg)})`;
        break;
      }
    }
  }

  return {
    classification,
    codes: [...new Set([...failures, ...warnings])].sort(),
    failures,
    warnings,
    depth,
    walk,
    first_broken_link,
    note,
  };
}
