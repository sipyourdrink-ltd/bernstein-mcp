/// <reference types="node" />
// verify_delegation_chain: the reference walk over the delegation-link corpus.

import { describe, expect, it } from "vitest";
import { verifyDelegationChain, type ChainContext } from "../src/verify/trace/chain.js";
import { traceDigest, jcsCodePointOrder } from "../src/verify/trace/canon.js";
import { sha256Hex } from "../src/verify/chains.js";
import { fromParsed, parseJson, utf8, type JsonObject, type JsonValue } from "../src/verify/pyjson.js";
import { MAX_TRACE_RECORDS } from "../src/limits.js";
import { bernsteinRecordText, traceVector, TRACE_VECTOR_NAMES } from "./helpers.js";

function records(vec: { records: Record<string, unknown>[] }): JsonValue[] {
  return vec.records.map((r) => fromParsed(r));
}

describe("delegation-link corpus", () => {
  it("has all 24 vectors", () => {
    expect(TRACE_VECTOR_NAMES).toHaveLength(24);
    expect(TRACE_VECTOR_NAMES[0]).toBe("01-valid-single-hop");
    expect(TRACE_VECTOR_NAMES[23]).toBe("24-parent-key-supplementary-plane");
  });

  it.each(TRACE_VECTOR_NAMES)("%s reaches its declared outcome", async (name) => {
    const vec = traceVector(name);
    const out = await verifyDelegationChain(records(vec), vec.context as ChainContext);
    expect(out.classification, `${name}: ${JSON.stringify(out.codes)}`).toBe(vec.expected.classification);
    expect(out.codes).toEqual([...vec.expected.codes].sort());
    expect(out.walk[0].record_sha256).toBe(vec.context.leaf);
    for (const [i, hop] of out.walk.entries()) expect(hop.depth).toBe(i);
    if (out.codes.length === 0) expect(out.first_broken_link).toBeNull();
    else expect(out.first_broken_link?.code).toBeDefined();
  });

  it.each(TRACE_VECTOR_NAMES)("%s is independent of record order", async (name) => {
    const vec = traceVector(name);
    const base = await verifyDelegationChain(records(vec), vec.context as ChainContext);
    const rs = records(vec);
    for (const perm of [[...rs].reverse(), [...rs.slice(1), rs[0]]]) {
      const out = await verifyDelegationChain(perm, vec.context as ChainContext);
      expect(out.classification).toBe(base.classification);
      expect(out.codes).toEqual(base.codes);
    }
  });

  it("produces every classification across the corpus", async () => {
    const seen = new Set<string>();
    for (const name of TRACE_VECTOR_NAMES) {
      const vec = traceVector(name);
      seen.add((await verifyDelegationChain(records(vec), vec.context as ChainContext)).classification);
    }
    expect([...seen].sort()).toEqual(["authorization-invalid", "provenance-invalid", "unverifiable", "verified"]);
  });
});

describe("vector 24: key order outside the BMP", () => {
  const vec = traceVector("24-parent-key-supplementary-plane");
  const leaf = vec.records[0];
  const root = fromParsed(vec.records[1]);
  const claimed = (leaf.delegation as { parent_record_hash: string }).parent_record_hash;

  it("verifies with no codes and no note", async () => {
    const out = await verifyDelegationChain(records(vec), vec.context as ChainContext);
    expect(out.classification).toBe("verified");
    expect(out.codes).toEqual([]);
    expect(out.note).toBeNull();
  });

  it("the link resolves under RFC 8785 order and NOT under code-point order", () => {
    expect(traceDigest(root, "sha256")).toBe(claimed);
    const codePoint = "sha256:" + sha256Hex(utf8(jcsCodePointOrder(root)));
    expect(codePoint).not.toBe(claimed);
  });

  it("names the code-point shortcut when a producer took it", async () => {
    const codePoint = "sha256:" + sha256Hex(utf8(jcsCodePointOrder(root)));
    const shortcutLeaf = { ...leaf, delegation: { ...(leaf.delegation as object), parent_record_hash: codePoint } };
    const out = await verifyDelegationChain([fromParsed(shortcutLeaf), root], { ...vec.context, leaf: traceDigest(fromParsed(shortcutLeaf), "sha256") } as ChainContext);
    expect(out.codes).toContain("parent_not_found");
    expect(out.codes).toContain("record_signature_invalid");
    expect(out.note).toContain(`parent link ${codePoint} resolves only under code-point key order`);
    expect(out.note).toContain(`rfc8785 digest of that parent: ${claimed}`);
  });
});

describe("bernstein fixtures as a chain", () => {
  const parentText = bernsteinRecordText("delegated-parent");
  const childText = bernsteinRecordText("delegated-child");
  const grandText = bernsteinRecordText("delegated-grandchild");
  const parent = parseJson(parentText) as JsonObject;
  const child = parseJson(childText) as JsonObject;
  const grand = parseJson(grandText) as JsonObject;
  const subject = (r: JsonObject) => r["subject"] as string;
  const iat = (r: JsonObject) => Number((r["iat"] as { lexeme: string }).lexeme);
  const credId = (r: JsonObject) => (r["delegation"] as JsonObject)["credential_id"] as string;
  const { kid: _kid, ...rootJwk } = JSON.parse(parentText).cnf.jwk;

  function context(credentials: ChainContext["credentials"]): ChainContext {
    return {
      leaf: traceDigest(grand, "sha256"),
      max_depth: 8,
      supported_digest_algorithms: ["sha256"],
      trusted_root_keys: [rootJwk],
      credentials,
    };
  }

  it("verifies parent → child → grandchild with matching credentials", async () => {
    const creds = {
      [credId(child)]: { issuer: subject(parent), holder: subject(child), not_before: iat(child) - 60, not_after: iat(child) + 60 },
      [credId(grand)]: { issuer: subject(child), holder: subject(grand), not_before: iat(grand) - 60, not_after: iat(grand) + 60 },
    };
    // Two hops may share one credential id; the map then holds one entry and the walk must still verify.
    const out = await verifyDelegationChain([parent, child, grand], context(creds));
    expect(out.classification, JSON.stringify(out)).toBe("verified");
    expect(out.depth).toBe(2);
    expect(out.walk.map((h) => h.subject)).toEqual([subject(grand), subject(child), subject(parent)]);
  });

  it("flags the grandchild's widened data_class once a lattice makes the classes comparable", async () => {
    const creds = {
      [credId(child)]: { issuer: subject(parent), holder: subject(child), not_before: iat(child) - 60, not_after: iat(child) + 60 },
      [credId(grand)]: { issuer: subject(child), holder: subject(grand), not_before: iat(grand) - 60, not_after: iat(grand) + 60 },
    };
    const out = await verifyDelegationChain([parent, child, grand], { ...context(creds), data_class_lattice: ["public", "internal", "confidential", "restricted"] });
    expect(out.classification).toBe("authorization-invalid");
    expect(out.codes).toEqual(["data_class_widened"]);
    expect(out.first_broken_link?.record_sha256).toBe(traceDigest(grand, "sha256"));
  });

  it("is authorization-invalid with no credentials registered", async () => {
    const out = await verifyDelegationChain([parent, child, grand], context({}));
    expect(out.classification).toBe("authorization-invalid");
    expect(out.codes).toEqual(["credential_unknown"]);
    expect(out.first_broken_link?.record_sha256).toBe(traceDigest(grand, "sha256"));
    expect(out.first_broken_link?.code).toBe("credential_unknown");
  });

  it("finds the leaf on its own when context.leaf is absent", async () => {
    const out = await verifyDelegationChain([child, parent, grand], { ...context({}), leaf: undefined });
    expect(out.walk[0].record_sha256).toBe(traceDigest(grand, "sha256"));
  });

  it("applies the documented defaults for an empty context", async () => {
    const out = await verifyDelegationChain([parent, child, grand], {});
    expect(out.classification).toBe("provenance-invalid");
    expect(out.codes).toEqual(["credential_unknown", "root_key_untrusted"]);
  });
});

describe("refusals", () => {
  it("leaf_not_found when context.leaf names no record", async () => {
    const vec = traceVector("01-valid-single-hop");
    const out = await verifyDelegationChain(records(vec), { ...vec.context, leaf: "sha256:" + "0".repeat(64) } as ChainContext);
    expect(out.classification).toBe("unverifiable");
    expect(out.codes).toEqual(["leaf_not_found"]);
  });

  it("leaf_ambiguous when two records are unreferenced", async () => {
    // Two chains with distinct leaves and distinct roots (24's root carries extra JWK members).
    const a = traceVector("01-valid-single-hop");
    const b = traceVector("24-parent-key-supplementary-plane");
    const out = await verifyDelegationChain([...records(a), ...records(b)], { ...a.context, leaf: undefined } as ChainContext);
    expect(out.classification).toBe("unverifiable");
    expect(out.codes).toEqual(["leaf_ambiguous"]);
  });

  it("too_many_records above the limit", async () => {
    const vec = traceVector("03-valid-root-only");
    const many = Array.from({ length: MAX_TRACE_RECORDS + 1 }, () => fromParsed(vec.records[0]));
    const out = await verifyDelegationChain(many, vec.context as ChainContext);
    expect(out.classification).toBe("unverifiable");
    expect(out.codes).toEqual(["too_many_records"]);
  });

  it("treats a non-object delegation member as no delegation block (a root)", async () => {
    const vec = traceVector("03-valid-root-only");
    const root = { ...vec.records[0], delegation: null };
    const out = await verifyDelegationChain([fromParsed(root)], { ...vec.context, leaf: traceDigest(fromParsed(root), "sha256") } as ChainContext);
    // The altered record no longer verifies, but the walk must not read a link that is not there.
    expect(out.codes).toEqual(["record_signature_invalid"]);
    expect(out.codes).not.toContain("digest_algorithm_unsupported");
    expect(out.depth).toBe(0);
    expect(out.walk).toHaveLength(1);
    expect(out.walk[0].delegation).toBeNull();
  });

  it("record_not_object when a record is not a JSON object", async () => {
    const vec = traceVector("03-valid-root-only");
    const out = await verifyDelegationChain([...records(vec), fromParsed([1])], vec.context as ChainContext);
    expect(out.classification).toBe("unverifiable");
    expect(out.codes).toEqual(["record_not_object"]);
  });
});
