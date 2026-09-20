/// <reference types="node" />
// verify_trace_record: one TRACE v0.2 Trust Record, check by check.

import { describe, expect, it } from "vitest";
import { verifyTraceRecord, TRACE_CHECK_ORDER } from "../src/verify/trace/record.js";
import { traceDigest, hasNonBmpKey, jcsCodePointOrder } from "../src/verify/trace/canon.js";
import { validateTraceRecord } from "../src/verify/trace/schema.js";
import { fromParsed, jcs, parseJson } from "../src/verify/pyjson.js";
import { bernsteinRecordText, traceVector, TRACE_VECTOR_NAMES } from "./helpers.js";

const BERNSTEIN = ["single-execution", "delegated-parent", "delegated-child", "delegated-grandchild", "aggregate"];

function check(v: Awaited<ReturnType<typeof verifyTraceRecord>>, name: string) {
  const c = v.checks.find((x) => x.name === name);
  if (!c) throw new Error(`no check ${name}`);
  return c;
}

describe("schema (vendored trace-claim.json)", () => {
  it("accepts every corpus record and every bernstein fixture", () => {
    for (const name of TRACE_VECTOR_NAMES) {
      for (const [i, r] of traceVector(name).records.entries()) {
        const res = validateTraceRecord(r);
        expect(res.ok, `${name} record ${i}: ${JSON.stringify(res.errors[0])}`).toBe(true);
      }
    }
    for (const name of BERNSTEIN) {
      const res = validateTraceRecord(JSON.parse(bernsteinRecordText(name)));
      expect(res.ok, `${name}: ${JSON.stringify(res.errors[0])}`).toBe(true);
    }
  });

  it("rejects an extra top-level key (additionalProperties: false)", () => {
    const r = { ...JSON.parse(bernsteinRecordText("single-execution")), extra: 1 };
    const res = validateTraceRecord(r);
    expect(res.ok).toBe(false);
    expect(res.errors[0].path).toBe("#/extra");
    expect(res.errors[0].message).toMatch(/extra/);
  });

  it("names the deepest failing path", () => {
    const r = JSON.parse(bernsteinRecordText("single-execution"));
    delete r.model.provider;
    const res = validateTraceRecord(r);
    expect(res.ok).toBe(false);
    expect(res.errors[0].path).toBe("#/model");
    expect(res.errors[0].message).toMatch(/provider/);
  });

  it("accepts a record carrying the reproducibility claim", () => {
    const r = {
      ...JSON.parse(bernsteinRecordText("single-execution")),
      reproducibility: {
        function: "verify_and_summarize",
        code_identity: "sha256:" + "a".repeat(64),
        input_closure: [
          {
            id: "transcript",
            digest: "sha256:" + "b".repeat(64),
            resolver: "run-cache"
          }
        ],
        transcript_digest: "sha256:" + "c".repeat(64)
      }
    };
    const res = validateTraceRecord(r);
    expect(res.ok, JSON.stringify(res.errors[0])).toBe(true);
  });
});

describe("canonicalization helpers", () => {
  it("digests the complete record, signature included", () => {
    const vec = traceVector("01-valid-single-hop");
    const leaf = fromParsed(vec.records[0]);
    expect(traceDigest(leaf, "sha256")).toBe(vec.context.leaf);
    const parent = fromParsed(vec.records[1]);
    expect(traceDigest(parent, "sha256")).toBe((vec.records[0].delegation as { parent_record_hash: string }).parent_record_hash);
    expect(traceDigest(parent, "sha384")).toMatch(/^sha384:[0-9a-f]{96}$/);
  });

  it("spots keys outside the BMP and orders them differently from RFC 8785", () => {
    const vec = traceVector("24-parent-key-supplementary-plane");
    const root = fromParsed(vec.records[1]);
    expect(hasNonBmpKey(root)).toBe(true);
    expect(hasNonBmpKey(fromParsed(vec.records[0]))).toBe(false);
    expect(jcsCodePointOrder(root)).not.toBe(jcs(root));
    expect(jcsCodePointOrder(fromParsed(vec.records[0]))).toBe(jcs(fromParsed(vec.records[0])));
  });
});

describe("verifyTraceRecord", () => {
  it("runs the checks in the documented order", async () => {
    const v = await verifyTraceRecord(bernsteinRecordText("single-execution"));
    expect(v.checks.map((c) => c.name)).toEqual([...TRACE_CHECK_ORDER]);
  });

  it.each(BERNSTEIN)("bernstein fixture %s is valid as a string", async (name) => {
    const text = bernsteinRecordText(name);
    const v = await verifyTraceRecord(text);
    expect(v.verdict, JSON.stringify(v.checks)).toBe("valid");
    expect(v.failing_check).toBeNull();
    expect(v.record_sha256).toBe(traceDigest(parseJson(text), "sha256"));
    expect(v.summary?.subject).toMatch(/^spiffe:\/\/bernstein\.run\/run\//);
    expect(v.summary?.eat_profile).toBe("tag:agentrust-io.com,2026:trace-v0.2");
    expect(v.summary?.provider).toBe("anthropic");
    expect(v.summary?.key_thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(check(v, "subject").detail).toMatch(/spiffe/);
    expect(check(v, "signature").outcome).toBe("ok");
    expect(check(v, "canonicalization").outcome).toBe("skipped");
  });

  it("verifies the same fixture passed as an object", async () => {
    const v = await verifyTraceRecord(JSON.parse(bernsteinRecordText("delegated-child")));
    expect(v.verdict).toBe("valid");
    expect(v.summary?.has_delegation).toBe(true);
    expect(check(v, "delegation").outcome).toBe("ok");
    expect(v.summary?.tool_calls).toBe(0);
  });

  it("reports references and delegation from the fixtures", async () => {
    const single = await verifyTraceRecord(bernsteinRecordText("single-execution"));
    expect(single.summary?.references).toBe(1);
    expect(single.summary?.has_delegation).toBe(false);
    expect(check(single, "delegation").outcome).toBe("skipped");
    expect(check(single, "references").outcome).toBe("ok");
    const agg = await verifyTraceRecord(bernsteinRecordText("aggregate"));
    expect(agg.summary?.references).toBeGreaterThan(0);
  });

  it("the child's parent_record_hash equals the parent's record_sha256", async () => {
    const parent = await verifyTraceRecord(bernsteinRecordText("delegated-parent"));
    const child = JSON.parse(bernsteinRecordText("delegated-child"));
    expect(child.delegation.parent_record_hash).toBe(parent.record_sha256);
  });

  it.each(TRACE_VECTOR_NAMES)("every record of %s passes the record checks except for key trust", async (name) => {
    for (const r of traceVector(name).records) {
      const v = await verifyTraceRecord(r);
      // Signature validity is per record; corpus vectors 06/07 carry a record signed by another key.
      const failing = v.checks.filter((c) => c.outcome === "fail").map((c) => c.name);
      expect(failing.every((f) => f === "signature"), `${name}: ${JSON.stringify(v.checks)}`).toBe(true);
    }
  });

  it("is unverifiable for text that is not JSON, and for a non-object", async () => {
    const bad = await verifyTraceRecord("{not json");
    expect(bad.verdict).toBe("unverifiable");
    expect(bad.checks).toHaveLength(1);
    expect(bad.checks[0].name).toBe("parse");
    const arr = await verifyTraceRecord("[1,2]");
    expect(arr.verdict).toBe("unverifiable");
    expect(arr.summary).toBeNull();
  });

  it("fails schema on an extra key and names it", async () => {
    const r = { ...JSON.parse(bernsteinRecordText("single-execution")), extra: 1 };
    const v = await verifyTraceRecord(r);
    expect(v.verdict).toBe("invalid");
    expect(v.failing_check).toBe("schema");
    expect(check(v, "schema").detail).toMatch(/extra/);
  });

  it("fails profile, subject, runtime, policy, appraisal on the wrong values", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const cases: [string, Record<string, unknown>, RegExp][] = [
      ["profile", { eat_profile: "tag:example,2026:other" }, /eat_profile/],
      ["subject", { subject: "not a uri" }, /URI/],
      ["runtime", { runtime: { platform: "software-only", measurement: "sha256:" + "1".repeat(64) } }, /software-only runtime claims a measurement/],
      ["policy", { policy: { bundle_hash: "sha256:abc", enforcement_mode: "enforce" } }, /bundle_hash/],
      ["appraisal", { appraisal: { status: "none", verifier: "verifier without scheme" } }, /verifier/],
    ];
    for (const [name, patch, re] of cases) {
      const v = await verifyTraceRecord({ ...base, ...patch });
      expect(v.verdict, name).toBe("invalid");
      const c = check(v, name);
      expect(c.outcome, name).toBe("fail");
      expect(c.detail, name).toMatch(re);
    }
  });

  it("passes runtime for a hardware platform without evaluating the measurement", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const v = await verifyTraceRecord({ ...base, runtime: { platform: "intel-tdx", measurement: "sha384:" + "a".repeat(96) } });
    expect(check(v, "runtime").outcome).toBe("ok");
    expect(check(v, "runtime").detail).toMatch(/not evaluated/);
  });

  it("refuses a JWK carrying a private member", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const v = await verifyTraceRecord({ ...base, cnf: { jwk: { ...base.cnf.jwk, d: "AAAA" } } });
    expect(v.verdict).toBe("invalid");
    expect(check(v, "cnf_key").outcome).toBe("fail");
    expect(check(v, "cnf_key").detail).toMatch(/private key member/);
  });

  it("is unverifiable for an unsigned record and for an unsupported key type", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const { signature: _sig, ...unsigned } = base;
    const u = await verifyTraceRecord(unsigned);
    expect(u.verdict).toBe("unverifiable");
    expect(u.failing_check).toBeNull();
    expect(check(u, "signature").outcome).toBe("unverifiable");
    expect(check(u, "signature").detail).toMatch(/unsigned record/);
    const rsa = await verifyTraceRecord({ ...base, cnf: { jwk: { kty: "RSA", n: "AQAB", e: "AQAB" } } });
    expect(rsa.verdict).toBe("unverifiable");
    expect(check(rsa, "signature").detail).toMatch(/RSA/);
  });

  it("fails a tampered signed record", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const v = await verifyTraceRecord({ ...base, data_class: "public" });
    expect(v.verdict).toBe("invalid");
    expect(v.failing_check).toBe("signature");
  });

  it("verifies an ES256 (P-256) signature made in this test", async () => {
    const base = JSON.parse(bernsteinRecordText("single-execution"));
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
    const { signature: _sig, ...body } = base;
    body.cnf = { jwk: { kty: "EC", crv: "P-256", x: pub.x, y: pub.y } };
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(jcs(fromParsed(body)))));
    const b64u = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const v = await verifyTraceRecord({ ...body, signature: b64u });
    expect(v.verdict, JSON.stringify(v.checks)).toBe("valid");
    expect(check(v, "signature").detail).toMatch(/ES256/);
    expect(v.summary?.key_thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const tampered = await verifyTraceRecord({ ...body, iat: body.iat + 1, signature: b64u });
    expect(tampered.failing_check).toBe("signature");
  });

  it("reports the key-order divergence for a record with a key outside the BMP", async () => {
    const root = traceVector("24-parent-key-supplementary-plane").records[1];
    const v = await verifyTraceRecord(root);
    expect(v.verdict).toBe("valid");
    const c = check(v, "canonicalization");
    expect(c.outcome).toBe("ok");
    expect(c.detail).toMatch(/rfc8785=sha256:[0-9a-f]{64} code_point=sha256:[0-9a-f]{64}/);
    expect(c.detail).toContain(v.record_sha256);
    expect(v.note).toBe(c.detail);
  });
});
