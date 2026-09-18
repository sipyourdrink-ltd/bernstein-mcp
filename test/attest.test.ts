/// <reference types="node" />
// A verdict leaves the endpoint as a DSSE envelope signed by the deployment
// key. Anyone holding the public JWK from /.well-known/bernstein-mcp/keys.json
// must be able to re-check it offline with nothing but WebCrypto.

import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.js";
import { KEYS_PATH, VERDICT_PAYLOAD_TYPE, VERDICT_STATEMENT_TYPE, jwkThumbprint, loadSigner, signVerdict } from "../src/verify/attest.js";
import { pae, producerFamily, producerLabel, verifyReceipt } from "../src/verify/receipt.js";
import { receiptString } from "./helpers.js";

const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined } as unknown as ExecutionContext;

async function testKey(): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d });
}

function b64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function checkEnvelope(envelope: { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] }, publicJwk: { x: string; kid: string }) {
  const key = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: publicJwk.x }, { name: "Ed25519" }, false, ["verify"]);
  const payload = b64(envelope.payload);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64(envelope.signatures[0].sig) as BufferSource, pae(envelope.payloadType, payload) as BufferSource);
  return { ok, statement: JSON.parse(new TextDecoder().decode(payload)), keyid: envelope.signatures[0].keyid };
}

describe("signed verdicts", () => {
  it("signs a statement that re-verifies against the published key", async () => {
    const env = { VERDICT_SIGNING_KEY: await testKey() } as Env;
    const keys = await worker.fetch(new Request(`https://mcp.bernstein.run${KEYS_PATH}`), env, ctx);
    expect(keys.status).toBe(200);
    expect(keys.headers.get("cache-control")).toBe("public, max-age=3600");
    const { keys: [publicJwk] } = (await keys.json()) as { keys: { x: string; kid: string; alg: string }[] };
    expect(publicJwk.alg).toBe("EdDSA");
    expect(publicJwk.kid).toBe(jwkThumbprint(publicJwk.x));

    const receipt = receiptString("valid-short-with-audit-range");
    const res = await worker.fetch(
      new Request("https://mcp.bernstein.run/verify", { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ receipt }) }),
      env,
      ctx,
    );
    const body = (await res.json()) as any;
    expect(body.keys_url).toBe(`https://mcp.bernstein.run${KEYS_PATH}`);
    const { ok, statement, keyid } = await checkEnvelope(body.signed_verdict, publicJwk);
    expect(ok).toBe(true);
    expect(keyid).toBe(publicJwk.kid);
    expect(body.signed_verdict.payloadType).toBe(VERDICT_PAYLOAD_TYPE);
    expect(statement.statement_type).toBe(VERDICT_STATEMENT_TYPE);
    expect(statement.verdict).toBe("valid");
    expect(statement.receipt_sha256).toBe(body.receipt_sha256);
    expect(statement.checks).toEqual(body.checks);
    expect(statement.appraisal).toMatchObject({ status: "affirming", verifier: "https://mcp.bernstein.run" });
    expect(statement.appraisal.timestamp).toBe(statement.issued_at);
    // A flipped bit anywhere in the statement must break the signature.
    const tampered = { ...body.signed_verdict, payload: btoa(atob(body.signed_verdict.payload).replace('"valid"', '"invalid"')) };
    expect((await checkEnvelope(tampered, publicJwk)).ok).toBe(false);
  });

  it("maps invalid → contraindicated and unverifiable → none", async () => {
    const signer = (await loadSigner(await testKey()))!;
    const bad = await signVerdict(await verifyReceipt(receiptString("invalid-entry-tampered")), signer, "test");
    expect(JSON.parse(atob(bad.payload)).appraisal.status).toBe("contraindicated");
    const none = await signVerdict(await verifyReceipt("{}"), signer, "test");
    expect(JSON.parse(atob(none.payload)).appraisal.status).toBe("none");
  });

  it("is exposed by the MCP tools and absent without a key", async () => {
    const env = { VERDICT_SIGNING_KEY: await testKey() } as Env;
    const call = async (e: Env, tool: string, args: Record<string, unknown>) => {
      const res = await worker.fetch(
        new Request("https://mcp.bernstein.run/mcp", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }),
        }),
        e,
        ctx,
      );
      return ((await res.json()) as any).result.structuredContent;
    };
    const info = await call(env, "server_info", {});
    expect(info.verdict_key.kid).toBe(jwkThumbprint(info.verdict_key.x));
    const out = await call(env, "verify_receipt", { receipt: receiptString("valid-short-with-audit-range") });
    expect((await checkEnvelope(out.signed_verdict, info.verdict_key)).ok).toBe(true);

    const bare = {} as Env;
    expect((await call(bare, "server_info", {})).verdict_key).toBeNull();
    expect((await call(bare, "verify_receipt", { receipt: "{}" })).signed_verdict).toBeNull();
    const keys = await worker.fetch(new Request(`https://mcp.bernstein.run${KEYS_PATH}`), bare, ctx);
    expect(await keys.json()).toEqual({ keys: [] });
  });

  it("ignores a malformed key instead of failing verification", async () => {
    const env = { VERDICT_SIGNING_KEY: "not a jwk" } as Env;
    const res = await worker.fetch(
      new Request("https://mcp.bernstein.run/verify", { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ receipt: receiptString("valid-short-with-audit-range") }) }),
      env,
      ctx,
    );
    const body = (await res.json()) as any;
    expect(body.verdict).toBe("valid");
    expect(body.signed_verdict).toBeNull();
  });
});

describe("producer", () => {
  it("labels the producer block and classifies it", () => {
    expect(producerLabel({ producer: { name: "bernstein-attest", version: "0.2.0", agent: "claude-code" } } as any)).toBe("bernstein-attest 0.2.0 (claude-code)");
    expect(producerLabel({ producer: { name: "bernstein", version: "4.0.0" } } as any)).toBe("bernstein 4.0.0");
    expect(producerLabel({ producer: { name: 7 } } as any)).toBeNull();
    expect(producerLabel({} as any)).toBeNull();
    expect(producerFamily("bernstein-attest 0.2.0 (codex)")).toBe("bernstein-attest");
    expect(producerFamily("bernstein 4.0.0")).toBe("bernstein");
    expect(producerFamily("someone-else 1.0")).toBe("other");
    expect(producerFamily(null)).toBe("other");
  });
});
