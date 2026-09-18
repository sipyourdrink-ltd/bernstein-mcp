import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index.js";
import { MAX_BODY_BYTES } from "../src/limits.js";
import { receiptString } from "./helpers.js";
import { buildReceipt } from "../cli/receipt.js";
import { importKey } from "../cli/keys.js";
import { GENESIS, hashRow, type RowInput } from "../cli/rows.js";
import { TEST_JWK } from "./cli/fixtures/test-key.js";

/**
 * A session receipt built the way `cli/receipt.ts` writes one, so the
 * request-log test below exercises the same `producer` block a real
 * `bernstein-attest` run leaves behind. Task 11 replaces this with the
 * frozen `vectors/session/session-valid.json` vector.
 */
async function sessionReceiptText(): Promise<string> {
  let head = GENESIS;
  const rows: RowInput[] = [];
  const inputs: RowInput[] = [
    { event: "session_started", agent: "claude-code", producer: "bernstein-attest 0.2.0", project: "demo", cwd_sha256: "c".repeat(64), ts: 1 },
    { event: "tool_call", tool: "Write", tool_use_id: "toolu_1", input_sha256: "a".repeat(64), output_sha256: "b".repeat(64), ok: true, path: "src/x.ts", ts: 2 },
    { event: "turn_ended", turn: 1, last_message_sha256: "d".repeat(64), ts: 3 },
  ];
  for (const input of inputs) {
    const r = hashRow(input, head);
    rows.push(r.row);
    head = r.head;
  }
  const sealed = await buildReceipt({
    runId: "sess-log-1",
    rows,
    files: [{ path: "src/x.ts", stepId: "toolu_1", contentSha256: "e".repeat(64) }],
    agent: "claude-code",
    model: "unknown",
    key: await importKey(TEST_JWK),
    now: 4,
  });
  return sealed.text;
}

const env = {} as Env;
const ctx = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

function req(path: string, init?: RequestInit): Request {
  return new Request(`https://mcp.bernstein.run${path}`, init);
}

const mcpHeaders = {
  "content-type": "application/json",
  accept: "application/json, text/event-stream",
};

function initializeMessage(id: number | string = 1) {
  return {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "vitest", version: "0" },
    },
  };
}

async function callFetch(body: unknown, headers: Record<string, string> = mcpHeaders) {
  return worker.fetch(
    req("/mcp", { method: "POST", headers, body: JSON.stringify(body) }),
    env,
    ctx,
  );
}

describe("POST /mcp — initialize", () => {
  it("returns 200 with serverInfo and tools capability", async () => {
    const res = await callFetch(initializeMessage());
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");

    const body = (await res.json()) as any;
    expect(body.result.serverInfo.name).toBe("bernstein");
    expect(body.result.capabilities.tools).toBeDefined();
  });
});

describe("POST /mcp — tools/list", () => {
  it("contains server_info", async () => {
    const res = await callFetch({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    const names = body.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain("server_info");
  });
});

describe("GET /mcp", () => {
  it("405s — stateless mode has no standalone SSE stream", async () => {
    const res = await worker.fetch(req("/mcp", { method: "GET" }), env, ctx);
    expect(res.status).toBe(405);
    expect(res.headers.get("content-type")).toMatch(/application\/json/);
    expect(res.headers.get("allow")).toBe("POST");
  });
});

describe("POST /mcp — body limits", () => {
  it("1.1 MB body -> 413", async () => {
    const oversized = "a".repeat(MAX_BODY_BYTES + 100_000);
    const res = await worker.fetch(
      req("/mcp", {
        method: "POST",
        headers: mcpHeaders,
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { pad: oversized } }),
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(413);
    const body = (await res.json()) as any;
    expect(body.error.code).toBeTypeOf("number");
  });

  it("invalid JSON -> JSON-RPC parse error, never a 500", async () => {
    const res = await worker.fetch(
      req("/mcp", { method: "POST", headers: mcpHeaders, body: "{not json" }),
      env,
      ctx,
    );
    expect([200, 400]).toContain(res.status);
    expect(res.status).not.toBe(500);
    const body = (await res.json()) as any;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error.code).toBe(-32700);
  });

  it("deep-nested JSON (depth 40) -> JSON-RPC error, no crash", async () => {
    let value: unknown = "leaf";
    for (let i = 0; i < 40; i++) value = { nested: value };
    const res = await worker.fetch(
      req("/mcp", {
        method: "POST",
        headers: mcpHeaders,
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { deep: value } }),
      }),
      env,
      ctx,
    );
    expect(res.status).not.toBe(500);
    const body = (await res.json()) as any;
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error).toBeDefined();
  });
});

describe("GET /healthz", () => {
  it("returns ok + version", async () => {
    const res = await worker.fetch(req("/healthz"), env, ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.ok).toBe(true);
    expect(body.version).toBe("v3.19.2");
  });
});

describe("GET /", () => {
  it("returns 200 text/html", async () => {
    const res = await worker.fetch(req("/"), env, ctx);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const text = await res.text();
    expect(text).toContain("claude mcp add");
  });
});

describe("GET /verify/*", () => {
  it("404s a path that is not a digest", async () => {
    const res = await worker.fetch(req("/verify/abc123"), env, ctx);
    expect(res.status).toBe(404);
  });
});

describe("unknown routes", () => {
  it("404s as JSON", async () => {
    const res = await worker.fetch(req("/nope"), env, ctx);
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toMatch(/application\/json/);
    // no CORS headers outside /verify/*
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("POST /mcp — rate limit binding", () => {
  function limiter(outcomes: boolean[]) {
    const keys: string[] = [];
    return {
      keys,
      binding: {
        limit: async ({ key }: { key: string }) => {
          keys.push(key);
          return { success: outcomes.shift() ?? true };
        },
      },
    };
  }

  it("keys the limiter by client IP and answers 429 once the bucket is spent", async () => {
    const l = limiter([true, false]);
    const limitedEnv = { MCP_RATE_LIMITER: l.binding } as unknown as Env;
    const headers = { ...mcpHeaders, "cf-connecting-ip": "203.0.113.7" };

    const first = await worker.fetch(
      req("/mcp", { method: "POST", headers, body: JSON.stringify(initializeMessage()) }),
      limitedEnv,
      ctx,
    );
    expect(first.status).toBe(200);

    const second = await worker.fetch(
      req("/mcp", { method: "POST", headers, body: JSON.stringify(initializeMessage()) }),
      limitedEnv,
      ctx,
    );
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBe("60");
    expect(await second.json()).toMatchObject({ error: "rate_limited" });
    expect(l.keys).toEqual(["203.0.113.7", "203.0.113.7"]);
  });

  it("does not limit /healthz", async () => {
    const l = limiter([false]);
    const limitedEnv = { MCP_RATE_LIMITER: l.binding } as unknown as Env;
    const res = await worker.fetch(req("/healthz"), limitedEnv, ctx);
    expect(res.status).toBe(200);
    expect(l.keys).toEqual([]);
  });
});

describe("request log line", () => {
  it("records route, rpc method, tool, verdict and client — never the body", async () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(String(line)));
    try {
      const receipt = receiptString("valid-short-with-audit-range");
      const rpc = (method: string, params: unknown) =>
        new Request("https://mcp.bernstein.run/mcp", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "cf-connecting-ip": "203.0.113.9" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
      await worker.fetch(rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test-client", version: "9.9" } }), env, ctx);
      await worker.fetch(rpc("tools/call", { name: "verify_receipt", arguments: { receipt } }), env, ctx);
      await worker.fetch(new Request("https://mcp.bernstein.run/verify", { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ receipt }) }), env, ctx);
      await worker.fetch(new Request("https://mcp.bernstein.run/verify/" + "0".repeat(64)), env, ctx);
      const logs = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.evt === "mcp.request");
      expect(logs).toHaveLength(4);
      expect(logs[0]).toMatchObject({ route: "/mcp", method: "POST", status: 200, rpc: "initialize", client: "test-client", client_version: "9.9", protocol: "2025-06-18" });
      expect(logs[1]).toMatchObject({ route: "/mcp", rpc: "tools/call", tool: "verify_receipt", verdict: "valid" });
      expect(logs[2]).toMatchObject({ route: "/verify", method: "POST", verdict: "valid" });
      expect(logs[3]).toMatchObject({ route: "/verify/<sha256>", method: "GET", status: 200 });
      for (const l of logs) {
        expect(JSON.stringify(l)).not.toContain("203.0.113.9");
        expect(JSON.stringify(l)).not.toContain("run_id");
      }
    } finally {
      spy.mockRestore();
    }
  });

  it("logs the producer family of a verified receipt, never the raw label", async () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: string) => void lines.push(String(line)));
    try {
      const sessionReceipt = await sessionReceiptText();
      const res = await worker.fetch(
        new Request("https://mcp.bernstein.run/verify", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: "receipt=" + encodeURIComponent(sessionReceipt),
        }),
        env,
        ctx,
      );
      expect(res.status).toBe(200);
      const logs = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.evt === "mcp.request");
      const line = logs.find((l) => l.route === "/verify" && l.method === "POST");
      expect(line?.producer).toBe("bernstein-attest");
      expect(JSON.stringify(line)).not.toContain("0.2.0");
    } finally {
      spy.mockRestore();
    }
  });
});
