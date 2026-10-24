import { describe, expect, it } from "vitest";
import { summarizeInvocations, summarizeLogs, renderMarkdown } from "../scripts/metrics-snapshot";
const line = (fields: Record<string, unknown>) => JSON.stringify({ evt: "mcp.request", ...fields });

describe("metrics snapshot", () => {
  it("sums API invocations and keeps errors separate from HTTP statuses", () => {
    const result = summarizeInvocations([
      { sum: { requests: 8, errors: 2, subrequests: 3 }, dimensions: { status: "ok" } },
      { sum: { requests: 2, errors: 1, subrequests: 0 }, dimensions: { status: "exception" } },
    ]);
    expect(result).toMatchObject({ requests: 10, exceptions: 3, subrequests: 3, statuses: { ok: 8, exception: 2 }, coverage: "unknown", earliest: null, latest: null, retention: "unverified" });
    expect(summarizeInvocations([]).requests).toBeNull();
    expect(summarizeInvocations([{ sum: { requests: 2 }, dimensions: { status: 200 } }]).statuses).toEqual({ "200": 2 });
    expect(summarizeInvocations([{ sum: { requests: 2 } }]).exceptions).toBeNull();
  });
  it("reports timestamp bounds and partial timestamp coverage honestly", () => {
    expect(summarizeInvocations([
      { dimensions: { datetime: "2026-09-20T00:00:00Z" } },
      { timestamp: "2026-09-19T00:00:00Z" },
      { dimensions: {} },
    ])).toMatchObject({ earliest: "2026-09-19T00:00:00.000Z", latest: "2026-09-20T00:00:00.000Z", coverage: "partial" });
  });
  it("counts direct and tail events while ignoring noise", () => {
    const result = summarizeLogs([
      line({ status: 200, rpc: "initialize", client: "a", client_version: "1", tool: "check", verdict: "pass", country: "IL" }),
      JSON.stringify({ logs: [{ message: [line({ status: 429, country: "US" }), "plain text", "{}"] }] }),
      line({ status: 413 }), line({ status: 500 }), line({ status: 503 }), line({ status: 204 }),
      "invalid", "null", JSON.stringify({ evt: "other" }), JSON.stringify({ logs: [null] }),
    ]);
    expect(result).toMatchObject({ requests: 6, statuses: { "200": 1, "204": 1, "429": 1, "413": 1, "500": 1, "503": 1 }, statusClasses: { "2xx": 2, "4xx": 2, "5xx": 2 }, status413: 1, status429: 1, loggedStatusGte500: 2, tools: { check: 1 }, verdicts: { pass: 1 }, topCountries: [{ country: "IL", requests: 1 }, { country: "US", requests: 1 }] });
  });
  it("deduplicates initialize tuples and excludes noninitialize or unnamed clients", () => {
    const result = summarizeLogs([
      line({ rpc: "initialize", client: "a", client_version: "1" }),
      line({ rpc: "initialize", client: "a", client_version: "1" }),
      line({ rpc: "initialize,tools/list", client: "a", client_version: "2" }),
      line({ rpc: ["tools/list", "initialize"], client: "b" }),
      line({ rpc: "tools/call", client: "ignored" }),
      line({ rpc: "notinitialize", client: "ignored" }), line({ rpc: "initialize" }),
    ]);
    expect(result.distinctClients).toBe(3);
    expect(result.clients).toEqual([{ client: "a", client_version: "1" }, { client: "a", client_version: "2" }, { client: "b", client_version: null }]);
  });
  it("limits countries to ten in deterministic count order", () => {
    const result = summarizeLogs(Array.from({ length: 12 }, (_, i) => line({ country: `C${i}` })));
    expect(result.topCountries).toHaveLength(10);
    expect(summarizeLogs([]).distinctClients).toBe(0);
  });
  it("counts inherited object names as ordinary keys", () => {
    const logs = summarizeLogs([line({ tool: "__proto__", verdict: "constructor", country: "toString", status: 600 })]);
    expect(logs.tools["__proto__"]).toBe(1);
    expect(logs.verdicts["constructor"]).toBe(1);
    expect(logs.topCountries).toEqual([{ country: "toString", requests: 1 }]);
    expect(logs.statusClasses["5xx"]).toBe(0);
    expect(logs.loggedStatusGte500).toBe(1);
    expect(summarizeInvocations([{ sum: { requests: 2 }, dimensions: { status: "__proto__" } }]).statuses["__proto__"]).toBe(2);
  });
  it("renders measured facts and exact thresholds without advice", () => {
    const output = renderMarkdown({ window: { since: "2026-09-18T00:00:00Z", until: "2026-10-01T00:00:00Z" }, api: null, logs: summarizeLogs([line({ status: 500 })]) });
    const threshold = "<20 clients freeze; 20–100 keep; >=100 bring T8 forward";
    expect(output).toContain(threshold);
    expect(output).toContain("API requests: unknown; logged requests: 1");
    expect(output).toContain("Measured distinct (client, client_version) pairs on initialize: 0");
    expect(output).toContain("retention: unverified");
    expect(output).toContain("## Data limits");
    expect(output).not.toMatch(/recommend|freeze now/i);
    expect(output.replace(threshold, "")).not.toMatch(/keep/i);
  });
});
