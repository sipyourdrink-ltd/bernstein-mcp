/// <reference types="node" />
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const THRESHOLDS = "<20 clients freeze; 20–100 keep; >=100 bring T8 forward";
const LIMITS = ["Client names are software identifiers, not people.", "No address data is collected.", "API retention is unverified.", "Logs may be sampled or incomplete; logged requests are not API invocation totals."];
type Row = Record<string, unknown>;
function object(value: unknown): Row | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : undefined;
}
function count(map: Record<string, number>, key: unknown): void {
  if (typeof key === "string" && key.length > 0) map[key] = (map[key] ?? 0) + 1;
}
function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}
export function summarizeInvocations(rows: readonly unknown[]) {
  const valid = rows.map(object).filter((row): row is Row => row !== undefined);
  function sum(field: string): number | null {
    if (valid.length === 0) return null;
    const values = valid.map(row => finite(object(row.sum)?.[field]));
    return values.every(value => value !== null) ? values.reduce<number>((total, value) => total + (value ?? 0), 0) : null;
  }
  const statuses: Record<string, number> = Object.create(null);
  const timestamps: string[] = [];
  for (const row of valid) {
    const dimensions = object(row.dimensions);
    const requests = finite(object(row.sum)?.requests);
    if ((typeof dimensions?.status === "string" || typeof dimensions?.status === "number") && requests !== null) {
      const status = String(dimensions.status);
      statuses[status] = (statuses[status] ?? 0) + requests;
    }
    const timestamp = dimensions?.datetime ?? row.datetime ?? row.timestamp;
    if (typeof timestamp === "string" && Number.isFinite(Date.parse(timestamp))) timestamps.push(new Date(timestamp).toISOString());
  }
  timestamps.sort();
  return {
    requests: sum("requests"), exceptions: sum("errors"), subrequests: sum("subrequests"), statuses,
    coverage: timestamps.length === 0 ? "unknown" : timestamps.length === valid.length ? "timestamp-bearing rows only; window completeness unknown" : "partial",
    earliest: timestamps[0] ?? null, latest: timestamps[timestamps.length - 1] ?? null,
    retention: "unverified",
  };
}

export function summarizeLogs(lines: readonly string[]) {
  const events: Row[] = [];
  function parse(message: string): unknown {
    try { return JSON.parse(message); } catch { return undefined; }
  }
  for (const line of lines) {
    const entry = object(parse(line));
    if (entry?.evt === "mcp.request") events.push(entry);
    else if (Array.isArray(entry?.logs)) {
      for (const log of entry.logs) {
        const messages = object(log)?.message;
        if (!Array.isArray(messages)) continue;
        for (const message of messages) {
          const event = typeof message === "string" ? object(parse(message)) : undefined;
          if (event?.evt === "mcp.request") events.push(event);
        }
      }
    }
  }
  const statuses: Record<string, number> = Object.create(null);
  const statusClasses = { "2xx": 0, "4xx": 0, "5xx": 0 };
  let loggedStatusGte500 = 0;
  const tools: Record<string, number> = Object.create(null);
  const verdicts: Record<string, number> = Object.create(null);
  const countries: Record<string, number> = Object.create(null);
  const clients = new Map<string, { client: string; client_version: string | null }>();
  for (const event of events) {
    if (typeof event.status === "number" && Number.isInteger(event.status)) {
      count(statuses, String(event.status));
      if (event.status >= 500) loggedStatusGte500++;
      const group = `${Math.floor(event.status / 100)}xx`;
      if (group in statusClasses) statusClasses[group as keyof typeof statusClasses]++;
    }
    count(tools, event.tool); count(verdicts, event.verdict); count(countries, event.country);
    const rpc = event.rpc;
    const initializes = typeof rpc === "string" ? rpc.split(",").map(method => method.trim()).includes("initialize") : Array.isArray(rpc) && rpc.includes("initialize");
    if (initializes && typeof event.client === "string" && event.client.length > 0) {
      const client = { client: event.client, client_version: typeof event.client_version === "string" ? event.client_version : null };
      clients.set(JSON.stringify([client.client, client.client_version]), client);
    }
  }
  const clientList = [...clients.values()].sort((a, b) => a.client.localeCompare(b.client) || (a.client_version ?? "").localeCompare(b.client_version ?? ""));
  return {
    requests: events.length, statuses, statusClasses,
    status413: statuses["413"] ?? 0, status429: statuses["429"] ?? 0, loggedStatusGte500,
    tools, verdicts,
    topCountries: Object.entries(countries).sort(([a, ac], [b, bc]) => bc - ac || a.localeCompare(b)).slice(0, 10).map(([country, requests]) => ({ country, requests })),
    distinctClients: clients.size, clients: clientList,
  };
}
type Snapshot = {
  window: { since: string; until: string };
  api: ReturnType<typeof summarizeInvocations> | null;
  logs: ReturnType<typeof summarizeLogs>;
  apiState?: string;
  thresholds?: string;
  limits?: readonly string[];
};
export function renderMarkdown(summary: Snapshot): string {
  const show = (value: unknown) => value === null || value === undefined ? "unknown" : String(value);
  return [
    "# MCP metrics snapshot", `Window: ${summary.window.since} → ${summary.window.until}`,
    `API: ${summary.apiState ?? (summary.api ? "available" : "unavailable")}`,
    `API requests: ${show(summary.api?.requests)}; logged requests: ${summary.logs.requests}`,
    `API exceptions: ${show(summary.api?.exceptions)}; logged status>=500: ${summary.logs.loggedStatusGte500}`,
    `API coverage: ${summary.api?.coverage ?? "unknown"}; earliest: ${show(summary.api?.earliest)}; latest: ${show(summary.api?.latest)}; retention: unverified`,
    `API statuses: ${JSON.stringify(summary.api?.statuses ?? {})}`,
    `Logged statuses: ${JSON.stringify(summary.logs.statuses)}`,
    `Logged status classes: ${JSON.stringify(summary.logs.statusClasses)}; HTTP 413: ${summary.logs.status413}; HTTP 429: ${summary.logs.status429}`,
    `Tools: ${JSON.stringify(summary.logs.tools)}`, `Verdicts: ${JSON.stringify(summary.logs.verdicts)}`,
    `Top 10 countries: ${JSON.stringify(summary.logs.topCountries)}`,
    `Measured distinct (client, client_version) pairs on initialize: ${summary.logs.distinctClients}`,
    `Clients: ${JSON.stringify(summary.logs.clients)}`, `Thresholds: ${THRESHOLDS}`,
    "## Data limits",
    ...(summary.limits ?? LIMITS).map(limit => `- ${limit}`),
    "Log timestamps are not guaranteed; the supplied log file is not verified to cover the requested window.",
  ].join("\n\n") + "\n";
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let since = "2026-09-18T00:00:00Z", until = new Date().toISOString(), logsPath: string | undefined;
  let noApi = false, format = "md";
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === "--no-api") { noApi = true; continue; }
    if (!["--since", "--until", "--logs-jsonl", "--format"].includes(flag)) throw new Error(`Unknown flag: ${flag}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${flag}`);
    if (flag === "--since") since = value;
    if (flag === "--until") until = value;
    if (flag === "--logs-jsonl") logsPath = value;
    if (flag === "--format") format = value;
  }
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
  if (![since, until].every(value => iso.test(value) && Number.isFinite(Date.parse(value))) || Date.parse(since) >= Date.parse(until)) throw new Error("Expected ISO dates with since before until");
  if (format !== "json" && format !== "md") throw new Error("Expected --format json|md");
  const logs = summarizeLogs(logsPath ? (await readFile(logsPath, "utf8")).split(/\r?\n/) : []);
  let api: Snapshot["api"] = null;
  let apiState = noApi ? "disabled" : "token unavailable";
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!noApi && token) {
    try {
      const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
        method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query($acc:String!,$script:String!,$from:Time!,$to:Time!){viewer{accounts(filter:{accountTag:$acc}){workersInvocationsAdaptive(limit:10000,filter:{scriptName:$script,datetime_geq:$from,datetime_lt:$to}){sum{requests errors subrequests} dimensions{status}}}}}",
          variables: { acc: "014c346e97ff3260b6956903e62f944d", script: "bernstein-mcp", from: since, to: until },
        }),
      });
      const raw = await response.text();
      let payload: Row | undefined;
      try { payload = object(JSON.parse(raw)); } catch { /* Raw non-JSON errors are printed below. */ }
      if (response.status !== 200 || !payload || payload.errors) {
        console.error(raw); apiState = "API error; see stderr";
      } else {
        const viewer = object(object(payload?.data)?.viewer);
        const accounts = viewer?.accounts;
        const rows = Array.isArray(accounts) ? object(accounts[0])?.workersInvocationsAdaptive : undefined;
        if (!Array.isArray(rows)) { console.error(raw); apiState = "API response missing invocation rows"; }
        else { api = summarizeInvocations(rows); apiState = "available; window coverage unknown"; }
      }
    } catch (error) { console.error(error instanceof Error ? error.message : String(error)); apiState = "API error; see stderr"; }
  }
  const summary: Snapshot = { window: { since, until }, api, apiState, logs, thresholds: THRESHOLDS, limits: [...LIMITS, "Log file window coverage is unverified."] };
  console.log(format === "json" ? JSON.stringify(summary, null, 2) : renderMarkdown(summary));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
