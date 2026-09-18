// Both agents send one JSON document on stdin. The shapes differ in small
// ways (Claude Code: `tool_response`, a separate PostToolUseFailure event;
// Codex: `tool_response`, `model`, `turn_id`); everything downstream sees
// one HookEvent. Unknown events and unparsable input are ignored, never
// errors — a hook that fails would slow the agent for nothing.
export type Agent = "claude-code" | "codex";
export type HookEvent =
  | { kind: "tool"; sessionId: string; cwd: string; toolName: string; toolUseId: string; toolInput: unknown; toolOutput: unknown; ok: boolean; agentId?: string; agentType?: string; model?: string }
  | { kind: "stop"; sessionId: string; cwd: string; lastMessage: string; model?: string }
  | { kind: "end"; sessionId: string; cwd: string; reason: string }
  | { kind: "ignore" };

type P = Record<string, unknown>;
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const opt = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

export function normalise(agent: Agent, payload: unknown): HookEvent {
  if (!payload || typeof payload !== "object") return { kind: "ignore" };
  const p = payload as P;
  const sessionId = str(p["session_id"]);
  const cwd = str(p["cwd"]);
  const model = agent === "codex" ? opt(p["model"]) : undefined;
  switch (str(p["hook_event_name"])) {
    case "PostToolUse":
    case "PostToolUseFailure": {
      const failure = p["hook_event_name"] === "PostToolUseFailure";
      const response = p["tool_response"] ?? p["tool_output"] ?? null;
      const flagged = p["tool_output_is_error"] === true || (response && typeof response === "object" && ((response as P)["is_error"] === true || (response as P)["isError"] === true));
      return {
        kind: "tool", sessionId, cwd,
        toolName: str(p["tool_name"]), toolUseId: str(p["tool_use_id"]),
        toolInput: p["tool_input"] ?? null, toolOutput: failure ? (p["error"] ?? null) : response,
        ok: !failure && !flagged,
        agentId: opt(p["agent_id"]), agentType: opt(p["agent_type"]), model,
      };
    }
    case "Stop":
      return { kind: "stop", sessionId, cwd, lastMessage: str(p["last_assistant_message"]), model };
    case "SessionEnd":
      return { kind: "end", sessionId, cwd, reason: str(p["reason"] ?? p["end_reason"]) || "unknown" };
    default:
      return { kind: "ignore" };
  }
}
