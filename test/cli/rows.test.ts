/// <reference types="node" />
import { describe, expect, it } from "vitest";
import { GENESIS, hashRow, sortedRow, toJsonObject } from "../../cli/rows.js";
import { walkJournal } from "../../src/verify/chains.js";

describe("journal rows", () => {
  it("hashes rows the verifier's walk accepts, independent of key order", () => {
    let head = GENESIS;
    const rows = [];
    const a = hashRow({ event: "session_started", agent: "claude-code", project: "demo", ts: 1700000000 }, head);
    rows.push(a.row); head = a.head;
    const b = hashRow({ ts: 1700000001, tool: "Bash", event: "tool_call", ok: true, tool_use_id: "toolu_1", input_sha256: "a".repeat(64), output_sha256: "b".repeat(64), command_head: "ls" }, head);
    rows.push(b.row); head = b.head;
    expect(a.row.index).toBe(0);
    expect(a.row.prev_hash).toBe("");
    expect(b.row.index).toBe(1);
    expect(b.row.prev_hash).toBe(a.row.event_hash);
    expect(head).toEqual({ index: 2, prev_hash: b.row.event_hash });
    const walk = walkJournal(rows.map(toJsonObject));
    expect(walk.divergentIndex).toBeNull();
    expect(walk.head).toBe(b.row.event_hash);
    expect(Object.keys(b.row)).toEqual([...Object.keys(b.row)].sort());
  });

  it("ignores ts when hashing the payload and catches a flipped boolean", () => {
    const x = hashRow({ event: "tool_call", ok: true, ts: 1 }, GENESIS);
    const y = hashRow({ event: "tool_call", ok: true, ts: 2 }, GENESIS);
    const z = hashRow({ event: "tool_call", ok: false, ts: 1 }, GENESIS);
    expect(x.row.payload_hash).toBe(y.row.payload_hash);
    expect(x.row.payload_hash).not.toBe(z.row.payload_hash);
    const tampered = [{ ...toJsonObject(x.row), ok: false }];
    expect(walkJournal(tampered).divergentIndex).toBe(0);
  });

  it("rejects floats and nested values", () => {
    expect(() => hashRow({ event: "x", ts: 1.5 }, GENESIS)).toThrow(/integer/);
    // @ts-expect-error nested values are not allowed
    expect(() => hashRow({ event: "x", nested: { a: 1 } }, GENESIS)).toThrow();
  });
});
