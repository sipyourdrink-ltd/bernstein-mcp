/// <reference types="node" />
import { readFileSync } from "node:fs";
import { join } from "node:path";

export function vectorText(name: string): string {
  return readFileSync(join(process.cwd(), "vectors", `${name}.json`), "utf-8");
}

/** The receipt exactly as the reference wrote it (number lexemes intact). */
export function receiptString(name: string): string {
  const text = vectorText(name);
  const start = text.indexOf('"input": ') + '"input": '.length;
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  throw new Error("input block not found");
}
