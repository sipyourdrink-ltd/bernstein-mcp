// Filled in by scripts/build-cli.mjs (esbuild `define`); the fallback is
// what vitest sees when it imports the TypeScript directly.
import pkg from "./package.json";

export const PRODUCER_NAME = "bernstein-attest";
export const PRODUCER_VERSION: string = (pkg as { version: string }).version;
