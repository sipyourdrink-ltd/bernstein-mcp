import { PRODUCER_NAME, PRODUCER_VERSION } from "./version.js";

export function main(argv: string[]): number {
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(`${PRODUCER_NAME} ${PRODUCER_VERSION}\n`);
    return 0;
  }
  process.stderr.write("usage: bernstein-attest <init|hook|seal|link|verify|status|uninstall>\n");
  return 2;
}

if (typeof require !== "undefined" && require.main === module) process.exitCode = main(process.argv.slice(2));
