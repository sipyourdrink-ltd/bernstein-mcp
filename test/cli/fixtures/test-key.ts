// A fixed test key so receipts built in tests are byte-stable.
export const TEST_JWK = {
  kty: "OKP" as const, crv: "Ed25519" as const,
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
};
