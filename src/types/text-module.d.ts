// Wrangler's default module rules treat "*.txt" as a Text module: the
// default export is the file's raw contents as a string. This declaration
// makes the same import shape typecheck; test/vitest.setup.ts teaches
// vitest the same convention so both toolchains agree on one import.
declare module "*.txt" {
  const content: string;
  export default content;
}
