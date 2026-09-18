// wrangler.toml [[rules]] type = "Data" for *.woff2: the default export is
// the file's bytes as an ArrayBuffer. vitest.config.ts mirrors this.
declare module "*.woff2" {
  const content: ArrayBuffer;
  export default content;
}
