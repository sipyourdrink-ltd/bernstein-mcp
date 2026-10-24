/**
 * JSON Schema (Draft 2020-12) validation against the repository's own schemas.
 *
 * The validators are generated at build time by `scripts/generate-validators.mjs`
 * from `schema/trace-claim.json`, `schema/trace-revocation-bundle.json` and
 * `schema/trace-revocation.json`, compiled ahead of time so nothing is evaluated
 * at run time and nothing is fetched: the statement schema the bundle schema
 * refers to by URL is compiled in beside it. Patterns follow ECMA-262, the
 * dialect JSON Schema 2020-12 specifies for `pattern`, and `format: uri` is
 * asserted, not treated as an annotation.
 */
export interface SchemaViolation {
    /** Location of the offending value, one entry per property name or array index. */
    readonly path: readonly string[];
    /** The failing keyword, for example `required`, `pattern` or `additionalProperties`. */
    readonly keyword: string;
    readonly message: string;
}
/**
 * Every violation of the Trust Record schema, in evaluation order. The first
 * entry is the one `verifyRecord` reports. Empty when the record is valid.
 */
export declare function recordSchemaViolations(record: unknown): SchemaViolation[];
/**
 * Every violation of the revocation bundle schema, sorted by location.
 *
 * The sort compares locations as sequences of strings, element by element, in
 * code-point order, with a location sorting before any location it is a prefix
 * of. That is the order the Python reference sorts its errors in before naming
 * the first one, so both report the same location for the same bundle.
 */
export declare function bundleSchemaViolations(bundle: unknown): SchemaViolation[];
/** SHA-256 of each schema file the validators were generated from, keyed by file name. */
export declare const SCHEMA_DIGESTS: Readonly<Record<string, string>>;
