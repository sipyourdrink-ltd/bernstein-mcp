/**
 * The JSON Schema `uri` format: the `URI` rule of RFC 3986 Appendix A.
 *
 * Built from the ABNF rule by rule, so each constant below is one production.
 * An IRI is not a URI, so a character outside ASCII is refused, and the whole
 * string must match: a trailing line feed is not part of any URI.
 */
/** True when *value* is a URI under RFC 3986. */
export declare function isUri(value: string): boolean;
/** The format checkers the generated schema validators call, keyed by format name. */
export declare const formats: {
    readonly uri: typeof isUri;
};
