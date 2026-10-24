/**
 * The delegation link of section 3.1.3: the digest a child record commits its
 * parent hop to.
 *
 * The pre-image is the complete parent record as published, with its `signature`
 * member present, canonicalised with RFC 8785 (section 3.1.3):
 *
 *     delegation.parent_record_hash = "sha256:" + hex(SHA-256(JCS(parent_record)))
 *
 * That is deliberately not the signature pre-image of section 3.2.2, which has
 * `signature` absent because a signature cannot cover itself. Digesting the record
 * as published means a verifier digests exactly what it received, with no
 * member-removal step to get wrong.
 *
 * What a verifier does with a *chain* of these links is not normative in v0.2, so
 * this module stops at one link. It gives a caller walking a chain the two
 * operations the specification does fix: recomputing the digest, and comparing a
 * child's commitment against a candidate parent.
 */
/** The digest algorithms the schema's pattern permits for a chain digest (section 3.1.3). */
export declare const DELEGATION_DIGEST_ALGORITHMS: readonly ["sha256", "sha384"];
export type DelegationDigestAlgorithm = (typeof DELEGATION_DIGEST_ALGORITHMS)[number];
/**
 * The chain digest of *record*, in the form `"<alg>:<hex>"` (section 3.1.3).
 *
 * The record is digested whole, signature included, over its RFC 8785 form. The
 * RFC 8785 key order is by UTF-16 code unit, which agrees with code-point order
 * across the Basic Multilingual Plane and diverges above it, so an implementation
 * that sorts by code point computes correct digests for ASCII records
 * indefinitely and a wrong one the first time a key carries a supplementary-plane
 * character.
 */
export declare function parentRecordHash(record: unknown, algorithm?: DelegationDigestAlgorithm): Promise<string>;
export interface DelegationLinkOptions {
    /**
     * The algorithms this verifier implements. A link naming any other algorithm is
     * reported as unsupported and MUST NOT fall back to another one (section 3.1.3).
     */
    readonly supportedDigestAlgorithms?: readonly string[];
}
export interface DelegationLink {
    /** The digest as the child states it. */
    readonly parentRecordHash: string;
    readonly algorithm: DelegationDigestAlgorithm;
    /** The delegation credential the child names as its authority for this hop. */
    readonly credentialId: string;
}
/**
 * Check that *parent* is the record *child* commits to in its `delegation` block.
 *
 * Returns the link when the recomputed digest of *parent* equals the child's
 * `parent_record_hash`. Refuses with `delegation_absent` when the child has no
 * `delegation` block (a root hop, which this function's caller has to handle as
 * such rather than treat as a broken link), `delegation_algorithm_unsupported`
 * when the prefix names an algorithm this verifier does not implement, and
 * `delegation_parent_mismatch` when the digests differ.
 *
 * This checks the link and nothing else: whether either record's own signature
 * verifies is `verifyRecord`'s question, and whether the credential authorises
 * what the child claims is not fixed by v0.2.
 */
export declare function verifyDelegationLink(child: unknown, parent: unknown, options?: DelegationLinkOptions): Promise<DelegationLink>;
