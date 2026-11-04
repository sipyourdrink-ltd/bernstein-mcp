export declare const schemaDigests: {
    "trace-claim.json": string;
    "trace-revocation-bundle.json": string;
    "trace-revocation.json": string;
};
export declare const validateRecord: typeof validate20;
declare function validate20(data: any, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors }?: {
    dynamicAnchors?: {} | undefined;
    instancePath?: string | undefined;
    rootData?: any;
}): boolean;
export declare const validateBundle: typeof validate23;
declare function validate23(data: any, { instancePath, parentData, parentDataProperty, rootData, dynamicAnchors }?: {
    dynamicAnchors?: {} | undefined;
    instancePath?: string | undefined;
    rootData?: any;
}): boolean;
export {};
