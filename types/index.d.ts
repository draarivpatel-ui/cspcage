export const CSPCAGE_VERSION: string;

export const CSPCAGE_SEVERITY: {
  readonly ERROR: 'error';
  readonly WARNING: 'warning';
  readonly NOTICE: 'notice';
};

export const CSPCAGE_ERROR_CODES: {
  readonly INVALID_INPUT: 'CSPCAGE_INVALID_INPUT';
  readonly INVALID_OPTIONS: 'CSPCAGE_INVALID_OPTIONS';
  readonly INPUT_TOO_LARGE: 'CSPCAGE_INPUT_TOO_LARGE';
  readonly TOO_MANY_POLICIES: 'CSPCAGE_TOO_MANY_POLICIES';
  readonly EMPTY_POLICY: 'CSPCAGE_EMPTY_POLICY';
  readonly TOO_MANY_DIRECTIVES: 'CSPCAGE_TOO_MANY_DIRECTIVES';
  readonly EMPTY_DIRECTIVE: 'CSPCAGE_EMPTY_DIRECTIVE';
  readonly INVALID_DIRECTIVE_NAME: 'CSPCAGE_INVALID_DIRECTIVE_NAME';
  readonly UNKNOWN_DIRECTIVE: 'CSPCAGE_UNKNOWN_DIRECTIVE';
  readonly DEPRECATED_DIRECTIVE: 'CSPCAGE_DEPRECATED_DIRECTIVE';
  readonly DUPLICATE_DIRECTIVE: 'CSPCAGE_DUPLICATE_DIRECTIVE';
  readonly INVALID_ASCII: 'CSPCAGE_INVALID_ASCII';
  readonly CONTROL_CHARACTER: 'CSPCAGE_CONTROL_CHARACTER';
  readonly HEADER_INJECTION: 'CSPCAGE_HEADER_INJECTION';
  readonly TOO_MANY_SOURCES: 'CSPCAGE_TOO_MANY_SOURCES';
  readonly SOURCE_TOO_LONG: 'CSPCAGE_SOURCE_TOO_LONG';
  readonly MISSING_DIRECTIVE_VALUE: 'CSPCAGE_MISSING_DIRECTIVE_VALUE';
  readonly UNEXPECTED_DIRECTIVE_VALUE: 'CSPCAGE_UNEXPECTED_DIRECTIVE_VALUE';
  readonly MALFORMED_SOURCE: 'CSPCAGE_MALFORMED_SOURCE';
  readonly MALFORMED_KEYWORD: 'CSPCAGE_MALFORMED_KEYWORD';
  readonly MALFORMED_NONCE: 'CSPCAGE_MALFORMED_NONCE';
  readonly MALFORMED_HASH: 'CSPCAGE_MALFORMED_HASH';
  readonly UNSUPPORTED_HASH_ALGORITHM: 'CSPCAGE_UNSUPPORTED_HASH_ALGORITHM';
  readonly INVALID_HOST_SOURCE: 'CSPCAGE_INVALID_HOST_SOURCE';
  readonly INVALID_REPORT_ENDPOINT: 'CSPCAGE_INVALID_REPORT_ENDPOINT';
  readonly INVALID_SANDBOX_TOKEN: 'CSPCAGE_INVALID_SANDBOX_TOKEN';
  readonly INVALID_TRUSTED_TYPES_TOKEN: 'CSPCAGE_INVALID_TRUSTED_TYPES_TOKEN';
  readonly NONE_CONFLICT: 'CSPCAGE_NONE_CONFLICT';
  readonly PROTOTYPE_POLLUTION: 'CSPCAGE_PROTOTYPE_POLLUTION';
  readonly INVALID_BUILD_INPUT: 'CSPCAGE_INVALID_BUILD_INPUT';
  readonly UNSAFE_BUILD_OUTPUT: 'CSPCAGE_UNSAFE_BUILD_OUTPUT';
  readonly INVALID_NONCE_INPUT: 'CSPCAGE_INVALID_NONCE_INPUT';
  readonly INVALID_HASH_INPUT: 'CSPCAGE_INVALID_HASH_INPUT';
  readonly INVALID_MERGE_INPUT: 'CSPCAGE_INVALID_MERGE_INPUT';
  readonly UNSAFE_INLINE_MERGE: 'CSPCAGE_UNSAFE_INLINE_MERGE';
  readonly INVALID_CLI_ARGUMENT: 'CSPCAGE_INVALID_CLI_ARGUMENT';
  readonly FINDINGS_TRUNCATED: 'CSPCAGE_FINDINGS_TRUNCATED';
};

export const CODE: typeof CSPCAGE_ERROR_CODES;
export type CspCageErrorCode = typeof CSPCAGE_ERROR_CODES[keyof typeof CSPCAGE_ERROR_CODES];

export class CspCageError extends Error {
  readonly name: 'CspCageError';
  readonly code: CspCageErrorCode;
  readonly detail: string;
  context?: unknown;
  constructor(code: CspCageErrorCode, detail?: string, context?: unknown);
}

export function isCspCageError(value: unknown): value is CspCageError;

export const CSP_PARSE_BOUNDS: {
  readonly maxBytes: number;
  readonly maxPolicies: number;
  readonly maxDirectivesPerPolicy: number;
  readonly maxTotalDirectives: number;
  readonly maxSourcesPerDirective: number;
  readonly maxSourceLength: number;
  readonly maxFindings: number;
};

export const CSP_PARSE_HARD_LIMITS: typeof CSP_PARSE_BOUNDS;
export const CSP_DIRECTIVES: readonly string[];
export const FETCH_DIRECTIVES: readonly string[];
export const SOURCE_LIST_DIRECTIVES: readonly string[];
export const DEPRECATED_DIRECTIVES: readonly string[];
export const CSP_KEYWORDS: readonly string[];
export const HASH_ALGORITHMS: readonly ['sha256', 'sha384', 'sha512'];
export const SCRIPT_GADGET_HOSTS: readonly string[];

export type CspHashAlgorithm = 'sha256' | 'sha384' | 'sha512';
export type CspInput = string | readonly string[];

export interface CspParseOptions {
  readonly maxBytes?: number;
  readonly maxPolicies?: number;
  readonly maxDirectivesPerPolicy?: number;
  readonly maxTotalDirectives?: number;
  readonly maxSourcesPerDirective?: number;
  readonly maxSourceLength?: number;
  readonly maxFindings?: number;
  readonly strict?: boolean;
}

export interface CspKeywordSource {
  readonly kind: 'keyword';
  readonly raw: string;
  readonly keyword: string;
}

export interface CspNonceSource {
  readonly kind: 'nonce';
  readonly raw: string;
  readonly nonce: string;
  readonly decodedBytes: number;
}

export interface CspHashSource {
  readonly kind: 'hash';
  readonly raw: string;
  readonly algorithm: CspHashAlgorithm;
  readonly digest: string;
  readonly digestBytes: number;
}

export interface CspSchemeSource {
  readonly kind: 'scheme';
  readonly raw: string;
  readonly scheme: string;
}

export interface CspWildcardSource {
  readonly kind: 'wildcard';
  readonly raw: string;
}

export interface CspHostSource {
  readonly kind: 'host';
  readonly raw: string;
  readonly scheme: string | null;
  readonly host: string;
  readonly hostIsWildcard: boolean;
  readonly port: number | '*' | null;
  readonly path: string | null;
  readonly ipv6: boolean;
  readonly hasExactPath: boolean;
}

export type CspSourceExpression = CspKeywordSource | CspNonceSource | CspHashSource | CspSchemeSource | CspWildcardSource | CspHostSource;

export interface CspDirective {
  readonly index: number;
  readonly name: string;
  readonly value: string;
  readonly tokens: readonly string[];
  readonly sources: readonly CspSourceExpression[];
  readonly ignored: boolean;
  readonly duplicateOf: string | null;
  readonly firstWinsShadowing: boolean;
}

export interface CspPolicy {
  readonly index: number;
  readonly raw: string;
  readonly directives: readonly CspDirective[];
  readonly directiveMap: {
    readonly [name: string]: CspDirective | undefined;
  };
  readonly directiveCount: number;
  readonly sourceExpressionCount: number;
}

export interface ParsedCsp {
  readonly valid: boolean;
  readonly policyCount: number;
  readonly policies: readonly CspPolicy[];
  readonly directiveCount: number;
  readonly sourceExpressionCount: number;
  readonly bounds: {
    readonly maxBytes: number;
    readonly maxPolicies: number;
    readonly maxDirectivesPerPolicy: number;
    readonly maxTotalDirectives: number;
    readonly maxSourcesPerDirective: number;
    readonly maxSourceLength: number;
    readonly maxFindings: number;
    readonly strict: boolean;
  };
}

export function parseCsp(input: CspInput, options?: CspParseOptions): ParsedCsp;

export type CspFindingSeverity = 'error' | 'warning' | 'notice';

export interface CspFinding {
  readonly severity: CspFindingSeverity;
  readonly code: string;
  readonly message: string;
  readonly policyIndex: number | null;
  readonly directive: string | null;
  readonly recommendation: string | null;
}

export interface CspPolicyResult {
  readonly policyIndex: number;
  readonly score: number;
  readonly grade: string;
  readonly strictCsp: boolean;
}

export interface CspAuditReport {
  readonly valid: boolean;
  readonly safe: boolean;
  readonly strict: boolean;
  readonly strictCsp: boolean;
  readonly grade: string;
  readonly score: number;
  readonly policyCount: number;
  readonly policyResults: readonly CspPolicyResult[];
  readonly counts: {
    readonly errors: number;
    readonly warnings: number;
    readonly notices: number;
  };
  readonly findings: readonly CspFinding[];
}

export interface CspAuditOptions extends CspParseOptions {
  readonly strict?: boolean;
}

export function auditCsp(input: CspInput | ParsedCsp, options?: CspAuditOptions): CspAuditReport;
export function isSafeCsp(input: CspInput | ParsedCsp, options?: CspAuditOptions): boolean;

export type CspDirectiveInputValue = string | readonly string[] | boolean | undefined;
export interface CspDirectiveInput {
  readonly [directive: string]: CspDirectiveInputValue;
}

export interface CspBuildOptions {
  readonly requireCleanAudit?: boolean;
  readonly allowUnsafeInline?: boolean;
}

export function buildCsp(directives: CspDirectiveInput, options?: CspBuildOptions): string;

export interface CreateStrictCspOptions {
  readonly nonce?: string;
  readonly reportTo?: string;
  readonly reportUri?: string;
  readonly connectSrc?: readonly string[];
  readonly imgSrc?: readonly string[];
  readonly styleSrc?: readonly string[];
  readonly fontSrc?: readonly string[];
  readonly mediaSrc?: readonly string[];
  readonly workerSrc?: readonly string[];
  readonly frameAncestors?: readonly string[];
  readonly formAction?: readonly string[];
  readonly upgradeInsecureRequests?: boolean;
  readonly requireTrustedTypesFor?: boolean;
}

export function createStrictCsp(options?: CreateStrictCspOptions): string;
export function generateNonce(bytes?: number): string;
export function computeHash(content: string | Uint8Array | ArrayBuffer, algorithm?: CspHashAlgorithm): string;

export type CspMergeInput = string | ParsedCsp | CspDirectiveInput;

export interface CspMergeOptions {
  readonly allowUnsafeInline?: boolean;
  readonly allowNoneWidening?: boolean;
  readonly requireCleanAudit?: boolean;
}

/**
 * Variadic merge arguments with a trailing options object. At runtime the final
 * argument is treated as options only when at least one policy precedes it and it
 * is a plain object whose keys are all known merge option names; an empty object
 * or one mixing option and directive keys is treated as a policy.
 */
export type CspMergeVariadicArgs = readonly [first: CspMergeInput, ...policies: CspMergeInput[], options: CspMergeOptions];

export function mergeCsp(policies: readonly CspMergeInput[], options?: CspMergeOptions): string;
export function mergeCsp(...args: CspMergeVariadicArgs): string;
export function mergeCsp(...policies: readonly CspMergeInput[]): string;
export function intersectCsp(policies: readonly CspMergeInput[], options?: CspMergeOptions): string;
export function intersectCsp(...args: CspMergeVariadicArgs): string;
export function intersectCsp(...policies: readonly CspMergeInput[]): string;

export interface CspDirectiveDiff {
  readonly name: string;
  readonly addedSources: readonly string[];
  readonly removedSources: readonly string[];
}

export interface CspDiffReport {
  readonly addedDirectives: readonly string[];
  readonly removedDirectives: readonly string[];
  readonly changedDirectives: readonly CspDirectiveDiff[];
  readonly unchangedDirectives: readonly string[];
  readonly summary: {
    readonly addedCount: number;
    readonly removedCount: number;
    readonly changedCount: number;
    readonly unchangedCount: number;
  };
}

export function diffCsp(before: CspMergeInput, after: CspMergeInput): CspDiffReport;

declare const cspcage: {
  readonly CSPCAGE_VERSION: typeof CSPCAGE_VERSION;
  readonly CSPCAGE_SEVERITY: typeof CSPCAGE_SEVERITY;
  readonly CSPCAGE_ERROR_CODES: typeof CSPCAGE_ERROR_CODES;
  readonly CODE: typeof CODE;
  readonly CSP_PARSE_BOUNDS: typeof CSP_PARSE_BOUNDS;
  readonly CSP_PARSE_HARD_LIMITS: typeof CSP_PARSE_HARD_LIMITS;
  readonly CSP_DIRECTIVES: typeof CSP_DIRECTIVES;
  readonly FETCH_DIRECTIVES: typeof FETCH_DIRECTIVES;
  readonly SOURCE_LIST_DIRECTIVES: typeof SOURCE_LIST_DIRECTIVES;
  readonly DEPRECATED_DIRECTIVES: typeof DEPRECATED_DIRECTIVES;
  readonly CSP_KEYWORDS: typeof CSP_KEYWORDS;
  readonly HASH_ALGORITHMS: typeof HASH_ALGORITHMS;
  readonly SCRIPT_GADGET_HOSTS: typeof SCRIPT_GADGET_HOSTS;
  readonly CspCageError: typeof CspCageError;
  readonly isCspCageError: typeof isCspCageError;
  readonly parseCsp: typeof parseCsp;
  readonly auditCsp: typeof auditCsp;
  readonly isSafeCsp: typeof isSafeCsp;
  readonly buildCsp: typeof buildCsp;
  readonly createStrictCsp: typeof createStrictCsp;
  readonly generateNonce: typeof generateNonce;
  readonly computeHash: typeof computeHash;
  readonly mergeCsp: typeof mergeCsp;
  readonly intersectCsp: typeof intersectCsp;
  readonly diffCsp: typeof diffCsp;
};

export default cspcage;
