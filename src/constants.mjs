export const CSPCAGE_VERSION = '1.0.0';

export const CSPCAGE_SEVERITY = Object.freeze({
  ERROR: 'error',
  WARNING: 'warning',
  NOTICE: 'notice'
});

export const CSPCAGE_ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'CSPCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'CSPCAGE_INVALID_OPTIONS',
  INPUT_TOO_LARGE: 'CSPCAGE_INPUT_TOO_LARGE',
  TOO_MANY_POLICIES: 'CSPCAGE_TOO_MANY_POLICIES',
  EMPTY_POLICY: 'CSPCAGE_EMPTY_POLICY',
  TOO_MANY_DIRECTIVES: 'CSPCAGE_TOO_MANY_DIRECTIVES',
  EMPTY_DIRECTIVE: 'CSPCAGE_EMPTY_DIRECTIVE',
  INVALID_DIRECTIVE_NAME: 'CSPCAGE_INVALID_DIRECTIVE_NAME',
  UNKNOWN_DIRECTIVE: 'CSPCAGE_UNKNOWN_DIRECTIVE',
  DEPRECATED_DIRECTIVE: 'CSPCAGE_DEPRECATED_DIRECTIVE',
  DUPLICATE_DIRECTIVE: 'CSPCAGE_DUPLICATE_DIRECTIVE',
  INVALID_ASCII: 'CSPCAGE_INVALID_ASCII',
  CONTROL_CHARACTER: 'CSPCAGE_CONTROL_CHARACTER',
  HEADER_INJECTION: 'CSPCAGE_HEADER_INJECTION',
  TOO_MANY_SOURCES: 'CSPCAGE_TOO_MANY_SOURCES',
  SOURCE_TOO_LONG: 'CSPCAGE_SOURCE_TOO_LONG',
  MISSING_DIRECTIVE_VALUE: 'CSPCAGE_MISSING_DIRECTIVE_VALUE',
  UNEXPECTED_DIRECTIVE_VALUE: 'CSPCAGE_UNEXPECTED_DIRECTIVE_VALUE',
  MALFORMED_SOURCE: 'CSPCAGE_MALFORMED_SOURCE',
  MALFORMED_KEYWORD: 'CSPCAGE_MALFORMED_KEYWORD',
  MALFORMED_NONCE: 'CSPCAGE_MALFORMED_NONCE',
  MALFORMED_HASH: 'CSPCAGE_MALFORMED_HASH',
  UNSUPPORTED_HASH_ALGORITHM: 'CSPCAGE_UNSUPPORTED_HASH_ALGORITHM',
  INVALID_HOST_SOURCE: 'CSPCAGE_INVALID_HOST_SOURCE',
  INVALID_REPORT_ENDPOINT: 'CSPCAGE_INVALID_REPORT_ENDPOINT',
  INVALID_SANDBOX_TOKEN: 'CSPCAGE_INVALID_SANDBOX_TOKEN',
  INVALID_TRUSTED_TYPES_TOKEN: 'CSPCAGE_INVALID_TRUSTED_TYPES_TOKEN',
  NONE_CONFLICT: 'CSPCAGE_NONE_CONFLICT',
  PROTOTYPE_POLLUTION: 'CSPCAGE_PROTOTYPE_POLLUTION',
  INVALID_BUILD_INPUT: 'CSPCAGE_INVALID_BUILD_INPUT',
  UNSAFE_BUILD_OUTPUT: 'CSPCAGE_UNSAFE_BUILD_OUTPUT',
  INVALID_NONCE_INPUT: 'CSPCAGE_INVALID_NONCE_INPUT',
  INVALID_HASH_INPUT: 'CSPCAGE_INVALID_HASH_INPUT',
  INVALID_MERGE_INPUT: 'CSPCAGE_INVALID_MERGE_INPUT',
  UNSAFE_INLINE_MERGE: 'CSPCAGE_UNSAFE_INLINE_MERGE',
  INVALID_CLI_ARGUMENT: 'CSPCAGE_INVALID_CLI_ARGUMENT'
});

export const CODE = CSPCAGE_ERROR_CODES;

export const CSP_PARSE_BOUNDS = Object.freeze({
  maxBytes: 8192,
  maxPolicies: 4,
  maxDirectivesPerPolicy: 32,
  maxTotalDirectives: 96,
  maxSourcesPerDirective: 64,
  maxSourceLength: 512,
  maxFindings: 128
});

export const CSP_PARSE_HARD_LIMITS = Object.freeze({
  maxBytes: 65536,
  maxPolicies: 16,
  maxDirectivesPerPolicy: 64,
  maxTotalDirectives: 256,
  maxSourcesPerDirective: 128,
  maxSourceLength: 2048,
  maxFindings: 512
});

export const FETCH_DIRECTIVES = Object.freeze([
  'child-src',
  'connect-src',
  'default-src',
  'font-src',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'prefetch-src',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'worker-src'
]);

export const SOURCE_LIST_DIRECTIVES = Object.freeze([
  ...FETCH_DIRECTIVES,
  'base-uri',
  'form-action',
  'frame-ancestors'
]);

export const DOCUMENT_DIRECTIVES = Object.freeze([
  'base-uri',
  'sandbox'
]);

export const NAVIGATION_DIRECTIVES = Object.freeze([
  'form-action'
]);

export const REPORTING_DIRECTIVES = Object.freeze([
  'report-uri',
  'report-to'
]);

export const OTHER_DIRECTIVES = Object.freeze([
  'frame-ancestors',
  'require-sri-for',
  'require-trusted-types-for',
  'trusted-types',
  'upgrade-insecure-requests'
]);

export const CSP_DIRECTIVES = Object.freeze([
  ...new Set([
    ...SOURCE_LIST_DIRECTIVES,
    ...DOCUMENT_DIRECTIVES,
    ...NAVIGATION_DIRECTIVES,
    ...REPORTING_DIRECTIVES,
    ...OTHER_DIRECTIVES
  ])
]);

export const CSP_DIRECTIVE_ORDER = Object.freeze([
  'default-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'style-src',
  'style-src-elem',
  'style-src-attr',
  'img-src',
  'font-src',
  'connect-src',
  'media-src',
  'object-src',
  'prefetch-src',
  'child-src',
  'frame-src',
  'worker-src',
  'manifest-src',
  'base-uri',
  'form-action',
  'frame-ancestors',
  'sandbox',
  'require-sri-for',
  'require-trusted-types-for',
  'trusted-types',
  'upgrade-insecure-requests',
  'report-uri',
  'report-to'
]);

export const DEPRECATED_DIRECTIVES = Object.freeze([
  'block-all-mixed-content',
  'plugin-types',
  'referrer'
]);

export const CSP_KEYWORDS = Object.freeze([
  'self',
  'unsafe-inline',
  'unsafe-eval',
  'strict-dynamic',
  'unsafe-hashes',
  'report-sample',
  'wasm-unsafe-eval',
  'inline-speculation-rules',
  'none'
]);

export const SANDBOX_TOKENS = Object.freeze([
  'allow-downloads',
  'allow-forms',
  'allow-modals',
  'allow-orientation-lock',
  'allow-pointer-lock',
  'allow-popups',
  'allow-popups-to-escape-sandbox',
  'allow-presentation',
  'allow-same-origin',
  'allow-scripts',
  'allow-storage-access-by-user-activation',
  'allow-top-navigation',
  'allow-top-navigation-by-user-activation',
  'allow-top-navigation-to-custom-protocols'
]);

export const HASH_ALGORITHMS = Object.freeze([
  'sha256',
  'sha384',
  'sha512'
]);

export const HASH_DIGEST_BYTES = Object.freeze({
  sha256: 32,
  sha384: 48,
  sha512: 64
});

export const DANGEROUS_OBJECT_KEYS = Object.freeze([
  '__proto__',
  'constructor',
  'prototype'
]);

export const SCRIPT_GADGET_HOSTS = Object.freeze([
  'googleapis.com',
  'gstatic.com',
  'googleusercontent.com',
  'firebaseapp.com',
  'amazonaws.com',
  'cloudfront.net',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'raw.githubusercontent.com'
]);

export const PLACEHOLDER_NONCE_VALUES = Object.freeze([
  '123456',
  '1234567890',
  'abcdef',
  'abc123',
  'test',
  'test-nonce',
  'nonce',
  'example',
  'sample',
  'placeholder',
  'change-me',
  'changeme',
  'static',
  '000000'
]);
