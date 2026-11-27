import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  CSP_KEYWORDS,
  DEPRECATED_DIRECTIVES,
  SOURCE_LIST_DIRECTIVES,
  CspCageError,
  computeHash,
  parseCsp
} from '../src/index.mjs';
import { assertFrozenDeep } from './helpers.mjs';

function expectParseError(input, code, options = undefined) {
  assert.throws(() => parseCsp(input, options), (error) => {
    assert.equal(error instanceof CspCageError, true);
    assert.equal(error.code, code);
    return true;
  });
}

for (const name of SOURCE_LIST_DIRECTIVES) {
  test('parses source-list directive: ' + name, () => {
    const parsed = parseCsp(name + " 'self'");
    assert.equal(parsed.valid, true);
    assert.equal(parsed.policyCount, 1);
    const item = parsed.policies[0].directiveMap[name];
    assert.equal(item.name, name);
    assert.equal(item.sources[0].kind, 'keyword');
    assert.equal(item.sources[0].keyword, 'self');
  });
}

for (const keyword of CSP_KEYWORDS) {
  test('parses quoted keyword source: ' + keyword, () => {
    const parsed = parseCsp("script-src '" + keyword + "'");
    assert.equal(parsed.policies[0].directives[0].sources[0].keyword, keyword);
  });
}

for (const keyword of ['SELF', 'Unsafe-Inline', 'STRICT-DYNAMIC', 'NONE']) {
  test('normalizes keyword case: ' + keyword, () => {
    const parsed = parseCsp("script-src '" + keyword + "'");
    assert.equal(parsed.policies[0].directives[0].sources[0].kind, 'keyword');
  });
}

const validSources = [
  'example.com',
  'example.com.',
  'sub.example.co.uk',
  '*.example.com',
  '*',
  'https:',
  'http:',
  'data:',
  'blob:',
  'filesystem:',
  'https://example.com',
  'https://example.com:443',
  'https://example.com/path',
  'https://example.com/path/',
  'example.com:443',
  'example.com/path',
  'example.com:443/path%20x',
  '127.0.0.1',
  '127.0.0.1:8080',
  '[2001:db8::1]',
  '[2001:db8::1]:443',
  'https://[2001:db8::1]/x',
  'xn--bcher-kva.example',
  'localhost'
];

for (const source of validSources) {
  test('parses valid host or scheme source: ' + source, () => {
    const parsed = parseCsp('img-src ' + source);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.policies[0].directives[0].sources.length, 1);
  });
}

const invalidSources = [
  'https://',
  'https://:443',
  'https://example.com:99999',
  'example.com:abc',
  'example.com:99999',
  ':443',
  'foo_bar.com',
  'example..com',
  '-example.com',
  'example-.com',
  '*.bad_example.com',
  '*example.com',
  'example.*.com',
  '[:::]',
  '[2001:db8::1',
  '2001:db8::1',
  'https://example.com/path%zz',
  'https://example.com/path%',
  'https://example.com/path?query',
  'https://example.com/path#fragment',
  'https://example.com/<x>',
  'https:///path',
  'http://.',
  'http://..',
  'http://-bad.com',
  'http://bad-.com',
  'http://999.999.999.999',
  'http://01.2.3.4',
  'http://1.2.3',
  'http://1.2.3.4.5',
  'javascript:alert(1)',
  'https:example.com',
  'http://user:pass@example.com'
];

for (const source of invalidSources) {
  test('rejects invalid host source: ' + source, () => {
    expectParseError('img-src ' + source, CODE.INVALID_HOST_SOURCE);
  });
}

for (const codePoint of [0, 1, 2, 8, 10, 11, 12, 13, 14, 31, 127]) {
  test('rejects control character U+' + codePoint.toString(16).padStart(4, '0'), () => {
    const input = "script-src 'self'" + String.fromCharCode(codePoint);
    assert.throws(() => parseCsp(input), (error) => error instanceof CspCageError && (error.code === CODE.CONTROL_CHARACTER || error.code === CODE.HEADER_INJECTION));
  });
}

for (const [label, character] of [
  ['non-ascii letter', 'é'],
  ['astral character', '𝔘'],
  ['line separator', '\u2028'],
  ['paragraph separator', '\u2029'],
  ['right-to-left mark', '\u200f'],
  ['lone high surrogate', '\ud800'],
  ['lone low surrogate', '\udc00']
]) {
  test('rejects ' + label, () => {
    expectParseError("script-src 'self'" + character, CODE.INVALID_ASCII);
  });
}

test('accepts horizontal tab as CSP whitespace', () => {
  const parsed = parseCsp("script-src\t'self'");
  assert.equal(parsed.valid, true);
});

test('accepts trailing semicolon', () => {
  const parsed = parseCsp("script-src 'self';");
  assert.equal(parsed.directiveCount, 1);
});

test('rejects repeated semicolon empty directive', () => {
  expectParseError("script-src 'self';; object-src 'none'", CODE.EMPTY_DIRECTIVE);
});

test('rejects leading semicolon empty directive', () => {
  expectParseError("; script-src 'self'", CODE.EMPTY_DIRECTIVE);
});

test('parses comma separated multi-policy header list', () => {
  const parsed = parseCsp("default-src 'self', script-src 'none'");
  assert.equal(parsed.policyCount, 2);
  assert.equal(parsed.policies[0].directiveMap['default-src'].name, 'default-src');
  assert.equal(parsed.policies[1].directiveMap['script-src'].name, 'script-src');
});

test('parses array input as independent headers', () => {
  const parsed = parseCsp(["default-src 'self'", "script-src 'none'"]);
  assert.equal(parsed.policyCount, 2);
});

test('duplicate directives in separate policies are independent', () => {
  const parsed = parseCsp("script-src 'self', script-src 'none'");
  assert.equal(parsed.valid, true);
  assert.equal(parsed.policyCount, 2);
});

test('rejects empty comma policy', () => {
  expectParseError("script-src 'self', ", CODE.EMPTY_POLICY);
});

test('normalizes uppercase directive names', () => {
  const parsed = parseCsp("SCRIPT-SRC 'self'");
  assert.equal(parsed.policies[0].directives[0].name, 'script-src');
});

test('duplicate directive strict parse throws first-wins error', () => {
  expectParseError("script-src 'self'; script-src 'none'", CODE.DUPLICATE_DIRECTIVE);
});

test('duplicate directive partial parse marks first-wins shadowing', () => {
  const parsed = parseCsp("script-src 'self'; script-src 'none'", { strict: false });
  assert.equal(parsed.valid, false);
  const items = parsed.policies[0].directives;
  assert.equal(items[0].ignored, false);
  assert.equal(items[1].ignored, true);
  assert.equal(items[1].firstWinsShadowing, true);
  assert.equal(parsed.policies[0].directiveMap['script-src'], items[0]);
});

for (const name of DEPRECATED_DIRECTIVES) {
  test('rejects deprecated directive: ' + name, () => {
    expectParseError(name, CODE.DEPRECATED_DIRECTIVE);
  });
}

for (const name of ['made-up-directive', 'x-webkit-csp', 'evidence', 'script-srcx']) {
  test('rejects unknown directive: ' + name, () => {
    expectParseError(name + " 'self'", CODE.UNKNOWN_DIRECTIVE);
  });
}

for (const token of [
  "'self",
  "self'",
  "'unknown'",
  "'unsafe-inline",
  "unsafe-inline'",
  "'nonce-",
  "'nonce-!!!!'",
  "'nonce-abc?'",
  "'nonce-AAA'",
  "'sha256-!!!'",
  "'sha256-short'",
  "'sha384-short'",
  "'sha512-short'",
  "'sha256-'"
]) {
  test('rejects malformed quoted source: ' + token, () => {
    assert.throws(() => parseCsp('script-src ' + token), (error) => error instanceof CspCageError && [
      CODE.MALFORMED_KEYWORD,
      CODE.MALFORMED_NONCE,
      CODE.MALFORMED_HASH
    ].includes(error.code));
  });
}

test('rejects sha1 hash algorithm', () => {
  expectParseError("script-src 'sha1-abcdefghij'", CODE.UNSUPPORTED_HASH_ALGORITHM);
});

test('rejects md5 hash algorithm', () => {
  expectParseError("script-src 'md5-abcdefghij'", CODE.UNSUPPORTED_HASH_ALGORITHM);
});

for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  test('parses valid hash algorithm: ' + algorithm, () => {
    const source = "'" + computeHash('console.log(1)', algorithm) + "'";
    const parsed = parseCsp('script-src ' + source);
    const item = parsed.policies[0].directives[0].sources[0];
    assert.equal(item.kind, 'hash');
    assert.equal(item.algorithm, algorithm);
  });
}

test('parses padded nonce and reports decoded byte count', () => {
  const parsed = parseCsp("script-src 'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng=='");
  const source = parsed.policies[0].directives[0].sources[0];
  assert.equal(source.kind, 'nonce');
  assert.equal(source.decodedBytes, 16);
});

test('parses unpadded nonce base64', () => {
  const parsed = parseCsp("script-src 'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng'");
  assert.equal(parsed.policies[0].directives[0].sources[0].decodedBytes, 16);
});

test('rejects nonce with impossible base64 length', () => {
  expectParseError("script-src 'nonce-abcde'", CODE.MALFORMED_NONCE);
});

test("rejects 'none' combined with another source", () => {
  expectParseError("script-src 'none' 'self'", CODE.NONE_CONFLICT);
});

test('parses source token structure and deep freezes output', () => {
  const parsed = parseCsp('script-src https://cdn.example.com:443/static/app.js');
  const source = parsed.policies[0].directives[0].sources[0];
  assert.equal(source.kind, 'host');
  assert.equal(source.scheme, 'https');
  assert.equal(source.host, 'cdn.example.com');
  assert.equal(source.port, 443);
  assert.equal(source.path, '/static/app.js');
  assert.equal(source.hasExactPath, true);
  assertFrozenDeep(parsed);
});

test('wildcard host structure is explicit', () => {
  const parsed = parseCsp('img-src *.example.com');
  const source = parsed.policies[0].directives[0].sources[0];
  assert.equal(source.kind, 'host');
  assert.equal(source.hostIsWildcard, true);
});

test('bare wildcard structure is explicit', () => {
  const parsed = parseCsp('img-src *');
  assert.equal(parsed.policies[0].directives[0].sources[0].kind, 'wildcard');
});

test('scheme source structure is explicit', () => {
  const parsed = parseCsp('img-src https:');
  const source = parsed.policies[0].directives[0].sources[0];
  assert.equal(source.kind, 'scheme');
  assert.equal(source.scheme, 'https');
});

test('rejects byte-length bound overflow', () => {
  expectParseError("script-src 'self' https://example.com", CODE.INPUT_TOO_LARGE, { maxBytes: 20 });
});

test('accepts input at configured byte boundary', () => {
  const input = "img-src 'self'";
  const parsed = parseCsp(input, { maxBytes: Buffer.byteLength(input) });
  assert.equal(parsed.valid, true);
});

test('comma separators count toward the byte bound before policy splitting', () => {
  const input = "img-src 'self'" + ','.repeat(100);
  expectParseError(input, CODE.INPUT_TOO_LARGE, { maxBytes: 20, maxPolicies: 16 });
});

test('rejects policy-count bound overflow', () => {
  expectParseError("img-src 'self', font-src 'self'", CODE.TOO_MANY_POLICIES, { maxPolicies: 1 });
});

test('rejects directives-per-policy bound overflow', () => {
  expectParseError("img-src 'self'; font-src 'self'", CODE.TOO_MANY_DIRECTIVES, { maxDirectivesPerPolicy: 1 });
});

test('rejects total-directive bound overflow across policies', () => {
  expectParseError("img-src 'self', font-src 'self'", CODE.TOO_MANY_DIRECTIVES, { maxTotalDirectives: 1, maxPolicies: 2 });
});

test('rejects source-count bound overflow', () => {
  expectParseError("img-src 'self' data:", CODE.TOO_MANY_SOURCES, { maxSourcesPerDirective: 1 });
});

test('rejects source-length bound overflow', () => {
  expectParseError("img-src 'self'", CODE.SOURCE_TOO_LONG, { maxSourceLength: 4 });
});

for (const options of [
  { maxBytes: 0 },
  { maxBytes: 65537 },
  { maxPolicies: 0 },
  { maxDirectivesPerPolicy: 65 },
  { maxFindings: 513 },
  { unknownOption: 1 }
]) {
  test('rejects invalid parser options: ' + JSON.stringify(options), () => {
    assert.throws(() => parseCsp("img-src 'self'", options), (error) => error instanceof CspCageError && error.code === CODE.INVALID_OPTIONS);
  });
}

for (const input of [null, undefined, 1, {}, [], ['valid', 2]]) {
  test('rejects invalid input type: ' + String(input), () => {
    assert.throws(() => parseCsp(input), (error) => error instanceof CspCageError && error.code === CODE.INVALID_INPUT);
  });
}

test('upgrade-insecure-requests accepts no value', () => {
  assert.equal(parseCsp('upgrade-insecure-requests').valid, true);
});

test('upgrade-insecure-requests rejects a value', () => {
  expectParseError("upgrade-insecure-requests 'self'", CODE.UNEXPECTED_DIRECTIVE_VALUE);
});

const sandboxTokens = [
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
];

for (const token of sandboxTokens) {
  test('parses sandbox token: ' + token, () => {
    assert.equal(parseCsp('sandbox ' + token).valid, true);
  });
}

test('parses empty sandbox as maximum restriction form', () => {
  assert.equal(parseCsp('sandbox').valid, true);
});

test('rejects unknown sandbox token', () => {
  expectParseError('sandbox allow-everything', CODE.INVALID_SANDBOX_TOKEN);
});

test('parses require-trusted-types-for script', () => {
  assert.equal(parseCsp("require-trusted-types-for 'script'").valid, true);
});

test('rejects missing require-trusted-types-for value', () => {
  expectParseError('require-trusted-types-for', CODE.INVALID_TRUSTED_TYPES_TOKEN);
});

test('rejects invalid require-trusted-types-for token', () => {
  expectParseError("require-trusted-types-for 'style'", CODE.INVALID_TRUSTED_TYPES_TOKEN);
});

for (const value of ["'none'", 'default', 'policy-one', '*', "'allow-duplicates'"]) {
  test('parses trusted-types value: ' + value, () => {
    assert.equal(parseCsp('trusted-types ' + value).valid, true);
  });
}

test('rejects trusted-types none with another token', () => {
  expectParseError("trusted-types 'none' default", CODE.NONE_CONFLICT);
});

test('parses require-sri-for script style', () => {
  assert.equal(parseCsp('require-sri-for script style').valid, true);
});

test('rejects invalid require-sri-for token', () => {
  expectParseError('require-sri-for image', CODE.MISSING_DIRECTIVE_VALUE);
});

test('parses report-uri endpoint', () => {
  assert.equal(parseCsp('report-uri /csp-report').valid, true);
});

test('rejects report-uri without endpoint', () => {
  expectParseError('report-uri', CODE.MISSING_DIRECTIVE_VALUE);
});

test('parses report-to endpoint group', () => {
  assert.equal(parseCsp('report-to csp-endpoint').valid, true);
});

test('rejects report-to with multiple tokens', () => {
  expectParseError('report-to one two', CODE.UNEXPECTED_DIRECTIVE_VALUE);
});

test('long hostile input remains bounded and typed', () => {
  const input = 'script-src ' + Array.from({ length: 80 }, () => 'bad_host.example').join(' ');
  assert.throws(() => parseCsp(input), (error) => error instanceof CspCageError && [CODE.INVALID_HOST_SOURCE, CODE.TOO_MANY_SOURCES].includes(error.code));
});

for (const source of ['example.com:*', '*:*', '*/path', 'https://*:443/path', '[2001:db8::1]:*']) {
  test('parses wildcard port or wildcard host form: ' + source, () => {
    const parsed = parseCsp('img-src ' + source);
    const item = parsed.policies[0].directives[0].sources[0];
    assert.equal(item.kind, 'host');
    if (source.includes(':*')) assert.equal(item.port, '*');
  });
}
