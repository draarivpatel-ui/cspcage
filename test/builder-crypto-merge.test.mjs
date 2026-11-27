import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE,
  CSP_DIRECTIVES,
  CspCageError,
  auditCsp,
  buildCsp,
  computeHash,
  createStrictCsp,
  diffCsp,
  generateNonce,
  intersectCsp,
  mergeCsp,
  parseCsp
} from '../src/index.mjs';

function expectError(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error instanceof CspCageError, true);
    assert.equal(error.code, code);
    return true;
  });
}

const canonicalValues = {
  'default-src': "'self'",
  'script-src': "'self'",
  'script-src-elem': "'self'",
  'script-src-attr': "'self'",
  'style-src': "'self'",
  'style-src-elem': "'self'",
  'style-src-attr': "'self'",
  'img-src': "'self'",
  'font-src': "'self'",
  'connect-src': "'self'",
  'media-src': "'self'",
  'object-src': "'none'",
  'prefetch-src': "'self'",
  'child-src': "'self'",
  'frame-src': "'self'",
  'worker-src': "'self'",
  'manifest-src': "'self'",
  'base-uri': "'none'",
  'form-action': "'self'",
  'frame-ancestors': "'none'",
  'sandbox': 'allow-scripts',
  'require-sri-for': 'script',
  'require-trusted-types-for': "'script'",
  'trusted-types': 'default',
  'upgrade-insecure-requests': '',
  'report-uri': '/csp-report',
  'report-to': 'csp-endpoint'
};

for (const name of CSP_DIRECTIVES) {
  test('builder accepts canonical directive: ' + name, () => {
    const value = canonicalValues[name];
    const input = Object.create(null);
    input[name] = value === '' ? true : [value];
    const header = buildCsp(input);
    assert.equal(header.includes(name), true);
    assert.equal(parseCsp(header).valid, true);
  });
}

const camelKeys = [
  ['defaultSrc', 'default-src'],
  ['scriptSrc', 'script-src'],
  ['scriptSrcElem', 'script-src-elem'],
  ['scriptSrcAttr', 'script-src-attr'],
  ['styleSrc', 'style-src'],
  ['styleSrcElem', 'style-src-elem'],
  ['styleSrcAttr', 'style-src-attr'],
  ['imgSrc', 'img-src'],
  ['fontSrc', 'font-src'],
  ['connectSrc', 'connect-src'],
  ['objectSrc', 'object-src'],
  ['baseUri', 'base-uri'],
  ['formAction', 'form-action'],
  ['frameAncestors', 'frame-ancestors'],
  ['upgradeInsecureRequests', 'upgrade-insecure-requests'],
  ['reportUri', 'report-uri'],
  ['reportTo', 'report-to']
];

for (const [key, expected] of camelKeys) {
  test('builder normalizes camelCase key: ' + key, () => {
    const input = Object.create(null);
    input[key] = expected === 'upgrade-insecure-requests' ? true : ["'none'"];
    if (expected === 'report-uri' || expected === 'report-to') input[key] = expected === 'report-uri' ? '/csp' : 'csp';
    const header = buildCsp(input);
    assert.equal(header.startsWith(expected), true);
  });
}

test('builder serializes deterministic canonical directive order', () => {
  const header = buildCsp({
    frameAncestors: ["'none'"],
    scriptSrc: ["'self'"],
    defaultSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'none'"]
  });
  assert.equal(header, "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
});

test('builder accepts whitespace separated string values', () => {
  const header = buildCsp({ scriptSrc: "'self' https://cdn.example.com/app.js" });
  assert.equal(header, "script-src 'self' https://cdn.example.com/app.js");
});

test('builder deduplicates repeated tokens', () => {
  const header = buildCsp({ scriptSrc: ["'self'", "'self'"] });
  assert.equal(header, "script-src 'self'");
});

test('builder output is independent of input key insertion order', () => {
  const one = buildCsp({ defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"] });
  const two = buildCsp({ frameAncestors: ["'none'"], baseUri: ["'none'"], objectSrc: ["'none'"], scriptSrc: ["'self'"], defaultSrc: ["'self'"] });
  assert.equal(one, two);
});

test('builder serializes upgrade-insecure-requests as valueless', () => {
  assert.equal(buildCsp({ upgradeInsecureRequests: true }), 'upgrade-insecure-requests');
});

test('builder serializes sandbox true as bare sandbox', () => {
  assert.equal(buildCsp({ sandbox: true }), 'sandbox');
});

test('builder accepts report-to group token', () => {
  assert.equal(buildCsp({ reportTo: 'csp-endpoint' }), 'report-to csp-endpoint');
});

for (const input of [null, undefined, [], 1, 'script-src', true]) {
  test('builder rejects invalid directive container: ' + String(input), () => {
    expectError(() => buildCsp(input), CODE.INVALID_BUILD_INPUT);
  });
}

for (const key of ['unknownDirective', 'xCspTest', 'script-srcx']) {
  test('builder rejects unknown directive key: ' + key, () => {
    expectError(() => buildCsp({ [key]: ["'self'"] }), CODE.UNKNOWN_DIRECTIVE);
  });
}

for (const key of ['block-all-mixed-content', 'plugin-types', 'referrer']) {
  test('builder rejects deprecated directive key: ' + key, () => {
    expectError(() => buildCsp({ [key]: ["'self'"] }), CODE.DEPRECATED_DIRECTIVE);
  });
}

test('builder rejects duplicate keys after camelCase normalization', () => {
  expectError(() => buildCsp({ scriptSrc: ["'self'"], 'script-src': ["'none'"] }), CODE.DUPLICATE_DIRECTIVE);
});

for (const key of ['bad key', 'bad\tkey', 'bad\nkey', 'ékey', '']) {
  test('builder rejects malformed directive key: ' + JSON.stringify(key), () => {
    assert.throws(() => buildCsp({ [key]: ["'self'"] }), (error) => error instanceof CspCageError);
  });
}

for (const key of ['__proto__', 'constructor', 'prototype']) {
  test('builder rejects prototype-pollution key: ' + key, () => {
    const input = Object.create(null);
    input[key] = ["'self'"];
    expectError(() => buildCsp(input), CODE.PROTOTYPE_POLLUTION);
  });
}

test('builder rejects boolean false as ambiguous', () => {
  expectError(() => buildCsp({ scriptSrc: false }), CODE.INVALID_BUILD_INPUT);
});

test('builder rejects numeric directive value', () => {
  expectError(() => buildCsp({ scriptSrc: 1 }), CODE.INVALID_BUILD_INPUT);
});

test('builder rejects null directive value', () => {
  expectError(() => buildCsp({ scriptSrc: null }), CODE.INVALID_BUILD_INPUT);
});

test('builder rejects empty source token array', () => {
  expectError(() => buildCsp({ scriptSrc: [] }), CODE.MISSING_DIRECTIVE_VALUE);
});

test('builder rejects tokens in valueless upgrade directive', () => {
  expectError(() => buildCsp({ upgradeInsecureRequests: ['yes'] }), CODE.UNEXPECTED_DIRECTIVE_VALUE);
});

for (const [label, token] of [
  ['semicolon', "'self';object-src"],
  ['comma', "'self',object-src"],
  ['carriage return', "'self'\r"],
  ['line feed', "'self'\n"],
  ['nul', "'self'\0"],
  ['tab', "'self'\t"],
  ['space', "'self' extra"],
  ['backslash', 'https:\\\\example.com'],
  ['control', "'self'\x1f"],
  ['non-ascii', "'sélf'"]
]) {
  test('builder rejects array token injection: ' + label, () => {
    assert.throws(() => buildCsp({ scriptSrc: [token] }), (error) => error instanceof CspCageError);
  });
}

for (const [label, value] of [
  ['semicolon', "'self'; object-src 'none'"],
  ['comma', "'self', object-src 'none'"],
  ['carriage return', "'self'\r"],
  ['line feed', "'self'\n"],
  ['nul', "'self'\0"],
  ['backslash', 'https:\\\\example.com'],
  ['control', "'self'\x1f"],
  ['non-ascii', "'sélf'"]
]) {
  test('builder rejects string value injection: ' + label, () => {
    assert.throws(() => buildCsp({ scriptSrc: value }), (error) => error instanceof CspCageError);
  });
}

test('builder rejects empty token in array', () => {
  expectError(() => buildCsp({ scriptSrc: [''] }), CODE.INVALID_BUILD_INPUT);
});

test('builder rejects overlong token', () => {
  expectError(() => buildCsp({ scriptSrc: ['x'.repeat(513)] }), CODE.INVALID_BUILD_INPUT);
});

test('builder rejects too many tokens', () => {
  expectError(() => buildCsp({ scriptSrc: Array.from({ length: 65 }, () => "'self'") }), CODE.INVALID_BUILD_INPUT);
});

test('builder surfaces malformed source grammar', () => {
  assert.throws(() => buildCsp({ scriptSrc: ['https://'] }), (error) => error instanceof CspCageError && error.code === CODE.INVALID_HOST_SOURCE);
});

for (const token of ["'unsafe-inline'", '*', 'data:', 'javascript:']) {
  test('base builder blocks audit-error source: ' + token, () => {
    expectError(() => buildCsp({ scriptSrc: [token] }), CODE.UNSAFE_BUILD_OUTPUT);
  });
}

test('unsafe-eval is blocked by builder audit', () => {
  expectError(() => buildCsp({ scriptSrc: ["'unsafe-eval'"] }), CODE.UNSAFE_BUILD_OUTPUT);
});

test('builder permits warning-only transitional policy by default', () => {
  assert.equal(buildCsp({ scriptSrc: ["'self'"] }), "script-src 'self'");
});

test('requireCleanAudit blocks warning-only transitional policy', () => {
  expectError(() => buildCsp({ scriptSrc: ["'self'"] }, { requireCleanAudit: true }), CODE.UNSAFE_BUILD_OUTPUT);
});

test('unsafe build error carries audit report', () => {
  assert.throws(() => buildCsp({ scriptSrc: ["'unsafe-inline'"] }), (error) => {
    assert.equal(error.code, CODE.UNSAFE_BUILD_OUTPUT);
    assert.equal(typeof error.audit, 'object');
    assert.equal(error.audit.counts.errors > 0, true);
    return true;
  });
});

test('allowUnsafeInline is an explicit builder escape hatch', () => {
  assert.equal(buildCsp({ scriptSrc: ["'unsafe-inline'"] }, { allowUnsafeInline: true }), "script-src 'unsafe-inline'");
});

test('strict policy preset contains required lockdown directives', () => {
  const nonce = generateNonce();
  const header = createStrictCsp({ nonce });
  for (const part of [
    "default-src 'self'",
    "script-src 'nonce-",
    "'strict-dynamic'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    'upgrade-insecure-requests'
  ]) assert.equal(header.includes(part), true, part);
  assert.equal(header.includes(nonce), true);
});

test('strict policy preset audits cleanly in strict mode', () => {
  const report = auditCsp(createStrictCsp(), { strict: true });
  assert.equal(report.safe, true);
  assert.equal(report.strictCsp, true);
});

test('strict policy nonce is fresh across calls', () => {
  const one = createStrictCsp();
  const two = createStrictCsp();
  assert.notEqual(one, two);
});

for (const nonceForm of [
  'MTIzNDU2Nzg5MDEyMzQ1Ng==',
  'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng==',
  "'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng=='"
]) {
  test('strict preset accepts nonce form: ' + nonceForm, () => {
    const header = createStrictCsp({ nonce: nonceForm });
    assert.equal(header.includes('MTIzNDU2Nzg5MDEyMzQ1Ng=='), true);
  });
}

for (const nonce of ['', 'not base64!', 'x'.repeat(300)]) {
  test('strict preset rejects malformed nonce input: ' + JSON.stringify(nonce).slice(0, 30), () => {
    expectError(() => createStrictCsp({ nonce }), CODE.INVALID_NONCE_INPUT);
  });
}

test('strict preset includes report-to when supplied', () => {
  assert.equal(createStrictCsp({ reportTo: 'csp-endpoint' }).includes('report-to csp-endpoint'), true);
});

test('strict preset can include legacy report-uri explicitly', () => {
  assert.equal(createStrictCsp({ reportUri: '/csp' }).includes('report-uri /csp'), true);
});

test('strict preset applies custom connect and image arrays', () => {
  const header = createStrictCsp({ connectSrc: ["'self'", 'https://api.example.com'], imgSrc: ["'self'"] });
  assert.equal(header.includes("connect-src 'self' https://api.example.com"), true);
  assert.equal(header.includes("img-src 'self';"), true);
});

test('strict preset supports Trusted Types requirement', () => {
  assert.equal(createStrictCsp({ requireTrustedTypesFor: true }).includes("require-trusted-types-for 'script'"), true);
});

test('strict preset can omit upgrade-insecure-requests explicitly', () => {
  assert.equal(createStrictCsp({ upgradeInsecureRequests: false }).includes('upgrade-insecure-requests'), false);
});

test('strict preset rejects unknown options', () => {
  expectError(() => createStrictCsp({ unknown: true }), CODE.INVALID_OPTIONS);
});

test('generateNonce default returns 16 random bytes as base64', () => {
  const nonce = generateNonce();
  assert.equal(Buffer.from(nonce, 'base64').length, 16);
  assert.match(nonce, /^[A-Za-z0-9+/]+={0,2}$/u);
});

for (const bytes of [16, 17, 24, 32, 48, 64]) {
  test('generateNonce supports size ' + bytes, () => {
    assert.equal(Buffer.from(generateNonce(bytes), 'base64').length, bytes);
  });
}

for (let index = 0; index < 12; index += 1) {
  test('generateNonce output is unique in sample ' + index, () => {
    const values = new Set(Array.from({ length: 8 }, () => generateNonce()));
    assert.equal(values.size, 8);
  });
}

for (const bytes of [-1, 0, 1, 8, 15, 65, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '16']) {
  test('generateNonce rejects invalid size: ' + String(bytes), () => {
    expectError(() => generateNonce(bytes), CODE.INVALID_NONCE_INPUT);
  });
}

test('computeHash matches sha256 test vector for x', () => {
  assert.equal(computeHash('x', 'sha256'), 'sha256-LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=');
});

test('computeHash matches sha256 empty input vector', () => {
  assert.equal(computeHash('', 'sha256'), 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
});

for (const [algorithm, bytes] of [['sha256', 32], ['sha384', 48], ['sha512', 64]]) {
  test('computeHash returns correct digest length for ' + algorithm, () => {
    const value = computeHash('content', algorithm);
    assert.equal(value.startsWith(algorithm + '-'), true);
    assert.equal(Buffer.from(value.slice(algorithm.length + 1), 'base64').length, bytes);
  });
}

test('computeHash accepts Uint8Array content', () => {
  assert.equal(computeHash(new Uint8Array([120]), 'sha256'), computeHash('x', 'sha256'));
});

test('computeHash accepts ArrayBuffer content', () => {
  assert.equal(computeHash(new Uint8Array([120]).buffer, 'sha256'), computeHash('x', 'sha256'));
});

for (const algorithm of ['sha1', 'md5', 'SHA256', '', null]) {
  test('computeHash rejects algorithm: ' + String(algorithm), () => {
    expectError(() => computeHash('x', algorithm), CODE.INVALID_HASH_INPUT);
  });
}

for (const content of [null, undefined, 1, {}, []]) {
  test('computeHash rejects content type: ' + String(content), () => {
    expectError(() => computeHash(content, 'sha256'), CODE.INVALID_HASH_INPUT);
  });
}

test('mergeCsp unions source allowlists deterministically', () => {
  const output = mergeCsp([
    "script-src 'self'; object-src 'none'",
    'script-src https://cdn.example.com/app.js'
  ]);
  assert.equal(output, "script-src 'self' https://cdn.example.com/app.js; object-src 'none'");
});

test('mergeCsp supports variadic inputs', () => {
  const output = mergeCsp("script-src 'self'", 'script-src https://cdn.example.com/app.js');
  assert.equal(output, "script-src 'self' https://cdn.example.com/app.js");
});

test('mergeCsp accepts directive objects', () => {
  const output = mergeCsp([{ scriptSrc: ["'self'"] }, { scriptSrc: ['https://cdn.example.com/app.js'] }]);
  assert.equal(output, "script-src 'self' https://cdn.example.com/app.js");
});

test('mergeCsp accepts parsed policies', () => {
  const output = mergeCsp([parseCsp("script-src 'self'"), parseCsp('script-src https://cdn.example.com/app.js')]);
  assert.equal(output, "script-src 'self' https://cdn.example.com/app.js");
});

test('mergeCsp deduplicates overlapping sources', () => {
  const output = mergeCsp(["script-src 'self'", "script-src 'self'"]);
  assert.equal(output, "script-src 'self'");
});

for (const pair of [
  ["script-src 'none'", "script-src 'self'"],
  ["script-src 'self'", "script-src 'none'"],
  ["script-src 'none'", "script-src 'none'"]
]) {
  test('mergeCsp never silently widens none: ' + pair.join(' plus '), () => {
    assert.equal(mergeCsp(pair), "script-src 'none'");
  });
}

test('allowNoneWidening is explicit and removes none only when other sources exist', () => {
  const output = mergeCsp(["script-src 'none'", "script-src 'self'"], { allowNoneWidening: true });
  assert.equal(output, "script-src 'self'");
});

test('allowNoneWidening keeps lone none', () => {
  const output = mergeCsp(["script-src 'none'"], { allowNoneWidening: true });
  assert.equal(output, "script-src 'none'");
});

test('mergeCsp blocks unsafe-inline by default', () => {
  expectError(() => mergeCsp(["script-src 'unsafe-inline'", "script-src 'self'"]), CODE.UNSAFE_INLINE_MERGE);
});

test('mergeCsp allows unsafe-inline only by explicit request', () => {
  const output = mergeCsp(["script-src 'unsafe-inline'", "script-src 'self'"], { allowUnsafeInline: true });
  assert.equal(output, "script-src 'unsafe-inline' 'self'");
});

test('mergeCsp rejects multi-policy input', () => {
  expectError(() => mergeCsp(["script-src 'self', object-src 'none'"]), CODE.INVALID_MERGE_INPUT);
});

for (const input of [null, 1, true, []]) {
  test('mergeCsp rejects invalid input shape: ' + String(input), () => {
    expectError(() => mergeCsp([input]), CODE.INVALID_MERGE_INPUT);
  });
}

test('mergeCsp rejects prototype-pollution keys in directive objects', () => {
  const input = Object.create(null);
  input.constructor = ["'self'"];
  expectError(() => mergeCsp([input]), CODE.PROTOTYPE_POLLUTION);
});

test('mergeCsp rejects unknown options', () => {
  expectError(() => mergeCsp(["script-src 'self'"], { unknown: true }), CODE.INVALID_OPTIONS);
});

test('intersectCsp keeps only common source expressions', () => {
  const output = intersectCsp([
    "script-src 'self' https://one.example.com",
    "script-src 'self' https://two.example.com"
  ]);
  assert.equal(output, "script-src 'self'");
});

test('intersectCsp falls back to none for disjoint source sets', () => {
  const output = intersectCsp([
    'script-src https://one.example.com',
    'script-src https://two.example.com'
  ]);
  assert.equal(output, "script-src 'none'");
});

test('intersectCsp none dominates', () => {
  const output = intersectCsp(["script-src 'none'", "script-src 'self'"]);
  assert.equal(output, "script-src 'none'");
});

test('intersectCsp carries restrictive directives present in one input', () => {
  const output = intersectCsp(["script-src 'self'; object-src 'none'", "script-src 'self'"]);
  assert.equal(output, "script-src 'self'; object-src 'none'");
});

test('intersectCsp blocks common unsafe-inline by default', () => {
  expectError(() => intersectCsp(["script-src 'unsafe-inline'", "script-src 'unsafe-inline'"]), CODE.UNSAFE_INLINE_MERGE);
});

test('diffCsp reports added removed changed and unchanged directives', () => {
  const before = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'";
  const after = "default-src 'self'; script-src 'self' https://cdn.example.com/app.js; frame-ancestors 'none'";
  const diff = diffCsp(before, after);
  assert.deepEqual(diff.addedDirectives, ['frame-ancestors']);
  assert.deepEqual([...diff.removedDirectives].sort(), ['base-uri', 'object-src']);
  assert.equal(diff.changedDirectives.length, 1);
  assert.equal(diff.changedDirectives[0].name, 'script-src');
  assert.deepEqual(diff.changedDirectives[0].addedSources, ['https://cdn.example.com/app.js']);
  assert.deepEqual(diff.unchangedDirectives, ['default-src']);
});

test('diffCsp treats source order as a set', () => {
  const diff = diffCsp("script-src 'self' https://a.example.com", "script-src https://a.example.com 'self'");
  assert.equal(diff.summary.changedCount, 0);
});

test('diffCsp summary counts match collections', () => {
  const diff = diffCsp("script-src 'self'", "script-src 'self'; object-src 'none'");
  assert.equal(diff.summary.addedCount, diff.addedDirectives.length);
  assert.equal(diff.summary.removedCount, diff.removedDirectives.length);
  assert.equal(diff.summary.changedCount, diff.changedDirectives.length);
  assert.equal(diff.summary.unchangedCount, diff.unchangedDirectives.length);
});

test('diff output is deeply frozen', () => {
  const diff = diffCsp("script-src 'self'", "script-src 'none'");
  assert.equal(Object.isFrozen(diff), true);
  assert.equal(Object.isFrozen(diff.summary), true);
});
