import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditCsp,
  computeHash,
  createStrictCsp,
  generateNonce,
  isSafeCsp,
  parseCsp
} from '../src/index.mjs';
import { assertFrozenDeep, assertHasCode, assertNoCode, codes } from './helpers.mjs';

function baseline(scriptValue = "'self'") {
  return "default-src 'self'; script-src " + scriptValue + "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
}

function policyWith(name, value) {
  const parts = [
    ['default-src', "'self'"],
    ['script-src', "'self'"],
    ['object-src', "'none'"],
    ['base-uri', "'none'"],
    ['frame-ancestors', "'none'"]
  ];
  let replaced = false;
  const output = parts.map(([directive, current]) => {
    if (directive === name) {
      replaced = true;
      return directive + ' ' + value;
    }
    return directive + ' ' + current;
  });
  if (!replaced) output.push(name + ' ' + value);
  return output.join('; ');
}

const strongNonce = 'MTIzNDU2Nzg5MDEyMzQ1Ng==';
const strongHash = computeHash('console.log(1)', 'sha256');

test('strict lockdown policy is safe with zero findings', () => {
  const report = auditCsp("default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(report.safe, true);
  assert.equal(report.grade, 'A+');
  assert.equal(report.score, 100);
  assert.equal(report.counts.errors, 0);
  assert.equal(report.counts.warnings, 0);
});

test('createStrictCsp output reaches strict-CSP shape', () => {
  const report = auditCsp(createStrictCsp({ nonce: generateNonce() }), { strict: true });
  assert.equal(report.safe, true);
  assert.equal(report.strictCsp, true);
  assert.equal(report.grade, 'A+');
  assert.equal(report.score, 100);
});

test('auditor accepts an already parsed policy', () => {
  const parsed = parseCsp(baseline());
  const report = auditCsp(parsed);
  assert.equal(report.valid, true);
  assert.equal(report.policyCount, 1);
});

test('auditor does not throw for malformed hostile text', () => {
  const report = auditCsp("script-src 'self'\r\nmalformed");
  assert.equal(report.valid, false);
  assert.equal(report.safe, false);
  assertHasCode(report, 'CSPCAGE_HEADER_INJECTION');
});

test('auditor does not throw for invalid input types', () => {
  for (const input of [null, undefined, 1, {}, []]) {
    const report = auditCsp(input);
    assert.equal(report.valid, false);
    assert.equal(report.safe, false);
  }
});

test('audit report and findings are deeply frozen', () => {
  const report = auditCsp(baseline());
  assertFrozenDeep(report);
});

test('finding objects expose machine-readable shape', () => {
  const report = auditCsp(baseline("'unsafe-inline'"));
  const finding = report.findings.find((item) => item.code === 'UNSAFE_INLINE_ACTIVE');
  assert.equal(typeof finding.message, 'string');
  assert.equal(typeof finding.recommendation, 'string');
  assert.equal(finding.directive, 'script-src');
  assert.equal(finding.policyIndex, 0);
});

test('strict mode makes warnings blocking', () => {
  const input = baseline("'nonce-" + strongNonce + "' 'unsafe-inline'");
  assert.equal(auditCsp(input).safe, true);
  assert.equal(auditCsp(input, { strict: true }).safe, false);
});

test('active unsafe-inline in script-src is an error', () => {
  const report = auditCsp(baseline("'unsafe-inline'"));
  assertHasCode(report, 'UNSAFE_INLINE_ACTIVE');
  assert.equal(report.safe, false);
});

test('active unsafe-inline in script-src-elem is an error', () => {
  const input = policyWith('script-src-elem', "'unsafe-inline'");
  const report = auditCsp(input);
  assertHasCode(report, 'UNSAFE_INLINE_ACTIVE');
});

test('active unsafe-inline in default-src fallback is an error', () => {
  const input = "default-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  const report = auditCsp(input);
  assertHasCode(report, 'UNSAFE_INLINE_ACTIVE');
});

test('nonce causes CSP3 unsafe-inline to be reported as legacy-shadowed', () => {
  const report = auditCsp(baseline("'nonce-" + strongNonce + "' 'unsafe-inline'"));
  assertHasCode(report, 'CSP3_UNSAFE_INLINE_IGNORED');
  assertNoCode(report, 'UNSAFE_INLINE_ACTIVE');
});

test('hash causes CSP3 unsafe-inline to be reported as legacy-shadowed', () => {
  const report = auditCsp(baseline("'" + strongHash + "' 'unsafe-inline'"));
  assertHasCode(report, 'CSP3_UNSAFE_INLINE_IGNORED');
  assertNoCode(report, 'UNSAFE_INLINE_ACTIVE');
});

test('strict-dynamic alone does not mark unsafe-inline as ignored', () => {
  const report = auditCsp(baseline("'strict-dynamic' 'unsafe-inline'"));
  assertHasCode(report, 'UNSAFE_INLINE_ACTIVE');
});

for (const keyword of ['unsafe-eval', 'wasm-unsafe-eval']) {
  test('detects dangerous eval keyword: ' + keyword, () => {
    const code = keyword === 'unsafe-eval' ? 'UNSAFE_EVAL' : 'WASM_UNSAFE_EVAL';
    const report = auditCsp(baseline("'" + keyword + "'"));
    assertHasCode(report, code);
    assert.equal(report.safe, false);
  });
}

test('detects unsafe-hashes as a warning', () => {
  const report = auditCsp(baseline("'" + strongHash + "' 'unsafe-hashes'"));
  assertHasCode(report, 'UNSAFE_HASHES');
});

test('detects strict-dynamic without strong nonce or hash', () => {
  const report = auditCsp(baseline("'strict-dynamic'"));
  assertHasCode(report, 'STRICT_DYNAMIC_WITHOUT_STRONG_PROOF');
});

test('script-src alone leaves fallback and hardening gaps', () => {
  const report = auditCsp("script-src 'self'");
  for (const code of ['MISSING_DEFAULT_SRC', 'MISSING_OBJECT_SRC', 'MISSING_BASE_URI', 'MISSING_FRAME_ANCESTORS']) assertHasCode(report, code);
});

test('default-src fallback without script-src is detected', () => {
  const report = auditCsp("default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assertHasCode(report, 'MISSING_SCRIPT_SRC');
});

test('missing script and default policy is an error', () => {
  const report = auditCsp("object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assertHasCode(report, 'MISSING_SCRIPT_POLICY');
  assertHasCode(report, 'MISSING_DEFAULT_SRC');
});

test('missing object-src is detected even with a restrictive default', () => {
  const report = auditCsp("default-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assertHasCode(report, 'MISSING_OBJECT_SRC');
});

for (const value of ["'self'", '*', 'https:', 'https://objects.example.com']) {
  test('object-src not exactly none is blocked: ' + value, () => {
    const report = auditCsp(policyWith('object-src', value));
    assertHasCode(report, 'OBJECT_SRC_NOT_NONE');
  });
}

test('missing base-uri is detected', () => {
  const report = auditCsp("default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
  assertHasCode(report, 'MISSING_BASE_URI');
});

for (const value of ['*', 'https:', 'https://evil.example.com']) {
  test('weak base-uri is blocked: ' + value, () => {
    const report = auditCsp(policyWith('base-uri', value));
    assertHasCode(report, 'WEAK_BASE_URI');
  });
}

test("base-uri 'self' is accepted", () => {
  const report = auditCsp(policyWith('base-uri', "'self'"));
  assertNoCode(report, 'WEAK_BASE_URI');
});

test('missing frame-ancestors is detected', () => {
  const report = auditCsp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'");
  assertHasCode(report, 'MISSING_FRAME_ANCESTORS');
}

);

for (const value of ['*', 'https:', 'http:', 'https://*.example.com', 'http://parent.example.com']) {
  test('weak frame-ancestors is blocked: ' + value, () => {
    const report = auditCsp(policyWith('frame-ancestors', value));
    assertHasCode(report, 'WEAK_FRAME_ANCESTORS');
  });
}

test("frame-ancestors 'self' is accepted", () => {
  const report = auditCsp(policyWith('frame-ancestors', "'self'"));
  assertNoCode(report, 'WEAK_FRAME_ANCESTORS');
});

test('exact HTTPS frame ancestor host is accepted structurally', () => {
  const report = auditCsp(policyWith('frame-ancestors', 'https://parent.example.com'));
  assertNoCode(report, 'WEAK_FRAME_ANCESTORS');
});

const criticalDirectives = ['script-src', 'object-src', 'default-src', 'connect-src'];
const criticalSchemes = ['*', 'https:', 'http:', 'data:', 'blob:', 'filesystem:'];

for (const directiveName of criticalDirectives) {
  for (const source of criticalSchemes) {
    test('critical source matrix ' + directiveName + ' ' + source, () => {
      const report = auditCsp(policyWith(directiveName, source));
      if (source === '*') assertHasCode(report, 'WILDCARD_SOURCE');
      if (source === 'https:') assertHasCode(report, 'BROAD_HTTPS_SCHEME');
      if (source === 'http:') assertHasCode(report, 'INSECURE_HTTP_SCHEME');
      if (source === 'data:' || source === 'blob:' || source === 'filesystem:') assertHasCode(report, 'DANGEROUS_DATA_SCHEME');
    });
  }
}

for (const directiveName of criticalDirectives) {
  test('explicit HTTP host is blocked in ' + directiveName, () => {
    const report = auditCsp(policyWith(directiveName, 'http://cdn.example.com'));
    assertHasCode(report, 'INSECURE_HTTP_HOST');
  });
}

for (const directiveName of criticalDirectives) {
  test('subdomain wildcard host is blocked in ' + directiveName, () => {
    const report = auditCsp(policyWith(directiveName, 'https://*.example.com'));
    assertHasCode(report, 'WILDCARD_HOST_SOURCE');
  });
}

test('javascript scheme is blocked in script-src', () => {
  const report = auditCsp(policyWith('script-src', 'javascript:'));
  assertHasCode(report, 'DANGEROUS_SCRIPT_SCHEME');
});

test('data scheme in img-src is outside the critical script matrix', () => {
  const report = auditCsp(policyWith('img-src', 'data:'));
  assertNoCode(report, 'DANGEROUS_DATA_SCHEME');
});

const gadgetHosts = [
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
];

for (const host of gadgetHosts) {
  test('detects CDN script gadget host: ' + host, () => {
    const report = auditCsp(baseline('https://' + host));
    assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
  });
}

for (const host of gadgetHosts) {
  test('detects wildcard CDN script gadget host: ' + host, () => {
    const report = auditCsp(baseline('https://*.' + host));
    assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
  });
}

for (const host of gadgetHosts) {
  test('exact path does not erase CDN gadget host risk: ' + host, () => {
    const report = auditCsp(baseline('https://' + host + '/exact-versioned-file.js'));
    assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
  });
}

test('detects bare jsDelivr host as a CDN script gadget host', () => {
  const report = auditCsp(baseline('https://jsdelivr.net'));
  assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

test('detects subdomain of a known gadget host', () => {
  const report = auditCsp(baseline('https://ajax.googleapis.com'));
  assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

test('does not match unrelated lookalike gadget suffix text', () => {
  const report = auditCsp(baseline('https://evilcdnjscloudflarecom.example.com'));
  assertNoCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

test('strict-dynamic suppresses obsolete host gadget allowlist finding', () => {
  const report = auditCsp(baseline("'nonce-" + strongNonce + "' 'strict-dynamic' https://cdn.jsdelivr.net"));
  assertNoCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

test('valid hash does not suppress live CDN host gadget finding', () => {
  const report = auditCsp(baseline("'" + strongHash + "' https://cdn.jsdelivr.net"));
  assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

test('nonce alone does not suppress CDN gadget host finding', () => {
  const report = auditCsp(baseline("'nonce-" + strongNonce + "' https://cdn.jsdelivr.net"));
  assertHasCode(report, 'CDN_SCRIPT_GADGET_HOST');
});

for (const bytes of [1, 4, 8, 15]) {
  test('detects weak nonce entropy at ' + bytes + ' bytes', () => {
    const nonce = Buffer.alloc(bytes, 7).toString('base64');
    const report = auditCsp(baseline("'nonce-" + nonce + "'"));
    assertHasCode(report, 'WEAK_NONCE_ENTROPY');
  });
}

for (const bytes of [16, 24, 32]) {
  test('accepts nonce entropy at ' + bytes + ' bytes', () => {
    const nonce = Buffer.alloc(bytes, 7).toString('base64');
    const report = auditCsp(baseline("'nonce-" + nonce + "'"));
    assertNoCode(report, 'WEAK_NONCE_ENTROPY');
  });
}

for (const nonce of ['123456', 'test', 'abc123', '000000']) {
  test('detects predictable nonce placeholder: ' + nonce, () => {
    const report = auditCsp(baseline("'nonce-" + nonce + "'"));
    assertHasCode(report, 'STATIC_NONCE_PLACEHOLDER');
  });
}

test('detects repeated nonce reuse inside one policy', () => {
  const input = baseline("'nonce-" + strongNonce + "'") + "; style-src 'nonce-" + strongNonce + "'";
  const report = auditCsp(input);
  assertHasCode(report, 'REPEATED_NONCE');
});

test('sha1 hash rejection appears as a parse audit error', () => {
  const report = auditCsp(baseline("'sha1-abcdefghij'"));
  assertHasCode(report, 'CSPCAGE_UNSUPPORTED_HASH_ALGORITHM');
});

test('malformed hash appears as a parse audit error', () => {
  const report = auditCsp(baseline("'sha256-short'"));
  assertHasCode(report, 'CSPCAGE_MALFORMED_HASH');
});

for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  test('valid ' + algorithm + ' hash has no malformed-hash finding', () => {
    const report = auditCsp(baseline("'" + computeHash('x', algorithm) + "'"));
    assertNoCode(report, 'CSPCAGE_MALFORMED_HASH');
  });
}

function reportingPolicy(endpoint, directiveName = 'report-uri') {
  return baseline() + '; ' + directiveName + ' ' + endpoint;
}

const endpointCases = [
  ['http://reports.example.com/csp', 'REPORT_ENDPOINT_NOT_HTTPS'],
  ['https://user:pass@reports.example.com/csp', 'REPORT_ENDPOINT_CREDENTIALS'],
  ['https://127.0.0.1/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://localhost/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://10.0.0.1/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://172.16.0.1/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://192.168.1.1/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://169.254.1.1/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['https://[::1]/csp', 'REPORT_ENDPOINT_PRIVATE_NETWORK'],
  ['//reports.example.com/csp', 'REPORT_ENDPOINT_PROTOCOL_RELATIVE'],
  ['https://reports.example.com/', 'REPORT_ENDPOINT_TOO_BROAD']
];

for (const [endpoint, code] of endpointCases) {
  test('detects reporting endpoint hazard ' + endpoint, () => {
    const report = auditCsp(reportingPolicy(endpoint));
    assertHasCode(report, code);
    assertHasCode(report, 'LEGACY_REPORT_URI');
  });
}

test('protocol-relative reporting endpoint is still audited for host hazards', () => {
  const report = auditCsp(reportingPolicy('//user:pass@localhost/csp'));
  assertHasCode(report, 'REPORT_ENDPOINT_PROTOCOL_RELATIVE');
  assertHasCode(report, 'REPORT_ENDPOINT_CREDENTIALS');
  assertHasCode(report, 'REPORT_ENDPOINT_PRIVATE_NETWORK');
});

test('trailing-dot localhost reporting endpoint is treated as loopback', () => {
  const report = auditCsp(reportingPolicy('https://localhost./csp'));
  assertHasCode(report, 'REPORT_ENDPOINT_PRIVATE_NETWORK');
});

test('valid HTTPS report-uri only carries legacy mechanism warning', () => {
  const report = auditCsp(reportingPolicy('https://reports.example.com/csp'));
  assertHasCode(report, 'LEGACY_REPORT_URI');
  assertNoCode(report, 'REPORT_ENDPOINT_NOT_HTTPS');
  assertNoCode(report, 'REPORT_ENDPOINT_PRIVATE_NETWORK');
  assertNoCode(report, 'REPORT_ENDPOINT_CREDENTIALS');
});

test('report-to URL form is audited as an endpoint', () => {
  const report = auditCsp(reportingPolicy('http://reports.example.com/csp', 'report-to'));
  assertHasCode(report, 'REPORT_ENDPOINT_NOT_HTTPS');
});

test('report-to group name is not treated as a URL', () => {
  const report = auditCsp(reportingPolicy('csp-endpoint', 'report-to'));
  assertNoCode(report, 'REPORT_ENDPOINT_NOT_HTTPS');
  assertNoCode(report, 'LEGACY_REPORT_URI');
});

test('safe baseline receives A or better grade', () => {
  const report = auditCsp(baseline());
  assert.equal(report.safe, true);
  assert.equal(report.score, 100);
  assert.equal(report.grade, 'A+');
});

test('active unsafe-inline materially reduces score', () => {
  const report = auditCsp(baseline("'unsafe-inline'"));
  assert.equal(report.score <= 65, true);
  assert.equal(['D', 'F'].includes(report.grade), true);
});

test('multiple severe bypasses drive score toward zero', () => {
  const report = auditCsp(baseline("'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net"));
  assert.equal(report.score < 30, true);
  assert.equal(report.grade, 'F');
});

test('warnings reduce score without making non-strict audit unsafe', () => {
  const report = auditCsp(reportingPolicy('https://reports.example.com/csp'));
  assert.equal(report.safe, true);
  assert.equal(report.score < 100, true);
});

test('parse-invalid policy score is capped', () => {
  const report = auditCsp("script-src 'sha1-abcdefghij'");
  assert.equal(report.score <= 45, true);
  assert.equal(report.grade, 'F');
});

test('multi-policy report uses the worst policy score', () => {
  const strict = "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  const weak = baseline("'unsafe-inline'");
  const report = auditCsp(strict + ', ' + weak);
  assert.equal(report.policyCount, 2);
  assert.equal(report.policyResults.length, 2);
  assert.equal(report.score, Math.min(...report.policyResults.map((item) => item.score)));
});

test('two independently strict policies can both be strict-CSP shape', () => {
  const one = createStrictCsp({ nonce: generateNonce() });
  const two = createStrictCsp({ nonce: generateNonce() });
  const report = auditCsp(one + ', ' + two);
  assert.equal(report.policyCount, 2);
  assert.equal(report.strictCsp, true);
});

test('finding policy indexes distinguish policies', () => {
  const strict = "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  const weak = baseline("'unsafe-inline'");
  const report = auditCsp(strict + ', ' + weak);
  const finding = report.findings.find((item) => item.code === 'UNSAFE_INLINE_ACTIVE');
  assert.equal(finding.policyIndex, 1);
});

test('repeated nonce across policies is detected', () => {
  const nonce = generateNonce();
  const one = createStrictCsp({ nonce });
  const two = createStrictCsp({ nonce });
  const report = auditCsp(one + ', ' + two);
  assertHasCode(report, 'REPEATED_NONCE');
});

test('array input audits as multiple policies', () => {
  const report = auditCsp([baseline(), baseline("'unsafe-inline'")]);
  assert.equal(report.policyCount, 2);
});

test('isSafeCsp mirrors audit safe decision', () => {
  assert.equal(isSafeCsp(baseline()), true);
  assert.equal(isSafeCsp(baseline("'unsafe-inline'")), false);
});

test('finding count remains bounded by configuration', () => {
  const tokens = Array.from({ length: 20 }, () => "'unsafe-inline'").join(' ');
  const report = auditCsp(baseline(tokens), { maxFindings: 10 });
  assert.equal(report.findings.length <= 10, true);
});

test('finding cap fails closed and cannot suppress error severity', () => {
  for (const cap of [1, 2, 3, 4]) {
    const report = auditCsp("script-src 'unsafe-inline'", { maxFindings: cap });
    assert.equal(report.counts.errors > 0, true);
    assert.equal(report.safe, false);
    assert.equal(report.findings.length <= cap, true);
    assertHasCode(report, 'CSPCAGE_FINDINGS_TRUNCATED');
  }
});

test('audit output never exposes raw source token text in finding messages', () => {
  const sentinelHost = 'sentinel-invalid-host.example';
  const report = auditCsp(baseline('https://' + sentinelHost));
  for (const finding of report.findings) {
    assert.equal(finding.message.includes(sentinelHost), false);
  }
});

test('script-src-attr unsafe-inline is audited', () => {
  const report = auditCsp(policyWith('script-src-attr', "'unsafe-inline'"));
  assertHasCode(report, 'UNSAFE_INLINE_ACTIVE');
});

test('frame-ancestors wildcard host is weak', () => {
  const report = auditCsp(policyWith('frame-ancestors', 'https://*.example.com'));
  assertHasCode(report, 'WEAK_FRAME_ANCESTORS');
});

test('audit of strict policy exposes no unexpected codes', () => {
  const report = auditCsp(createStrictCsp({ nonce: generateNonce() }));
  assert.deepEqual(codes(report), []);
});

for (const source of ['example.com:*', 'https://example.com:*/path']) {
  test('detects wildcard port in critical directive: ' + source, () => {
    const report = auditCsp(policyWith('script-src', source));
    assertHasCode(report, 'WILDCARD_PORT_SOURCE');
  });
}

for (const nonce of ['AAAAAAAAAAAAAAAAAAAAAA==', 'AQIDBAUGBwgJCgsMDQ4PEA==', 'AQIBAgECAQIBAgECAQIBAg==']) {
  test('detects low-complexity nonce bytes: ' + nonce, () => {
    const report = auditCsp(baseline("'nonce-" + nonce + "'"));
    assertHasCode(report, 'STATIC_NONCE_PLACEHOLDER');
  });
}

test('wildcard port in form-action is detected', () => {
  const report = auditCsp(policyWith('form-action', 'https://example.com:*'));
  assertHasCode(report, 'WILDCARD_PORT_SOURCE');
});

test('wildcard host in form-action is detected', () => {
  const report = auditCsp(policyWith('form-action', 'https://*.example.com'));
  assertHasCode(report, 'WILDCARD_HOST_SOURCE');
});

for (const endpoint of ['https://100.64.0.1/csp', 'https://198.18.0.1/csp', 'https://[::ffff:127.0.0.1]/csp']) {
  test('detects non-public reporting network target: ' + endpoint, () => {
    const report = auditCsp(reportingPolicy(endpoint));
    assertHasCode(report, 'REPORT_ENDPOINT_PRIVATE_NETWORK');
  });
}

test('auditor rejects malformed parsed-shaped objects without throwing', () => {
  const malformed = {
    policyCount: 1,
    policies: [{ directiveMap: {}, directives: [{ name: 'script-src', tokens: [], sources: [null] }] }]
  };
  const report = auditCsp(malformed);
  assert.equal(report.valid, false);
  assert.equal(report.safe, false);
});

test('auditor rejects null options without throwing', () => {
  const report = auditCsp(baseline(), null);
  assert.equal(report.valid, true);
});

test('bare https scheme in script-src makes policy unsafe', () => {
  const report = auditCsp(policyWith('script-src', 'https:'));
  assert.equal(report.safe, false);
  assertHasCode(report, 'BROAD_HTTPS_SCHEME');
});
