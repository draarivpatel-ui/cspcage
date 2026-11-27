import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'cspcage.mjs');
const strictPolicy = "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const strictBuild = JSON.stringify({
  defaultSrc: ["'none'"],
  scriptSrc: ["'none'"],
  objectSrc: ["'none'"],
  baseUri: ["'none'"],
  frameAncestors: ["'none'"]
});

function run(args, input = '') {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, input, encoding: 'utf8', timeout: 10000 });
}

function assertNoStack(result) {
  assert.equal(result.stderr.includes('\n    at '), false, result.stderr);
  assert.equal(result.stderr.includes('node:internal'), false, result.stderr);
}

test('CLI prints version', () => {
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'cspcage 1.0.0\n');
});

test('CLI prints help with zero status when requested', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('Usage:'), true);
});

test('CLI missing command is usage error', () => {
  const result = run([]);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI unknown command is usage error', () => {
  const result = run(['not-a-command']);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI unknown option is usage error', () => {
  const result = run(['parse', strictPolicy, '--wat']);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI parse accepts valid policy argument', () => {
  const result = run(['parse', strictPolicy]);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('valid=true'), true);
});

test('CLI parse accepts valid policy from stdin', () => {
  const result = run(['parse', '-'], strictPolicy);
  assert.equal(result.status, 0);
});

test('CLI parse JSON emits structured policy', () => {
  const result = run(['parse', '--json', strictPolicy]);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.valid, true);
  assert.equal(parsed.policyCount, 1);
  assert.equal(parsed.directiveCount, 5);
});

test('CLI parse reports multi-policy count', () => {
  const result = run(['parse', '--json', strictPolicy + ', ' + strictPolicy]);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).policyCount, 2);
});

test('CLI parse rejects duplicate directives with exit 1', () => {
  const result = run(['parse', "script-src 'self'; script-src 'none'"]);
  assert.equal(result.status, 1);
  assert.equal(result.stderr.includes('CSPCAGE_DUPLICATE_DIRECTIVE'), true);
  assertNoStack(result);
});

test('CLI parse rejects CRLF injection without stack trace', () => {
  const result = run(['parse', "script-src 'self'\r\nobject-src 'none'"]);
  assert.equal(result.status, 1);
  assertNoStack(result);
});

test('CLI parse rejects unknown directive without stack trace', () => {
  const result = run(['parse', 'made-up-directive x']);
  assert.equal(result.status, 1);
  assertNoStack(result);
});

test('CLI parse missing input is usage error', () => {
  const result = run(['parse']);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI audit accepts strict lockdown policy', () => {
  const result = run(['audit', strictPolicy]);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('safe=true'), true);
});

test('CLI audit rejects active unsafe-inline', () => {
  const result = run(['audit', "script-src 'unsafe-inline'"]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('UNSAFE_INLINE_ACTIVE'), true);
  assertNoStack(result);
});

test('CLI audit JSON emits machine-readable report', () => {
  const result = run(['audit', '--json', strictPolicy]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.safe, true);
  assert.equal(report.grade, 'A+');
  assert.equal(Array.isArray(report.findings), true);
});

test('CLI audit warning-only report passes without strict', () => {
  const policy = strictPolicy + '; report-uri https://reports.example.com/csp';
  const result = run(['audit', policy]);
  assert.equal(result.status, 0);
});

test('CLI audit warning-only report fails with strict', () => {
  const policy = strictPolicy + '; report-uri https://reports.example.com/csp';
  const result = run(['audit', '--strict', policy]);
  assert.equal(result.status, 1);
});

test('CLI audit accepts stdin', () => {
  const result = run(['audit', '-'], strictPolicy);
  assert.equal(result.status, 0);
});

test('CLI audit malformed input never emits stack trace', () => {
  const result = run(['audit', '-'], 'script-src \0');
  assert.equal(result.status, 1);
  assertNoStack(result);
});

test('CLI build writes deterministic header', () => {
  const result = run(['build', strictBuild]);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, strictPolicy + '\n');
});

test('CLI build accepts JSON directives from stdin', () => {
  const result = run(['build', '-'], strictBuild);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, strictPolicy + '\n');
});

test('CLI build JSON emits header and audit', () => {
  const result = run(['build', '--json', strictBuild]);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.header, strictPolicy);
  assert.equal(output.audit.safe, true);
});

test('CLI build blocks unsafe-inline', () => {
  const result = run(['build', JSON.stringify({ scriptSrc: ["'unsafe-inline'"] })]);
  assert.equal(result.status, 1);
  assertNoStack(result);
});

test('CLI build blocks injection input', () => {
  const result = run(['build', JSON.stringify({ scriptSrc: ["'self'; object-src *"] })]);
  assert.equal(result.status, 1);
  assertNoStack(result);
});

test('CLI build invalid JSON is usage error', () => {
  const result = run(['build', '{broken']);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI build strict blocks warning-only transitional policy', () => {
  const result = run(['build', '--strict', JSON.stringify({ scriptSrc: ["'self'"] })]);
  assert.equal(result.status, 1);
});

test('CLI nonce prints default nonce', () => {
  const result = run(['nonce']);
  assert.equal(result.status, 0);
  assert.equal(Buffer.from(result.stdout.trim(), 'base64').length, 16);
});

test('CLI nonce prints requested size', () => {
  const result = run(['nonce', '32']);
  assert.equal(result.status, 0);
  assert.equal(Buffer.from(result.stdout.trim(), 'base64').length, 32);
});

test('CLI nonce JSON shape is correct', () => {
  const result = run(['nonce', '24', '--json']);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.bytes, 24);
  assert.equal(Buffer.from(output.nonce, 'base64').length, 24);
});

for (const bytes of ['0', '8', '65', 'x']) {
  test('CLI nonce rejects invalid size ' + bytes, () => {
    const result = run(['nonce', bytes]);
    assert.equal(result.status, 2);
    assertNoStack(result);
  });
}

test('CLI hash computes sha256 vector for x', () => {
  const result = run(['hash', 'sha256', 'x']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'sha256-LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=\n');
});

for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  test('CLI hash supports ' + algorithm, () => {
    const result = run(['hash', algorithm, 'content']);
    assert.equal(result.status, 0);
    assert.equal(result.stdout.startsWith(algorithm + '-'), true);
  });
}

test('CLI hash reads content from stdin', () => {
  const result = run(['hash', 'sha256', '-'], 'x');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'sha256-LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=\n');
});

test('CLI hash JSON shape is correct', () => {
  const result = run(['hash', 'sha256', 'x', '--json']);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.algorithm, 'sha256');
  assert.equal(output.hash.startsWith('sha256-'), true);
});

test('CLI hash rejects invalid algorithm without stack trace', () => {
  const result = run(['hash', 'sha1', 'x']);
  assert.equal(result.status, 2);
  assertNoStack(result);
});

test('CLI hash handles Unicode input as UTF-8', () => {
  const result = run(['hash', 'sha256', 'é']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.startsWith('sha256-'), true);
});

test('CLI hostile oversized input fails cleanly', () => {
  const result = run(['parse', 'script-src ' + 'x'.repeat(9000)]);
  assert.equal(result.status, 1);
  assertNoStack(result);
});
