import assert from 'node:assert/strict';

export function codes(report) {
  return report.findings.map((finding) => finding.code);
}

export function hasCode(report, code) {
  return codes(report).includes(code);
}

export function assertHasCode(report, code) {
  assert.equal(hasCode(report, code), true, 'expected ' + code + ' in ' + codes(report).join(','));
}

export function assertNoCode(report, code) {
  assert.equal(hasCode(report, code), false, 'did not expect ' + code);
}

export function assertFrozenDeep(value) {
  if (value === null || typeof value !== 'object') return;
  assert.equal(Object.isFrozen(value), true);
  if (Array.isArray(value)) {
    for (const item of value) assertFrozenDeep(item);
    return;
  }
  for (const key of Object.keys(value)) assertFrozenDeep(value[key]);
}

export function validHashSource(computeHash, content, algorithm) {
  return "'" + computeHash(content, algorithm) + "'";
}
