import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { CODE, CspCageError, parseCsp } from '../src/index.mjs';

const labelUnit = fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz');
const hostLabel = fc.string({ unit: labelUnit, minLength: 1, maxLength: 10 });
const controlCharacter = fc.constantFrom('\0', '\r', '\n', '\x1b', '\x7f');
const fuzzOptions = { seed: 20261127, numRuns: 110 };

function validPolicy(label) {
  return "default-src 'none'; script-src 'self'; img-src https://" + label + '.example.com';
}

test('fast-check generated bounded safe policies parse as valid', () => {
  fc.assert(fc.property(hostLabel, (label) => {
    const parsed = parseCsp(validPolicy(label));
    assert.equal(parsed.valid, true);
    assert.equal(parsed.directiveCount, 3);
    const directives = parsed.policies[0].directiveMap;
    assert.equal(directives['default-src'].tokens.includes("'none'"), true);
    assert.equal(directives['img-src'].tokens.includes('https://' + label + '.example.com'), true);
  }), fuzzOptions);
});

test('fast-check header control injection is always rejected', () => {
  fc.assert(fc.property(hostLabel, controlCharacter, fc.integer({ min: 0, max: 24 }), (label, control, index) => {
    const policy = validPolicy(label);
    const at = index % (policy.length + 1);
    const hostile = policy.slice(0, at) + control + policy.slice(at);
    assert.throws(
      () => parseCsp(hostile),
      (error) => error instanceof CspCageError && (error.code === CODE.CONTROL_CHARACTER || error.code === CODE.HEADER_INJECTION)
    );
  }), fuzzOptions);
});

test('fast-check duplicate directives fail closed in strict mode', () => {
  fc.assert(fc.property(fc.constantFrom('script-src', 'img-src', 'default-src'), (directive) => {
    assert.throws(
      () => parseCsp(directive + " 'self'; " + directive + " 'none'"),
      (error) => error instanceof CspCageError && error.code === CODE.DUPLICATE_DIRECTIVE
    );
  }), fuzzOptions);
});
