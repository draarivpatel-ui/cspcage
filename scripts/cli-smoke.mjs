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

assert.equal(run(['--version']).stdout, 'cspcage 1.0.0\n');
assert.equal(run(['parse', strictPolicy]).status, 0);
assert.equal(run(['parse', '-'], strictPolicy).status, 0);
assert.equal(run(['parse', "script-src 'self'; script-src 'none'"]).status, 1);
assert.equal(run(['audit', strictPolicy]).status, 0);
assert.equal(run(['audit', "script-src 'unsafe-inline'"]).status, 1);
assert.equal(run(['audit', '--json', strictPolicy]).status, 0);
assert.equal(JSON.parse(run(['audit', '--json', strictPolicy]).stdout).grade, 'A+');
assert.equal(run(['build', strictBuild]).status, 0);
assert.equal(run(['build', strictBuild]).stdout, strictPolicy + '\n');
assert.equal(run(['nonce', '16']).status, 0);
assert.match(run(['nonce', '16']).stdout.trim(), /^[A-Za-z0-9+/]+={0,2}$/);
assert.equal(run(['hash', 'sha256', 'x']).stdout, 'sha256-LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=\n');
assert.equal(run(['hash', 'sha256', '-'], 'x').status, 0);
assert.equal(run(['audit', 'script-src *\r\n']).status, 1);
assert.equal(run(['does-not-exist']).status, 2);
process.stdout.write('cspcage CLI smoke passed\n');
