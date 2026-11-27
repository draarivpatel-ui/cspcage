import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const esm = await import(pathToFileURL(path.join(root, 'src', 'index.mjs')).href);
const cjs = require(path.join(root, 'dist', 'cjs', 'index.cjs'));

const exportNames = [
  'CODE',
  'CSP_DIRECTIVES',
  'CSP_KEYWORDS',
  'CSP_PARSE_BOUNDS',
  'CSP_PARSE_HARD_LIMITS',
  'CSPCAGE_ERROR_CODES',
  'CSPCAGE_SEVERITY',
  'CSPCAGE_VERSION',
  'DEPRECATED_DIRECTIVES',
  'FETCH_DIRECTIVES',
  'HASH_ALGORITHMS',
  'SCRIPT_GADGET_HOSTS',
  'SOURCE_LIST_DIRECTIVES',
  'CspCageError',
  'isCspCageError',
  'parseCsp',
  'auditCsp',
  'isSafeCsp',
  'buildCsp',
  'createStrictCsp',
  'computeHash',
  'generateNonce',
  'diffCsp',
  'intersectCsp',
  'mergeCsp'
];

for (const name of exportNames) {
  test('CJS exposes ESM export: ' + name, () => {
    assert.notEqual(esm[name], undefined);
    assert.notEqual(cjs[name], undefined);
    assert.equal(typeof cjs[name], typeof esm[name]);
  });
}

test('ESM default export exists', () => {
  assert.equal(typeof esm.default, 'object');
  assert.equal(esm.default.CSPCAGE_VERSION, esm.CSPCAGE_VERSION);
});

test('CJS default export object exists', () => {
  assert.equal(typeof cjs.default, 'object');
  assert.equal(cjs.default.CSPCAGE_VERSION, esm.CSPCAGE_VERSION);
});

function json(value) {
  return JSON.parse(JSON.stringify(value));
}

const parityPolicies = [
  "default-src 'self'",
  "script-src 'none'; object-src 'none'",
  "script-src 'self' https://cdn.example.com/app.js",
  "script-src 'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng=='",
  "img-src *",
  'sandbox allow-scripts',
  "require-trusted-types-for 'script'",
  'report-uri /csp',
  "frame-ancestors 'self'",
  "default-src 'self', script-src 'none'"
];

for (const policy of parityPolicies) {
  test('CJS and ESM parse parity: ' + policy.slice(0, 45), () => {
    assert.deepEqual(json(cjs.parseCsp(policy)), json(esm.parseCsp(policy)));
  });
}

for (const policy of parityPolicies) {
  test('CJS and ESM audit parity: ' + policy.slice(0, 45), () => {
    assert.deepEqual(json(cjs.auditCsp(policy)), json(esm.auditCsp(policy)));
  });
}

const parityBuildInputs = [
  { scriptSrc: ["'self'"] },
  { defaultSrc: ["'none'"], scriptSrc: ["'none'"], objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"] },
  { sandbox: true },
  { upgradeInsecureRequests: true },
  { reportTo: 'csp-endpoint' }
];

for (const [index, input] of parityBuildInputs.entries()) {
  test('CJS and ESM builder parity ' + index, () => {
    assert.equal(cjs.buildCsp(input), esm.buildCsp(input));
  });
}

for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  test('CJS and ESM hash parity: ' + algorithm, () => {
    assert.equal(cjs.computeHash('x', algorithm), esm.computeHash('x', algorithm));
  });
}

test('CJS and ESM nonce contract parity', () => {
  assert.equal(Buffer.from(cjs.generateNonce(), 'base64').length, 16);
  assert.equal(Buffer.from(esm.generateNonce(), 'base64').length, 16);
});

test('CJS and ESM strict preset parity with fixed nonce', () => {
  const nonce = 'MTIzNDU2Nzg5MDEyMzQ1Ng==';
  assert.equal(cjs.createStrictCsp({ nonce }), esm.createStrictCsp({ nonce }));
});

test('CJS and ESM merge parity', () => {
  const inputs = ["script-src 'self'", 'script-src https://cdn.example.com/app.js'];
  assert.equal(cjs.mergeCsp(inputs), esm.mergeCsp(inputs));
});

test('CJS and ESM intersection parity', () => {
  const inputs = ["script-src 'self' https://a.example.com", "script-src 'self'"];
  assert.equal(cjs.intersectCsp(inputs), esm.intersectCsp(inputs));
});

test('CJS and ESM diff parity', () => {
  assert.deepEqual(json(cjs.diffCsp("script-src 'self'", "script-src 'none'")), json(esm.diffCsp("script-src 'self'", "script-src 'none'")));
});

test('CJS and ESM typed error parity', () => {
  assert.throws(() => cjs.parseCsp("script-src 'self'; script-src 'none'"), (error) => error instanceof cjs.CspCageError && error.code === cjs.CODE.DUPLICATE_DIRECTIVE);
  assert.throws(() => esm.parseCsp("script-src 'self'; script-src 'none'"), (error) => error instanceof esm.CspCageError && error.code === esm.CODE.DUPLICATE_DIRECTIVE);
});

function repoFiles(directory = root, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) repoFiles(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

test('repository contains no em dash or en dash bytes', () => {
  const offenders = [];
  for (const file of repoFiles()) {
    const bytes = fs.readFileSync(file);
    if (bytes.includes(Buffer.from([0xe2, 0x80, 0x94])) || bytes.includes(Buffer.from([0xe2, 0x80, 0x93]))) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no local user filesystem paths', () => {
  const needle = Buffer.from('/' + 'Users' + '/');
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file).includes(needle)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no email address literals', () => {
  const offenders = [];
  const pattern = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/u;
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    const matches = [...text.matchAll(new RegExp(pattern.source, 'gu'))].map((match) => match[0].toLowerCase());
    const disallowed = matches.filter((value) => {
      const domain = value.split('@')[1] || '';
      return domain !== 'example.com' && !domain.endsWith('.example.com');
    });
    if (disallowed.length > 0) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository contains no coauthor trailer marker', () => {
  const needle = 'Co-' + 'Authored-' + 'By';
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file, 'utf8').includes(needle)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('repository text files use LF line endings', () => {
  const offenders = [];
  for (const file of repoFiles()) {
    if (fs.readFileSync(file).includes(0x0d)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no vendor shaped credential placeholders are present', () => {
  const offenders = [];
  const patterns = [
    /tskey-[A-Za-z0-9_-]/u,
    /sk-[A-Za-z0-9]/u,
    /ghp_[A-Za-z0-9]/u,
    /github_pat_[A-Za-z0-9_]/u,
    /AKIA[A-Z0-9]/u,
    /xox[baprs]-[A-Za-z0-9-]/u,
    /AIza[A-Za-z0-9_-]/u
  ];
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const pattern of patterns) if (pattern.test(text)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('package identity and version are correct', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'cspcage');
  assert.equal(pkg.version, '1.0.0');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.license, 'MIT');
});

test('package has zero runtime and development dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
});

test('package exports dual ESM and CJS entry points', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './dist/cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
  assert.equal(pkg.main, './dist/cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
});

test('package repository points to the intended public repository', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.repository.url, 'https://github.com/draarivpatel-ui/cspcage');
});

test('package engine requires Node 18 or newer', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.engines.node, '>=18.0.0');
});

test('package files include runtime and exclude development directories', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const item of ['bin', 'src', 'dist/cjs', 'types', 'examples']) assert.equal(pkg.files.includes(item), true, item);
  for (const item of ['test', 'scripts', '.github']) assert.equal(pkg.files.includes(item), false, item);
});

test('generated CJS file exists and is marked generated', () => {
  const text = fs.readFileSync(path.join(root, 'dist', 'cjs', 'index.cjs'), 'utf8');
  assert.equal(text.includes('Generated by scripts/build-cjs.mjs'), true);
  assert.equal(text.includes('module.exports'), true);
});

test('generated CJS uses LF line endings', () => {
  const text = fs.readFileSync(path.join(root, 'dist', 'cjs', 'index.cjs'), 'utf8');
  assert.equal(text.includes('\r'), false);
});

test('CI uses ubuntu-latest and windows-latest across four Node versions', () => {
  const text = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.equal(text.includes('os: [ubuntu-latest, windows-latest]'), true);
  assert.equal(text.includes('node: [18, 20, 22, 24]'), true);
});

for (const command of ['npm test', 'node scripts/build-cjs.mjs --check', 'node scripts/check-types.mjs', 'node scripts/cli-smoke.mjs', 'npm pack --dry-run', 'node scripts/check-pack.mjs']) {
  test('CI runs required command: ' + command, () => {
    const text = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
    assert.equal(text.includes(command), true);
  });
}

test('CI runs examples', () => {
  const text = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.equal(text.includes('for example in examples/*.mjs'), true);
});

test('TypeScript declaration has no any type', () => {
  const text = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  assert.equal(/\bany\b/u.test(text), false);
});

for (const name of ['parseCsp', 'auditCsp', 'buildCsp', 'generateNonce', 'computeHash', 'mergeCsp', 'intersectCsp', 'diffCsp', 'createStrictCsp', 'isSafeCsp']) {
  test('TypeScript declaration declares ' + name, () => {
    const text = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
    assert.equal(text.includes('function ' + name + '('), true);
  });
}

for (const file of ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'LICENSE']) {
  test('required repository document exists: ' + file, () => {
    const full = path.join(root, file);
    assert.equal(fs.statSync(full).isFile(), true);
    assert.equal(fs.statSync(full).size > 0, true);
  });
}

for (const file of ['audit-policy.mjs', 'build-strict-policy.mjs', 'merge-and-diff.mjs']) {
  test('runnable example exists: ' + file, () => {
    const full = path.join(root, 'examples', file);
    assert.equal(fs.statSync(full).isFile(), true);
    assert.equal(fs.readFileSync(full, 'utf8').includes('../src/index.mjs'), true);
  });
}

test('license is MIT', () => {
  const text = fs.readFileSync(path.join(root, 'LICENSE'), 'utf8');
  assert.equal(text.includes('MIT License'), true);
});

test('README documents parser bounds', () => {
  const text = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.equal(text.includes('Header bytes'), true);
  assert.equal(text.includes('8192'), true);
});

test('README documents script gadget and XSS audit coverage', () => {
  const text = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.equal(text.includes('JSONP'), true);
  assert.equal(text.includes('script-gadget'), true);
  assert.equal(text.includes('unsafe-inline'), true);
});

test('README documents merge protections', () => {
  const text = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.equal(text.includes('allowNoneWidening'), true);
  assert.equal(text.includes('allowUnsafeInline'), true);
});

test('bin file has executable shebang', () => {
  const text = fs.readFileSync(path.join(root, 'bin', 'cspcage.mjs'), 'utf8');
  assert.equal(text.startsWith('#!/usr/bin/env node'), true);
});

test('bin file is executable on disk where executable modes exist', () => {
  if (process.platform === 'win32') return;
  const mode = fs.statSync(path.join(root, 'bin', 'cspcage.mjs')).mode;
  assert.notEqual(mode & 0o111, 0);
});

test('repository scripts exist', () => {
  for (const file of ['build-cjs.mjs', 'check-types.mjs', 'cli-smoke.mjs', 'check-pack.mjs', 'run-tests.mjs']) {
    assert.equal(fs.statSync(path.join(root, 'scripts', file)).isFile(), true, file);
  }
});

test('git attributes enforce LF normalization', () => {
  const text = fs.readFileSync(path.join(root, '.gitattributes'), 'utf8');
  assert.equal(text.includes('eol=lf'), true);
});

test('gitignore excludes generated local artifacts', () => {
  const text = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
  for (const item of ['node_modules/', '*.tgz', 'coverage/']) assert.equal(text.includes(item), true, item);
});

test('no package lock or node_modules is required for zero dependency runtime', () => {
  assert.equal(fs.existsSync(path.join(root, 'node_modules')), false);
});

test('source files have no runtime dependency imports outside node builtins and local modules', () => {
  const offenders = [];
  for (const file of fs.readdirSync(path.join(root, 'src')).filter((name) => name.endsWith('.mjs'))) {
    const text = fs.readFileSync(path.join(root, 'src', file), 'utf8');
    for (const match of text.matchAll(/^import\s*\{[^}]+\}\s*from\s*['"]([^'"]+)['"];$/gmu)) {
      if (!match[1].startsWith('./') && !match[1].startsWith('node:')) offenders.push(file + ':' + match[1]);
    }
  }
  assert.deepEqual(offenders, []);
});
