#!/usr/bin/env node

import fs from 'node:fs';
import {
  CSPCAGE_VERSION,
  auditCsp,
  buildCsp,
  computeHash,
  generateNonce,
  parseCsp
} from '../src/index.mjs';

function usage() {
  return [
    'cspcage ' + CSPCAGE_VERSION,
    '',
    'Usage:',
    '  cspcage parse <policy|-> [--json] [--strict]',
    '  cspcage audit <policy|-> [--json] [--strict]',
    '  cspcage build <json-directives|-> [--json] [--strict]',
    '  cspcage nonce [bytes] [--json]',
    '  cspcage hash <sha256|sha384|sha512> [content|-] [--json]',
    '',
    'Exit codes: 0 pass, 1 blocked or invalid policy, 2 usage or input error.'
  ].join('\n') + '\n';
}

function parseFlags(args, allowed) {
  const flags = new Set();
  const positionals = [];
  for (const arg of args) {
    if (arg.startsWith('--')) {
      if (!allowed.has(arg)) throw new Error('unknown option ' + arg);
      flags.add(arg);
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals };
}

function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function inputText(positionals, label) {
  if (positionals.length > 1) throw new Error('too many ' + label + ' arguments');
  const value = positionals.length === 0 || positionals[0] === '-' ? readStdin() : positionals[0];
  if (typeof value !== 'string' || value.length === 0) throw new Error('missing ' + label);
  return value;
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function findingLine(finding) {
  const directive = finding.directive === null ? '-' : finding.directive;
  const policy = finding.policyIndex === null ? '-' : String(finding.policyIndex);
  return finding.severity + ' ' + finding.code + ' policy=' + policy + ' directive=' + directive + ' - ' + finding.message;
}

function run(argv) {
  const args = argv.slice(2);
  const command = args.shift();
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(usage());
    return command === undefined ? 2 : 0;
  }
  if (command === '--version' || command === '-v' || command === 'version') {
    process.stdout.write('cspcage ' + CSPCAGE_VERSION + '\n');
    return 0;
  }

  if (command === 'parse') {
    const { flags, positionals } = parseFlags(args, new Set(['--json', '--strict']));
    const input = inputText(positionals, 'policy');
    try {
      const parsed = parseCsp(input, { strict: true });
      if (flags.has('--json')) {
        printJson(parsed);
      } else {
        process.stdout.write('valid=true policies=' + parsed.policyCount + ' directives=' + parsed.directiveCount + ' sources=' + parsed.sourceExpressionCount + '\n');
      }
      return 0;
    } catch (error) {
      process.stderr.write('cspcage: ' + error.message + '\n');
      return 1;
    }
  }

  if (command === 'audit') {
    const { flags, positionals } = parseFlags(args, new Set(['--json', '--strict']));
    const input = inputText(positionals, 'policy');
    const report = auditCsp(input, { strict: flags.has('--strict') });
    if (flags.has('--json')) {
      printJson(report);
    } else {
      process.stdout.write('safe=' + report.safe + ' grade=' + report.grade + ' score=' + report.score + ' errors=' + report.counts.errors + ' warnings=' + report.counts.warnings + '\n');
      for (const finding of report.findings) process.stdout.write(findingLine(finding) + '\n');
    }
    return report.safe ? 0 : 1;
  }

  if (command === 'build') {
    const { flags, positionals } = parseFlags(args, new Set(['--json', '--strict']));
    const input = inputText(positionals, 'JSON directives');
    let directives;
    try {
      directives = JSON.parse(input);
    } catch {
      process.stderr.write('cspcage: build input must be valid JSON\n');
      return 2;
    }
    try {
      const header = buildCsp(directives, { requireCleanAudit: flags.has('--strict') });
      if (flags.has('--json')) printJson({ header, audit: auditCsp(header) });
      else process.stdout.write(header + '\n');
      return 0;
    } catch (error) {
      process.stderr.write('cspcage: ' + error.message + '\n');
      return 1;
    }
  }

  if (command === 'nonce') {
    const { flags, positionals } = parseFlags(args, new Set(['--json']));
    if (positionals.length > 1) throw new Error('too many nonce arguments');
    let bytes = 16;
    if (positionals.length === 1) {
      if (!/^[0-9]+$/u.test(positionals[0])) throw new Error('nonce byte count must be a positive integer');
      bytes = Number(positionals[0]);
    }
    const nonce = generateNonce(bytes);
    if (flags.has('--json')) printJson({ nonce, bytes });
    else process.stdout.write(nonce + '\n');
    return 0;
  }

  if (command === 'hash') {
    const { flags, positionals } = parseFlags(args, new Set(['--json']));
    if (positionals.length === 0) throw new Error('missing hash algorithm');
    const algorithm = positionals[0];
    const content = positionals.length === 1 || positionals[1] === '-' ? readStdin() : positionals[1];
    if (positionals.length > 2) throw new Error('too many hash arguments');
    const hash = computeHash(content, algorithm);
    if (flags.has('--json')) printJson({ algorithm, hash });
    else process.stdout.write(hash + '\n');
    return 0;
  }

  throw new Error('unknown command ' + command);
}

try {
  const status = run(process.argv);
  process.exitCode = status;
} catch (error) {
  const message = error instanceof Error ? error.message : 'invalid input';
  process.stderr.write('cspcage: ' + message + '\n');
  process.stderr.write('Run cspcage --help for usage.\n');
  process.exitCode = 2;
}
