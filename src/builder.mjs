import {
  CSP_DIRECTIVE_ORDER,
  CSP_DIRECTIVES,
  CSPCAGE_ERROR_CODES,
  DANGEROUS_OBJECT_KEYS,
  DEPRECATED_DIRECTIVES,
  SOURCE_LIST_DIRECTIVES
} from './constants.mjs';
import { auditCsp } from './auditor.mjs';
import { CspCageError } from './errors.mjs';
import { generateNonce } from './crypto.mjs';
import { parseCsp } from './parser.mjs';
import { isPlainObject, scanHeaderCharacters, splitWhitespace, truncateDetail, uniqueTokens } from './utils.mjs';

function normalizeDirectiveName(key) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 80) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'directive keys must be bounded strings');
  }
  scanHeaderCharacters(key, 0);
  if (/\s/u.test(key)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'directive keys must not contain whitespace');
  }
  const lowerRaw = key.toLowerCase();
  if (DANGEROUS_OBJECT_KEYS.includes(lowerRaw)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.PROTOTYPE_POLLUTION, 'prototype-pollution directive keys are forbidden');
  }
  const name = key.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replace(/_/g, '-').toLowerCase();
  if (DANGEROUS_OBJECT_KEYS.includes(name)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.PROTOTYPE_POLLUTION, 'prototype-pollution directive keys are forbidden');
  }
  if (!/^[a-z][a-z0-9-]{0,63}$/u.test(name) || name.startsWith('-') || name.endsWith('-') || name.includes('--')) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_DIRECTIVE_NAME, 'directive key is malformed: ' + truncateDetail(key, 40));
  }
  if (DEPRECATED_DIRECTIVES.includes(name)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.DEPRECATED_DIRECTIVE, 'deprecated directive is forbidden: ' + name);
  }
  if (!CSP_DIRECTIVES.includes(name)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.UNKNOWN_DIRECTIVE, 'unknown directive is forbidden: ' + name);
  }
  return name;
}

function assertSafeToken(token, directiveName) {
  if (typeof token !== 'string' || token.length === 0 || token.length > 512) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'tokens for ' + directiveName + ' must be non-empty bounded strings');
  }
  scanHeaderCharacters(token, 0);
  if (/[;,\s\\]/u.test(token)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'token for ' + directiveName + ' contains whitespace, semicolon, comma, or backslash injection');
  }
  return token;
}

function valueTokens(value, directiveName) {
  if (value === undefined) return null;
  if (typeof value === 'boolean') {
    if (!value) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'boolean false is ambiguous for ' + directiveName + '; omit the directive instead');
    }
    return [];
  }
  let rawTokens;
  if (typeof value === 'string') {
    scanHeaderCharacters(value, 0);
    if (/[;,\\]/u.test(value)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'directive value for ' + directiveName + ' contains semicolon, comma, or backslash injection');
    }
    rawTokens = splitWhitespace(value);
  } else if (Array.isArray(value)) {
    rawTokens = value.slice();
  } else {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'directive value for ' + directiveName + ' must be a string, array, or true');
  }
  if (rawTokens.length > 64) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'too many tokens for ' + directiveName);
  }
  return uniqueTokens(rawTokens.map((token) => assertSafeToken(token, directiveName)));
}

function normalizeBuildOptions(options) {
  if (options === undefined) return Object.freeze({ requireCleanAudit: false, allowUnsafeInline: false });
  if (!isPlainObject(options)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'build options must be a plain object');
  }
  for (const key of Object.keys(options)) {
    if (key !== 'requireCleanAudit' && key !== 'allowUnsafeInline') {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'unknown build option ' + truncateDetail(key, 40));
    }
  }
  return Object.freeze({ requireCleanAudit: options.requireCleanAudit === true, allowUnsafeInline: options.allowUnsafeInline === true });
}

export function normalizeDirectiveInput(input) {
  if (!isPlainObject(input)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'directives must be supplied as a plain object');
  }
  const normalized = new Map();
  for (const key of Object.keys(input)) {
    const name = normalizeDirectiveName(key);
    if (normalized.has(name)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.DUPLICATE_DIRECTIVE, 'duplicate directive after key normalization: ' + name);
    }
    const tokens = valueTokens(input[key], name);
    if (tokens === null) continue;
    if (name === 'upgrade-insecure-requests' && tokens.length !== 0) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.UNEXPECTED_DIRECTIVE_VALUE, 'upgrade-insecure-requests does not accept tokens');
    }
    if (SOURCE_LIST_DIRECTIVES.includes(name) && tokens.length === 0) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.MISSING_DIRECTIVE_VALUE, name + ' requires at least one token');
    }
    normalized.set(name, tokens);
  }
  if (normalized.size === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_BUILD_INPUT, 'at least one directive is required');
  }
  return normalized;
}

function orderedNames(map) {
  const known = CSP_DIRECTIVE_ORDER.filter((name) => map.has(name));
  const unknown = [...map.keys()].filter((name) => !CSP_DIRECTIVE_ORDER.includes(name)).sort();
  return known.concat(unknown);
}

function serializeDirectiveMap(map) {
  return orderedNames(map).map((name) => {
    const tokens = map.get(name);
    return tokens.length === 0 ? name : name + ' ' + tokens.join(' ');
  }).join('; ');
}

export function buildCsp(directives, options = undefined) {
  const buildOptions = normalizeBuildOptions(options);
  const normalized = normalizeDirectiveInput(directives);
  const serialized = serializeDirectiveMap(normalized);
  parseCsp(serialized);
  const audit = auditCsp(serialized);
  const blockingErrors = audit.findings.filter((finding) => finding.severity === 'error' && finding.code !== 'MISSING_SCRIPT_POLICY' && !(buildOptions.allowUnsafeInline && finding.code === 'UNSAFE_INLINE_ACTIVE')).length;
  if (blockingErrors > 0 || (buildOptions.requireCleanAudit && audit.counts.warnings > 0)) {
    const error = new CspCageError(CSPCAGE_ERROR_CODES.UNSAFE_BUILD_OUTPUT, 'serialized CSP did not pass the security audit');
    error.audit = audit;
    throw error;
  }
  return serialized;
}

function normalizeNonceToken(nonce) {
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 256) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_NONCE_INPUT, 'nonce must be a bounded base64 string');
  }
  scanHeaderCharacters(nonce, 0);
  let value = nonce;
  if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);
  if (value.toLowerCase().startsWith('nonce-')) value = value.slice(6);
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(value)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_NONCE_INPUT, 'nonce must use strict base64 characters');
  }
  return value;
}

function strictArray(value, fallback, name) {
  if (value === undefined) return fallback.slice();
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, name + ' must be a non-empty bounded array');
  }
  return value.slice();
}

export function createStrictCsp(options = {}) {
  if (!isPlainObject(options)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'strict CSP options must be a plain object');
  }
  const allowed = new Set(['nonce', 'reportTo', 'reportUri', 'connectSrc', 'imgSrc', 'styleSrc', 'fontSrc', 'mediaSrc', 'workerSrc', 'frameAncestors', 'formAction', 'upgradeInsecureRequests', 'requireTrustedTypesFor']);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'unknown strict CSP option ' + truncateDetail(key, 40));
    }
  }
  const nonce = normalizeNonceToken(options.nonce === undefined ? generateNonce() : options.nonce);
  const directives = {
    defaultSrc: ["'self'"],
    scriptSrc: ["'nonce-" + nonce + "'", "'strict-dynamic'"],
    styleSrc: strictArray(options.styleSrc, ["'self'"], 'styleSrc'),
    imgSrc: strictArray(options.imgSrc, ["'self'", 'data:'], 'imgSrc'),
    fontSrc: strictArray(options.fontSrc, ["'self'"], 'fontSrc'),
    connectSrc: strictArray(options.connectSrc, ["'self'"], 'connectSrc'),
    mediaSrc: strictArray(options.mediaSrc, ["'self'"], 'mediaSrc'),
    workerSrc: strictArray(options.workerSrc, ["'self'"], 'workerSrc'),
    objectSrc: ["'none'"],
    baseUri: ["'none'"],
    frameAncestors: strictArray(options.frameAncestors, ["'none'"], 'frameAncestors'),
    formAction: strictArray(options.formAction, ["'self'"], 'formAction'),
    manifestSrc: ["'self'"]
  };
  if (options.upgradeInsecureRequests !== false) directives.upgradeInsecureRequests = true;
  if (options.requireTrustedTypesFor === true) directives.requireTrustedTypesFor = "'script'";
  if (typeof options.reportTo === 'string' && options.reportTo.length > 0) directives.reportTo = options.reportTo;
  if (typeof options.reportUri === 'string' && options.reportUri.length > 0) directives.reportUri = options.reportUri;
  return buildCsp(directives, { requireCleanAudit: options.reportUri === undefined });
}
