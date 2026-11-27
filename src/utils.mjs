import { CSP_PARSE_BOUNDS, CSP_PARSE_HARD_LIMITS, CSPCAGE_ERROR_CODES, DANGEROUS_OBJECT_KEYS } from './constants.mjs';
import { CspCageError } from './errors.mjs';

export function deepFreeze(value, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item, seen);
    return value;
  }
  for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  return value;
}

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function byteLength(text) {
  return Buffer.byteLength(text, 'utf8');
}

export function truncateDetail(text, maxLength = 96) {
  const value = String(text);
  if (value.length <= maxLength) return value;
  return value.slice(0, maxLength - 3) + '...';
}

export function scanHeaderCharacters(text, policyIndex = 0) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 0x0d || code === 0x0a) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.HEADER_INJECTION, 'CR or LF header injection is forbidden', { policyIndex, characterIndex: index });
    }
    if (code === 0x00) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.CONTROL_CHARACTER, 'NUL bytes are forbidden', { policyIndex, characterIndex: index });
    }
    if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.CONTROL_CHARACTER, 'control characters are forbidden', { policyIndex, characterIndex: index });
    }
    if (code > 0x7e) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_ASCII, 'non-ASCII, Unicode format, bidi, and surrogate code units are forbidden', { policyIndex, characterIndex: index });
    }
  }
}

export function splitWhitespace(text) {
  return text.trim().split(/[ \t]+/u).filter((part) => part.length > 0);
}

function boundValue(options, name) {
  const value = options[name];
  if (value === undefined) return CSP_PARSE_BOUNDS[name];
  if (!Number.isSafeInteger(value) || value < 1 || value > CSP_PARSE_HARD_LIMITS[name]) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, name + ' must be an integer from 1 to ' + CSP_PARSE_HARD_LIMITS[name]);
  }
  return value;
}

export function resolveParseOptions(options = {}) {
  if (!isPlainObject(options)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'options must be a plain object');
  }
  for (const key of Object.keys(options)) {
    if (!(key in CSP_PARSE_BOUNDS) && key !== 'strict' && key !== 'maxFindings') {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'unknown option ' + truncateDetail(key, 40));
    }
  }
  return Object.freeze({
    maxBytes: boundValue(options, 'maxBytes'),
    maxPolicies: boundValue(options, 'maxPolicies'),
    maxDirectivesPerPolicy: boundValue(options, 'maxDirectivesPerPolicy'),
    maxTotalDirectives: boundValue(options, 'maxTotalDirectives'),
    maxSourcesPerDirective: boundValue(options, 'maxSourcesPerDirective'),
    maxSourceLength: boundValue(options, 'maxSourceLength'),
    maxFindings: boundValue(options, 'maxFindings'),
    strict: options.strict !== false
  });
}

export function assertSafeObjectKey(key) {
  const lower = String(key).toLowerCase();
  if (DANGEROUS_OBJECT_KEYS.includes(lower)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.PROTOTYPE_POLLUTION, 'dangerous object key is forbidden');
  }
}

export function hasDangerousObjectKey(value, depth = 0) {
  if (value === null || typeof value !== 'object' || depth > 8) return false;
  if (Array.isArray(value)) {
    return value.some((item) => hasDangerousObjectKey(item, depth + 1));
  }
  for (const key of Object.keys(value)) {
    if (DANGEROUS_OBJECT_KEYS.includes(key.toLowerCase())) return true;
    if (hasDangerousObjectKey(value[key], depth + 1)) return true;
  }
  return false;
}

export function decodeBase64Value(value) {
  if (typeof value !== 'string' || value.length < 4 || value.length > 1024) return null;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(value)) return null;
  if (value.includes('=') && value.length % 4 !== 0) return null;
  if (value.length % 4 === 1) return null;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  const unpadded = padding === 0 ? normalized : normalized.slice(0, -padding);
  const padded = unpadded + '='.repeat((4 - (unpadded.length % 4)) % 4);
  const decoded = Buffer.from(padded, 'base64');
  if (decoded.length === 0) return null;
  return decoded;
}

export function uniqueTokens(tokens) {
  const seen = new Set();
  const output = [];
  for (const token of tokens) {
    if (!seen.has(token)) {
      seen.add(token);
      output.push(token);
    }
  }
  return output;
}

export function compareTokenLists(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function normalizeAsciiToken(token, maxLength = 512) {
  if (typeof token !== 'string' || token.length === 0 || token.length > maxLength) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_INPUT, 'token must be a non-empty bounded string');
  }
  scanHeaderCharacters(token, 0);
  if (/[ \t]/u.test(token)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_INPUT, 'token must not contain whitespace');
  }
  return token;
}
