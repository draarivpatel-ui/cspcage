import {
  CSP_DIRECTIVES,
  CSP_KEYWORDS,
  CSP_PARSE_BOUNDS,
  DEPRECATED_DIRECTIVES,
  HASH_DIGEST_BYTES,
  SANDBOX_TOKENS,
  SOURCE_LIST_DIRECTIVES,
  CSPCAGE_ERROR_CODES
} from './constants.mjs';
import { isIPv6 } from 'node:net';
import { CspCageError } from './errors.mjs';
import { byteLength, deepFreeze, decodeBase64Value, resolveParseOptions, scanHeaderCharacters, splitWhitespace, truncateDetail } from './utils.mjs';

function errorDetail(token) {
  return truncateDetail(token, 80);
}

function toError(value) {
  if (value instanceof CspCageError) return value;
  return new CspCageError(CSPCAGE_ERROR_CODES.INVALID_INPUT, 'unexpected parser failure');
}

function recordError(errors, error, bounds) {
  if (errors.length < bounds.maxFindings) errors.push(toError(error));
}

function normalizeInput(input) {
  if (typeof input === 'string') return [input];
  if (Array.isArray(input) && input.length > 0 && input.every((item) => typeof item === 'string')) return input.slice();
  throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_INPUT, 'CSP input must be a string or a non-empty array of strings');
}

function splitPolicyUnits(headers) {
  const pieces = [];
  for (const header of headers) {
    const parts = header.split(',');
    for (const part of parts) pieces.push(part);
  }
  return pieces;
}

function validateScheme(scheme) {
  return /^[A-Za-z][A-Za-z0-9+.-]{0,31}$/u.test(scheme);
}

function validPort(text) {
  if (text === '*') return '*';
  if (!/^[0-9]{1,5}$/u.test(text)) return null;
  const port = Number(text);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) return null;
  return port;
}

function validateIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/u.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    if (Number(part) > 255) return false;
  }
  return true;
}

function validateDnsName(host) {
  const canonical = host.endsWith('.') ? host.slice(0, -1) : host;
  if (canonical.length === 0 || canonical.length > 253) return false;
  const labels = canonical.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false;
    if (!/^[A-Za-z0-9-]+$/u.test(label)) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
  }
  return true;
}

function validateIpv6(host) {
  return isIPv6(host);
}

function parseHostAndPort(hostPort) {
  if (hostPort.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host source is missing a host');
  }
  let host = hostPort;
  let port = null;
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    if (close < 0) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'IPv6 host is missing a closing bracket');
    }
    host = hostPort.slice(1, close);
    if (!validateIpv6(host)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'IPv6 host is malformed');
    }
    const rest = hostPort.slice(close + 1);
    if (rest.length > 0) {
      if (!rest.startsWith(':')) {
        throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'unexpected data after IPv6 host');
      }
      port = validPort(rest.slice(1));
      if (port === null) {
        throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'port must be an integer from 0 to 65535');
      }
    }
    return { host: host.toLowerCase(), port, ipv6: true, wildcard: false };
  }

  const colonCount = hostPort.split(':').length - 1;
  if (colonCount > 1) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'IPv6 hosts must use brackets');
  }
  if (colonCount === 1) {
    const pieces = hostPort.split(':');
    host = pieces[0];
    port = validPort(pieces[1]);
    if (port === null) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'port must be an integer from 0 to 65535');
    }
  }
  if (host.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host source is missing a host');
  }
  if (host === '*') return { host: '*', port, ipv6: false, wildcard: true };
  let wildcard = false;
  let dnsHost = host;
  if (host.startsWith('*.')) {
    wildcard = true;
    dnsHost = host.slice(2);
  } else if (host.includes('*')) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'wildcard is only valid as a complete left-most host label');
  }
  if (/^[0-9.]+$/u.test(dnsHost)) {
    if (!validateIpv4(dnsHost)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'IPv4 host is malformed');
    }
  } else if (!validateDnsName(dnsHost)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host name is malformed');
  }
  return { host: host.toLowerCase(), port, ipv6: false, wildcard };
}

function validatePath(path) {
  if (path.length > 512) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'source path is too long');
  }
  if (/[?#\\<>"'`;,\s]/u.test(path)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'source path contains forbidden characters');
  }
  for (let index = 0; index < path.length; index += 1) {
    if (path[index] === '%') {
      if (!/^[0-9A-Fa-f]{2}$/u.test(path.slice(index + 1, index + 3))) {
        throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'source path contains malformed percent encoding');
      }
      index += 2;
    }
  }
}

function parseHostSource(token) {
  if (/["'`;,\s\\<>?#]/u.test(token)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host source contains forbidden characters: ' + errorDetail(token));
  }
  let rest = token;
  let scheme = null;
  const schemeSplit = rest.indexOf('://');
  if (schemeSplit >= 0) {
    scheme = rest.slice(0, schemeSplit);
    if (!validateScheme(scheme)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host source scheme is malformed');
    }
    rest = rest.slice(schemeSplit + 3);
  }
  if (rest.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HOST_SOURCE, 'host source is missing a host');
  }
  const slash = rest.indexOf('/');
  const hostPort = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? null : rest.slice(slash);
  if (path !== null) validatePath(path);
  const parsed = parseHostAndPort(hostPort);
  return Object.freeze({
    kind: 'host',
    raw: token,
    scheme: scheme === null ? null : scheme.toLowerCase(),
    host: parsed.host,
    hostIsWildcard: parsed.wildcard,
    port: parsed.port,
    path,
    ipv6: parsed.ipv6,
    hasExactPath: path !== null && path.length > 1 && !path.endsWith('/')
  });
}

function parseKeywordOrQuotedSource(token) {
  const lower = token.toLowerCase();
  if (!token.startsWith("'") || !token.endsWith("'") || token.length < 2) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_KEYWORD, 'quoted source expression has malformed quotes');
  }
  for (const keyword of CSP_KEYWORDS) {
    if (lower === "'" + keyword + "'") {
      return Object.freeze({ kind: 'keyword', raw: token, keyword });
    }
  }
  if (lower.startsWith("'nonce-")) {
    const nonce = token.slice(7, -1);
    const decoded = decodeBase64Value(nonce);
    if (decoded === null) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_NONCE, 'nonce value is not strict base64');
    }
    return Object.freeze({ kind: 'nonce', raw: token, nonce, decodedBytes: decoded.length });
  }
  if (/^'(?:sha1|md5)-/u.test(lower)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.UNSUPPORTED_HASH_ALGORITHM, 'only sha256, sha384, and sha512 CSP hashes are accepted');
  }
  const hashMatch = /^'(sha256|sha384|sha512)-/u.exec(lower);
  if (hashMatch !== null) {
    const algorithm = hashMatch[1];
    const digest = token.slice(algorithm.length + 2, -1);
    const decoded = decodeBase64Value(digest);
    if (decoded === null || decoded.length !== HASH_DIGEST_BYTES[algorithm]) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_HASH, algorithm + ' digest is malformed or has the wrong length');
    }
    return Object.freeze({ kind: 'hash', raw: token, algorithm, digest, digestBytes: decoded.length });
  }
  if (lower.startsWith("'nonce")) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_NONCE, 'nonce source is malformed');
  }
  if (lower.startsWith("'sha")) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_HASH, 'hash source is malformed');
  }
  throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_KEYWORD, 'unknown quoted source expression: ' + errorDetail(token));
}

export function parseSourceExpression(token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.MALFORMED_SOURCE, 'source expression must be a non-empty string');
  }
  if (token === '*') {
    return Object.freeze({ kind: 'wildcard', raw: token });
  }
  if (token.includes("'")) return parseKeywordOrQuotedSource(token);
  if (/^[A-Za-z][A-Za-z0-9+.-]{0,31}:$/u.test(token)) {
    return Object.freeze({ kind: 'scheme', raw: token, scheme: token.slice(0, -1).toLowerCase() });
  }
  return parseHostSource(token);
}

function validateReportEndpointToken(token) {
  if (token.length === 0 || token.length > 1024) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_REPORT_ENDPOINT, 'report endpoint length is invalid');
  }
  if (/["'`;\s\\<>]/u.test(token)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_REPORT_ENDPOINT, 'report endpoint contains forbidden characters');
  }
}

function validateDirectiveValue(name, tokens, policyIndex, directiveIndex, errors, bounds) {
  if (SOURCE_LIST_DIRECTIVES.includes(name)) {
    if (tokens.length === 0) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.MISSING_DIRECTIVE_VALUE, name + ' requires at least one source expression', { policyIndex, directiveIndex }), bounds);
      return [];
    }
    if (tokens.length > bounds.maxSourcesPerDirective) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.TOO_MANY_SOURCES, name + ' exceeds the source expression bound', { policyIndex, directiveIndex }), bounds);
      return [];
    }
    const sources = [];
    for (const token of tokens) {
      if (token.length > bounds.maxSourceLength) {
        recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.SOURCE_TOO_LONG, 'source expression exceeds the byte-length bound', { policyIndex, directiveIndex }), bounds);
        continue;
      }
      try {
        sources.push(parseSourceExpression(token));
      } catch (error) {
        const wrapped = toError(error);
        if (wrapped.context === undefined) wrapped.context = { policyIndex, directiveIndex };
        recordError(errors, wrapped, bounds);
      }
    }
    const lowerTokens = tokens.map((token) => token.toLowerCase());
    if (lowerTokens.includes("'none'") && tokens.length > 1) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.NONE_CONFLICT, "'none' must be the only source expression in " + name, { policyIndex, directiveIndex }), bounds);
    }
    return sources;
  }

  if (name === 'upgrade-insecure-requests') {
    if (tokens.length !== 0) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.UNEXPECTED_DIRECTIVE_VALUE, name + ' does not accept a value', { policyIndex, directiveIndex }), bounds);
    }
    return [];
  }
  if (name === 'sandbox') {
    for (const token of tokens) {
      if (!SANDBOX_TOKENS.includes(token.toLowerCase())) {
        recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.INVALID_SANDBOX_TOKEN, 'unknown sandbox token: ' + errorDetail(token), { policyIndex, directiveIndex }), bounds);
      }
    }
    return [];
  }
  if (name === 'require-trusted-types-for') {
    if (tokens.length === 0 || tokens.some((token) => token.toLowerCase() !== "'script'")) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.INVALID_TRUSTED_TYPES_TOKEN, "require-trusted-types-for accepts only 'script'", { policyIndex, directiveIndex }), bounds);
    }
    return [];
  }
  if (name === 'trusted-types') {
    if (tokens.length === 0) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.MISSING_DIRECTIVE_VALUE, 'trusted-types requires a value', { policyIndex, directiveIndex }), bounds);
      return [];
    }
    const lowerTokens = tokens.map((token) => token.toLowerCase());
    if (lowerTokens.includes("'none'") && tokens.length > 1) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.NONE_CONFLICT, "trusted-types 'none' must appear alone", { policyIndex, directiveIndex }), bounds);
    }
    for (const token of tokens) {
      const lower = token.toLowerCase();
      const valid = lower === "'none'" || lower === "'allow-duplicates'" || token === '*' || /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(token);
      if (!valid) {
        recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.INVALID_TRUSTED_TYPES_TOKEN, 'malformed trusted-types token: ' + errorDetail(token), { policyIndex, directiveIndex }), bounds);
      }
    }
    return [];
  }
  if (name === 'require-sri-for') {
    if (tokens.length === 0 || tokens.some((token) => !['script', 'style'].includes(token.toLowerCase()))) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.MISSING_DIRECTIVE_VALUE, 'require-sri-for accepts only script and style tokens', { policyIndex, directiveIndex }), bounds);
    }
    return [];
  }
  if (name === 'report-uri') {
    if (tokens.length === 0) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.MISSING_DIRECTIVE_VALUE, 'report-uri requires at least one endpoint', { policyIndex, directiveIndex }), bounds);
      return [];
    }
    for (const token of tokens) {
      try {
        validateReportEndpointToken(token);
      } catch (error) {
        recordError(errors, error, bounds);
      }
    }
    return [];
  }
  if (name === 'report-to') {
    if (tokens.length !== 1) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.UNEXPECTED_DIRECTIVE_VALUE, 'report-to requires exactly one endpoint group token', { policyIndex, directiveIndex }), bounds);
      return [];
    }
    try {
      validateReportEndpointToken(tokens[0]);
    } catch (error) {
      recordError(errors, error, bounds);
    }
    return [];
  }
  return [];
}

function parsePolicy(body, policyIndex, errors, bounds, totalState) {
  const trimmed = body.trim();
  const directives = [];
  const directiveMap = Object.create(null);
  const segments = trimmed.split(';');
  let sourceExpressionCount = 0;
  for (let segmentIndex = 0; segmentIndex < segments.length; segmentIndex += 1) {
    const segment = segments[segmentIndex].trim();
    if (segment.length === 0) {
      if (segmentIndex !== segments.length - 1) {
        recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.EMPTY_DIRECTIVE, 'empty directive or repeated semicolon', { policyIndex }), bounds);
      }
      continue;
    }
    if (directives.length >= bounds.maxDirectivesPerPolicy || totalState.count >= bounds.maxTotalDirectives) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.TOO_MANY_DIRECTIVES, 'directive count bound exceeded', { policyIndex }), bounds);
      break;
    }
    const parts = splitWhitespace(segment);
    const rawName = parts.shift() || '';
    const name = rawName.toLowerCase();
    const directiveIndex = directives.length;
    if (!/^[a-z][a-z0-9-]{0,63}$/u.test(name) || name !== rawName && !/^[A-Za-z][A-Za-z0-9-]{0,63}$/u.test(rawName)) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.INVALID_DIRECTIVE_NAME, 'directive name is malformed: ' + errorDetail(rawName), { policyIndex, directiveIndex }), bounds);
      continue;
    }
    if (!CSP_DIRECTIVES.includes(name)) {
      const code = DEPRECATED_DIRECTIVES.includes(name) ? CSPCAGE_ERROR_CODES.DEPRECATED_DIRECTIVE : CSPCAGE_ERROR_CODES.UNKNOWN_DIRECTIVE;
      const detail = code === CSPCAGE_ERROR_CODES.DEPRECATED_DIRECTIVE ? 'deprecated directive is forbidden: ' + name : 'unknown directive is forbidden: ' + errorDetail(rawName);
      recordError(errors, new CspCageError(code, detail, { policyIndex, directiveIndex }), bounds);
    }
    const duplicate = Object.prototype.hasOwnProperty.call(directiveMap, name);
    const tokens = parts;
    const value = tokens.join(' ');
    const sources = validateDirectiveValue(name, tokens, policyIndex, directiveIndex, errors, bounds);
    if (SOURCE_LIST_DIRECTIVES.includes(name)) sourceExpressionCount += tokens.length;
    const directive = Object.freeze({
      index: directiveIndex,
      name,
      value,
      tokens: Object.freeze(tokens.slice()),
      sources: Object.freeze(sources),
      ignored: duplicate,
      duplicateOf: duplicate ? name : null,
      firstWinsShadowing: duplicate
    });
    directives.push(directive);
    totalState.count += 1;
    if (!duplicate) directiveMap[name] = directive;
    if (duplicate) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.DUPLICATE_DIRECTIVE, 'duplicate directive ' + name + ' is ignored because the first directive wins', { policyIndex, directiveIndex }), bounds);
    }
  }
  if (directives.length === 0) {
    recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.EMPTY_POLICY, 'policy contains no directives', { policyIndex }), bounds);
  }
  return Object.freeze({
    index: policyIndex,
    raw: body,
    directives: Object.freeze(directives),
    directiveMap,
    directiveCount: directives.length,
    sourceExpressionCount
  });
}

export function parseCspInternal(input, options = {}) {
  let bounds;
  try {
    bounds = resolveParseOptions(options);
  } catch (error) {
    return {
      value: Object.freeze({
        valid: false,
        policyCount: 0,
        policies: Object.freeze([]),
        directiveCount: 0,
        sourceExpressionCount: 0,
        bounds: CSP_PARSE_BOUNDS
      }),
      errors: [toError(error)]
    };
  }

  const errors = [];
  const policies = [];
  let totalBytes = 0;
  try {
    const headers = normalizeInput(input);
    for (const header of headers) totalBytes += byteLength(header);
    if (totalBytes > bounds.maxBytes) {
      recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.INPUT_TOO_LARGE, 'CSP input exceeds the byte-length bound'), bounds);
    } else {
      const units = splitPolicyUnits(headers);
      if (units.length > bounds.maxPolicies) {
        recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.TOO_MANY_POLICIES, 'policy count bound exceeded'), bounds);
      }
      const usable = units.slice(0, bounds.maxPolicies);
      for (let index = 0; index < usable.length; index += 1) {
        const unit = usable[index];
        try {
          scanHeaderCharacters(unit, index);
        } catch (error) {
          recordError(errors, error, bounds);
          continue;
        }
        if (unit.trim().length === 0) {
          recordError(errors, new CspCageError(CSPCAGE_ERROR_CODES.EMPTY_POLICY, 'empty policy in header list', { policyIndex: index }), bounds);
          continue;
        }
        const totalState = { count: policies.reduce((sum, policy) => sum + policy.directiveCount, 0) };
        policies.push(parsePolicy(unit, index, errors, bounds, totalState));
      }
    }
  } catch (error) {
    recordError(errors, error, bounds);
  }

  const directiveCount = policies.reduce((sum, policy) => sum + policy.directiveCount, 0);
  const sourceExpressionCount = policies.reduce((sum, policy) => sum + policy.sourceExpressionCount, 0);
  const value = deepFreeze({
    valid: errors.length === 0,
    policyCount: policies.length,
    policies,
    directiveCount,
    sourceExpressionCount,
    bounds
  });
  return { value, errors };
}

export function parseCsp(input, options = {}) {
  const parsed = parseCspInternal(input, options);
  let strict = true;
  try {
    strict = resolveParseOptions(options).strict;
  } catch {
    strict = true;
  }
  if (parsed.errors.length > 0 && strict) throw parsed.errors[0];
  return deepFreeze(parsed.value);
}
