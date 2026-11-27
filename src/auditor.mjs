import {
  CSP_PARSE_BOUNDS,
  CSPCAGE_SEVERITY,
  PLACEHOLDER_NONCE_VALUES,
  SCRIPT_GADGET_HOSTS
} from './constants.mjs';
import { parseCspInternal } from './parser.mjs';
import { decodeBase64Value, deepFreeze, isPlainObject, resolveParseOptions } from './utils.mjs';

const ERROR = CSPCAGE_SEVERITY.ERROR;
const WARNING = CSPCAGE_SEVERITY.WARNING;
const NOTICE = CSPCAGE_SEVERITY.NOTICE;

function makeAccumulator(maxFindings) {
  const findings = [];
  const counts = { error: 0, warning: 0, notice: 0 };
  let truncated = false;
  return {
    findings,
    counts,
    add(severity, code, message, context = {}) {
      if (Object.prototype.hasOwnProperty.call(counts, severity)) counts[severity] += 1;
      const finding = {
        severity,
        code,
        message,
        policyIndex: typeof context.policyIndex === 'number' ? context.policyIndex : null,
        directive: typeof context.directive === 'string' ? context.directive : null,
        recommendation: typeof context.recommendation === 'string' ? context.recommendation : null
      };
      if (findings.length >= maxFindings) {
        truncated = true;
        return;
      }
      findings.push(Object.freeze(finding));
    },
    finish() {
      if (!truncated) return;
      counts.error += 1;
      const sentinel = Object.freeze({
        severity: ERROR,
        code: 'CSPCAGE_FINDINGS_TRUNCATED',
        message: 'finding count reached the configured cap; suppressed findings make this report fail closed',
        policyIndex: null,
        directive: null,
        recommendation: 'Increase maxFindings or reduce policy complexity, then re-run the audit before deployment.'
      });
      if (findings.length < maxFindings) findings.push(sentinel);
      else findings[maxFindings - 1] = sentinel;
    }
  };
}

function errorCode(error) {
  return typeof error.code === 'string' ? error.code : 'CSPCAGE_INVALID_INPUT';
}

function errorMessage(error) {
  if (typeof error.detail === 'string' && error.detail.length > 0) return error.detail;
  if (typeof error.message === 'string') return error.message;
  return 'invalid CSP input';
}

function errorContext(error) {
  const context = error.context;
  if (!isPlainObject(context)) return {};
  return context;
}

function directive(policy, name) {
  return policy.directiveMap[name] || null;
}

function effectiveFetchDirective(policy, name) {
  const exact = directive(policy, name);
  if (exact !== null) return exact;
  if (name === 'script-src-elem' || name === 'script-src-attr') {
    const script = directive(policy, 'script-src');
    if (script !== null) return script;
  }
  return directive(policy, 'default-src');
}

function tokenIsNone(token) {
  return token.toLowerCase() === "'none'";
}

function exactlyNone(item) {
  return item !== null && item.tokens.length === 1 && tokenIsNone(item.tokens[0]);
}

function hasKeyword(item, keyword) {
  if (item === null) return false;
  return item.sources.some((source) => source.kind === 'keyword' && source.keyword === keyword);
}

function hasValidHash(item) {
  return item !== null && item.sources.some((source) => source.kind === 'hash');
}

function hasNonce(item) {
  return item !== null && item.sources.some((source) => source.kind === 'nonce');
}

function hasStrongNonceOrHash(item) {
  if (item === null) return false;
  return item.sources.some((source) => {
    if (source.kind === 'hash') return true;
    return source.kind === 'nonce' && source.decodedBytes >= 16;
  });
}

function scriptRelevantDirectives(policy) {
  const output = [];
  const seen = new Set();
  for (const name of ['script-src', 'script-src-elem', 'script-src-attr']) {
    const item = effectiveFetchDirective(policy, name);
    if (item !== null && !seen.has(item)) {
      seen.add(item);
      output.push(item);
    }
  }
  return output;
}

function criticalSourceDirective(name) {
  return name === 'script-src' || name === 'script-src-elem' || name === 'script-src-attr' || name === 'object-src' || name === 'default-src' || name === 'connect-src' || name === 'form-action';
}

function scriptGadgetMatch(host) {
  let candidate = host.toLowerCase();
  if (candidate.startsWith('*.')) candidate = candidate.slice(2);
  if (candidate.endsWith('.')) candidate = candidate.slice(0, -1);
  for (const gadget of SCRIPT_GADGET_HOSTS) {
    if (candidate === gadget || candidate.endsWith('.' + gadget)) return gadget;
  }
  return null;
}

function analyzeUnsafeScriptTokens(policy, item, acc) {
  const context = { policyIndex: policy.index, directive: item.name };
  const inline = hasKeyword(item, 'unsafe-inline');
  if (inline) {
    if (hasNonce(item) || hasValidHash(item)) {
      acc.add(WARNING, 'CSP3_UNSAFE_INLINE_IGNORED', "'unsafe-inline' is ignored by CSP Level 3 browsers because a nonce or hash is present, but legacy CSP2 browsers may still execute inline scripts", { ...context, recommendation: 'Remove unsafe-inline and keep strong nonces or hashes.' });
    } else {
      acc.add(ERROR, 'UNSAFE_INLINE_ACTIVE', "'unsafe-inline' permits inline script execution and is a primary XSS bypass", { ...context, recommendation: 'Replace inline scripts with strong nonces or hashes.' });
    }
  }
  if (hasKeyword(item, 'unsafe-eval')) {
    acc.add(ERROR, 'UNSAFE_EVAL', "'unsafe-eval' permits eval and string-to-code execution", { ...context, recommendation: 'Remove eval-like code paths and delete unsafe-eval.' });
  }
  if (hasKeyword(item, 'wasm-unsafe-eval')) {
    acc.add(ERROR, 'WASM_UNSAFE_EVAL', "'wasm-unsafe-eval' permits WebAssembly compilation from attacker-controlled bytes", { ...context, recommendation: 'Serve trusted Wasm artifacts from exact hosts instead.' });
  }
  if (hasKeyword(item, 'unsafe-hashes')) {
    acc.add(WARNING, 'UNSAFE_HASHES', "'unsafe-hashes' extends hashes to inline event handlers and javascript URLs", { ...context, recommendation: 'Remove inline handlers instead of enabling unsafe-hashes.' });
  }
  if (hasKeyword(item, 'strict-dynamic') && !hasStrongNonceOrHash(item)) {
    acc.add(WARNING, 'STRICT_DYNAMIC_WITHOUT_STRONG_PROOF', "'strict-dynamic' has little value without a strong nonce or a valid hash in the same directive", { ...context, recommendation: 'Pair strict-dynamic with a 128-bit or stronger nonce or a valid hash.' });
  }
}

function analyzeCriticalSources(policy, item, acc) {
  if (!criticalSourceDirective(item.name)) return;
  const context = { policyIndex: policy.index, directive: item.name };
  for (const source of item.sources) {
    if (source.kind === 'wildcard') {
      acc.add(ERROR, 'WILDCARD_SOURCE', 'a wildcard source permits scripts, objects, or connections from arbitrary origins', { ...context, recommendation: 'Replace wildcards with exact HTTPS origins.' });
    }
    if (source.kind === 'scheme') {
      if (source.scheme === 'http') {
        acc.add(ERROR, 'INSECURE_HTTP_SCHEME', 'the http scheme permits network attackers to replace protected resources', { ...context, recommendation: 'Use exact HTTPS origins.' });
      } else if (source.scheme === 'https') {
        const severity = item.name === 'connect-src' || item.name === 'form-action' ? WARNING : ERROR;
        acc.add(severity, 'BROAD_HTTPS_SCHEME', 'the bare https scheme is a wildcard over every HTTPS origin', { ...context, recommendation: 'Use exact HTTPS origins.' });
      } else if (source.scheme === 'data' || source.scheme === 'blob' || source.scheme === 'filesystem') {
        const severity = item.name === 'connect-src' ? WARNING : ERROR;
        acc.add(severity, 'DANGEROUS_DATA_SCHEME', source.scheme + ' is a dangerous broad scheme in ' + item.name, { ...context, recommendation: 'Remove data, blob, and filesystem schemes from executable or connection directives.' });
      } else if (source.scheme === 'javascript' || source.scheme === 'vbscript') {
        acc.add(ERROR, 'DANGEROUS_SCRIPT_SCHEME', source.scheme + ' is an executable scheme', { ...context, recommendation: 'Remove executable schemes immediately.' });
      }
    }
    if (source.kind === 'host') {
      if (source.scheme === 'http') {
        acc.add(ERROR, 'INSECURE_HTTP_HOST', 'an explicit HTTP host can be replaced by a network attacker', { ...context, recommendation: 'Use HTTPS for every external origin.' });
      }
      if (source.hostIsWildcard) {
        const severity = item.name === 'connect-src' || item.name === 'form-action' ? WARNING : ERROR;
        acc.add(severity, 'WILDCARD_HOST_SOURCE', 'subdomain wildcard hosting is broader than an exact origin allowlist', { ...context, recommendation: 'Use exact host names and paths where possible.' });
      }
      if (source.port === '*') {
        const severity = item.name === 'connect-src' || item.name === 'form-action' ? WARNING : ERROR;
        acc.add(severity, 'WILDCARD_PORT_SOURCE', 'a wildcard port broadens the origin beyond a single HTTPS service', { ...context, recommendation: 'Pin the expected HTTPS port or omit the port for the scheme default.' });
      }
    }
  }
}

function analyzeCdnGadgets(policy, acc) {
  for (const item of scriptRelevantDirectives(policy)) {
    if (hasKeyword(item, 'strict-dynamic')) continue;
    for (const source of item.sources) {
      if (source.kind !== 'host') continue;
      const matched = scriptGadgetMatch(source.host);
      if (matched !== null) {
        acc.add(ERROR, 'CDN_SCRIPT_GADGET_HOST', source.host + ' is a known JSONP, AngularJS, or CDN script-gadget bypass host; exact paths remain URL-allowlist entries and do not provide cryptographic proof of content', { policyIndex: policy.index, directive: item.name, recommendation: 'Use strict-dynamic with a strong nonce or hash instead of a CDN URL allowlist.' });
      }
    }
  }
}

function analyzeFrameworkGaps(policy, acc) {
  const context = { policyIndex: policy.index, directive: null };
  const defaultSrc = directive(policy, 'default-src');
  const scriptSrc = directive(policy, 'script-src');
  const scriptElem = directive(policy, 'script-src-elem');
  const scriptAttr = directive(policy, 'script-src-attr');
  if (defaultSrc === null) {
    acc.add(WARNING, 'MISSING_DEFAULT_SRC', 'default-src is missing, so unlisted fetch directives have no restrictive fallback', { ...context, directive: 'default-src', recommendation: "Add default-src 'none' or default-src 'self'." });
  }
  if (scriptSrc === null && defaultSrc === null && scriptElem === null && scriptAttr === null) {
    acc.add(ERROR, 'MISSING_SCRIPT_POLICY', 'neither script-src nor default-src constrains script execution', { ...context, directive: 'script-src', recommendation: "Add script-src with a strong nonce or hash and object-src 'none'." });
  } else if (scriptSrc === null) {
    acc.add(WARNING, 'MISSING_SCRIPT_SRC', 'script-src is missing and script execution relies on partial or fallback directives', { ...context, directive: 'script-src', recommendation: 'Add an explicit script-src policy.' });
  }

  const objectSrc = directive(policy, 'object-src');
  if (objectSrc === null) {
    acc.add(WARNING, 'MISSING_OBJECT_SRC', "object-src 'none' is missing; plugin and object fallback posture is implicit", { ...context, directive: 'object-src', recommendation: "Add object-src 'none'." });
  } else if (!exactlyNone(objectSrc)) {
    acc.add(ERROR, 'OBJECT_SRC_NOT_NONE', "object-src is not exactly 'none', leaving plugin or object injection surface", { policyIndex: policy.index, directive: 'object-src', recommendation: "Set object-src 'none'." });
  }

  const baseUri = directive(policy, 'base-uri');
  if (baseUri === null) {
    acc.add(WARNING, 'MISSING_BASE_URI', 'base-uri is missing, so a base-tag injection can redirect relative URLs', { ...context, directive: 'base-uri', recommendation: "Set base-uri 'none' unless the application requires 'self'." });
  } else if (!(exactlyNone(baseUri) || (baseUri.tokens.length === 1 && baseUri.tokens[0].toLowerCase() === "'self'"))) {
    acc.add(ERROR, 'WEAK_BASE_URI', "base-uri is broader than 'none' or 'self'", { policyIndex: policy.index, directive: 'base-uri', recommendation: "Set base-uri 'none' or base-uri 'self'." });
  }

  const frameAncestors = directive(policy, 'frame-ancestors');
  if (frameAncestors === null) {
    acc.add(WARNING, 'MISSING_FRAME_ANCESTORS', 'frame-ancestors is missing, leaving clickjacking protection to weaker legacy headers', { ...context, directive: 'frame-ancestors', recommendation: "Set frame-ancestors 'none' or frame-ancestors 'self'." });
  } else {
    const badWildcard = frameAncestors.sources.some((source) => source.kind === 'wildcard' || source.hostIsWildcard === true || source.port === '*' || (source.kind === 'scheme' && ['http', 'https', 'data', 'blob', 'filesystem'].includes(source.scheme)) || (source.kind === 'host' && source.scheme === 'http'));
    if (badWildcard) {
      acc.add(ERROR, 'WEAK_FRAME_ANCESTORS', 'frame-ancestors uses a wildcard or dangerous scheme and does not provide reliable clickjacking protection', { policyIndex: policy.index, directive: 'frame-ancestors', recommendation: "Use frame-ancestors 'none', 'self', or exact HTTPS parent origins." });
    } else if (!(exactlyNone(frameAncestors) || frameAncestors.sources.every((source) => source.kind === 'keyword' && source.keyword === 'self' || source.kind === 'host'))) {
      acc.add(WARNING, 'BROAD_FRAME_ANCESTORS', 'frame-ancestors should be none, self, or exact HTTPS parent origins', { policyIndex: policy.index, directive: 'frame-ancestors', recommendation: 'Reduce frame-ancestors to exact required parent origins.' });
    }
  }
}

function analyzeNoncesAndHashes(policy, acc, nonceCounts) {
  for (const item of policy.directives) {
    for (const source of item.sources) {
      if (source.kind !== 'nonce') continue;
      const lower = source.nonce.toLowerCase();
      if (source.decodedBytes < 16) {
        acc.add(ERROR, 'WEAK_NONCE_ENTROPY', 'nonce decodes to fewer than 16 bytes and provides less than 128 bits of entropy', { policyIndex: policy.index, directive: item.name, recommendation: 'Use generateNonce(16) or a stronger CSPRNG nonce.' });
      }
      if (PLACEHOLDER_NONCE_VALUES.includes(lower) || /^0+$/u.test(lower) || /^123456/u.test(lower) || lowComplexityNonce(source.nonce)) {
        acc.add(ERROR, 'STATIC_NONCE_PLACEHOLDER', 'nonce uses a predictable placeholder or static test value', { policyIndex: policy.index, directive: item.name, recommendation: 'Generate a fresh unpredictable nonce for every response.' });
      }
      const key = source.nonce;
      nonceCounts.set(key, (nonceCounts.get(key) || 0) + 1);
    }
  }
}


function lowComplexityNonce(nonce) {
  const decoded = decodeBase64Value(nonce);
  if (decoded === null || decoded.length < 4) return false;
  let allSame = true;
  let ascending = true;
  let descending = true;
  for (let index = 1; index < decoded.length; index += 1) {
    if (decoded[index] !== decoded[0]) allSame = false;
    if (decoded[index] !== ((decoded[index - 1] + 1) % 256)) ascending = false;
    if (decoded[index] !== ((decoded[index - 1] + 255) % 256)) descending = false;
  }
  if (allSame || ascending || descending) return true;
  if (decoded.length >= 8 && decoded.length % 2 === 0) {
    let repeatingPair = true;
    for (let index = 2; index < decoded.length; index += 1) {
      if (decoded[index] !== decoded[index % 2]) {
        repeatingPair = false;
        break;
      }
    }
    if (repeatingPair) return true;
  }
  return false;
}

function parseEndpointUrl(token) {
  try {
    return new URL(token);
  } catch {
    return null;
  }
}

function ipv4PrivateOrLoopback(host) {
  if (!/^[0-9.]+$/u.test(host)) return false;
  const parts = host.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return true;
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

function privateOrLoopbackHost(host) {
  let lower = host.toLowerCase().replace(/^\[|\]$/gu, '');
  if (lower.endsWith('.')) lower = lower.slice(0, -1);
  if (lower === 'localhost' || lower.endsWith('.localhost')) return true;
  if (ipv4PrivateOrLoopback(lower)) return true;
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('::ffff:')) {
    const mapped = lower.slice(7);
    if (ipv4PrivateOrLoopback(mapped)) return true;
    const hexParts = mapped.split(':');
    if (hexParts.length === 2 && hexParts.every((part) => /^[0-9a-f]{1,4}$/u.test(part))) {
      const value = (parseInt(hexParts[0], 16) << 16) + parseInt(hexParts[1], 16);
      const dotted = [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
      if (ipv4PrivateOrLoopback(dotted)) return true;
    }
  }
  if (lower.startsWith('fe80:')) return true;
  if ((lower.startsWith('fc') || lower.startsWith('fd')) && lower.includes(':')) return true;
  return false;
}

function analyzeOneEndpoint(token, policy, directiveName, acc) {
  const context = { policyIndex: policy.index, directive: directiveName };
  const protocolRelative = token.startsWith('//');
  let url = parseEndpointUrl(token);
  if (url === null && protocolRelative) url = parseEndpointUrl('https:' + token);
  if (protocolRelative) {
    acc.add(WARNING, 'REPORT_ENDPOINT_PROTOCOL_RELATIVE', 'protocol-relative reporting endpoints can leak reports over plaintext HTTP', { ...context, recommendation: 'Use an explicit HTTPS endpoint.' });
  }
  if (url === null) return;
  if (url.username !== '' || url.password !== '') {
    acc.add(ERROR, 'REPORT_ENDPOINT_CREDENTIALS', 'reporting endpoint contains credentials in the URL', { ...context, recommendation: 'Remove credentials and use a server-side secret or signed ingestion path.' });
  }
  if (!protocolRelative && url.protocol !== 'https:') {
    acc.add(WARNING, 'REPORT_ENDPOINT_NOT_HTTPS', 'reporting endpoint is not HTTPS and can expose violation reports', { ...context, recommendation: 'Use HTTPS for every reporting endpoint.' });
  }
  if (privateOrLoopbackHost(url.hostname)) {
    acc.add(WARNING, 'REPORT_ENDPOINT_PRIVATE_NETWORK', 'reporting endpoint targets loopback or private-network infrastructure and may become an SSRF primitive in server-side forwarding', { ...context, recommendation: 'Use a tightly scoped external reporting ingestion service.' });
  }
  if (url.pathname === '/' || url.pathname === '' || url.hostname.includes('*')) {
    acc.add(WARNING, 'REPORT_ENDPOINT_TOO_BROAD', 'reporting endpoint is broad or unprefixed and may mix sensitive violation reports with unrelated traffic', { ...context, recommendation: 'Use a dedicated HTTPS reporting path.' });
  }
}

function analyzeReporting(policy, acc) {
  const reportUri = directive(policy, 'report-uri');
  if (reportUri !== null) {
    acc.add(WARNING, 'LEGACY_REPORT_URI', 'report-uri is legacy; report-to is the CSP Level 3 reporting mechanism', { policyIndex: policy.index, directive: 'report-uri', recommendation: 'Prefer report-to while retaining report-uri only for required legacy clients.' });
    for (const token of reportUri.tokens) analyzeOneEndpoint(token, policy, 'report-uri', acc);
  }
  const reportTo = directive(policy, 'report-to');
  if (reportTo !== null) {
    const token = reportTo.tokens[0] || '';
    if (token.includes(':') || token.includes('/') || token.includes('@')) analyzeOneEndpoint(token, policy, 'report-to', acc);
  }
}

function gradeFromScore(score) {
  if (score >= 97) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

const DEDUCTIONS = Object.freeze({
  UNSAFE_INLINE_ACTIVE: 35,
  UNSAFE_EVAL: 30,
  WASM_UNSAFE_EVAL: 25,
  WILDCARD_SOURCE: 25,
  DANGEROUS_SCRIPT_SCHEME: 30,
  DANGEROUS_DATA_SCHEME: 20,
  INSECURE_HTTP_SCHEME: 20,
  INSECURE_HTTP_HOST: 15,
  CDN_SCRIPT_GADGET_HOST: 25,
  WEAK_NONCE_ENTROPY: 15,
  STATIC_NONCE_PLACEHOLDER: 20,
  OBJECT_SRC_NOT_NONE: 15,
  WEAK_BASE_URI: 15,
  WEAK_FRAME_ANCESTORS: 20,
  MISSING_SCRIPT_POLICY: 35,
  REPORT_ENDPOINT_CREDENTIALS: 15,
  CSPCAGE_DUPLICATE_DIRECTIVE: 15,
  CSPCAGE_UNKNOWN_DIRECTIVE: 15,
  CSPCAGE_DEPRECATED_DIRECTIVE: 12,
  CSPCAGE_MALFORMED_NONCE: 12,
  CSPCAGE_MALFORMED_HASH: 12,
  CSPCAGE_FINDINGS_TRUNCATED: 10
});

function scoreFindings(findings, policyIndex) {
  let score = 100;
  const seenCodes = new Set();
  for (const finding of findings) {
    if (finding.policyIndex !== null && finding.policyIndex !== policyIndex) continue;
    const base = DEDUCTIONS[finding.code] || (finding.severity === ERROR ? 12 : finding.severity === WARNING ? 5 : 1);
    const key = finding.code + ':' + finding.directive;
    const deduction = seenCodes.has(key) ? Math.min(4, Math.ceil(base / 4)) : base;
    seenCodes.add(key);
    score -= deduction;
  }
  return Math.max(0, score);
}

function strictPolicyShape(policy) {
  const script = effectiveFetchDirective(policy, 'script-src');
  const objectSrc = directive(policy, 'object-src');
  const baseUri = directive(policy, 'base-uri');
  const frameAncestors = directive(policy, 'frame-ancestors');
  const scriptStrict = script !== null && hasKeyword(script, 'strict-dynamic') && hasStrongNonceOrHash(script) && !hasKeyword(script, 'unsafe-inline') && !hasKeyword(script, 'unsafe-eval');
  const baseStrong = baseUri !== null && exactlyNone(baseUri);
  const frameStrong = frameAncestors !== null && (exactlyNone(frameAncestors) || (frameAncestors.tokens.length === 1 && frameAncestors.tokens[0].toLowerCase() === "'self'"));
  return scriptStrict && exactlyNone(objectSrc) && baseStrong && frameStrong;
}

function looksParsedCsp(input) {
  if (!isPlainObject(input) || !Array.isArray(input.policies) || typeof input.policyCount !== 'number') return false;
  return input.policies.every((policy) => {
    if (!isPlainObject(policy) || !Array.isArray(policy.directives) || policy.directiveMap === null || typeof policy.directiveMap !== 'object') return false;
    return policy.directives.every((item) => {
      if (!isPlainObject(item) || typeof item.name !== 'string' || !Array.isArray(item.tokens) || !Array.isArray(item.sources)) return false;
      return item.tokens.every((token) => typeof token === 'string') && item.sources.every((source) => isPlainObject(source) && typeof source.kind === 'string');
    });
  });
}

export function auditCsp(input, options = {}) {
  if (!isPlainObject(options)) options = {};
  let bounds = CSP_PARSE_BOUNDS;
  try {
    bounds = resolveParseOptions(options);
  } catch {
    bounds = CSP_PARSE_BOUNDS;
  }
  const acc = makeAccumulator(bounds.maxFindings);
  let parsed;
  let parseErrors = [];
  if (looksParsedCsp(input)) {
    parsed = input;
  } else {
    const internal = parseCspInternal(input, options);
    parsed = internal.value;
    parseErrors = internal.errors;
  }

  for (const error of parseErrors) {
    const context = errorContext(error);
    acc.add(ERROR, errorCode(error), errorMessage(error), { policyIndex: typeof context.policyIndex === 'number' ? context.policyIndex : null, directive: null, recommendation: 'Reject or rewrite the malformed CSP header before deployment.' });
  }

  const nonceCounts = new Map();
  for (const policy of parsed.policies) {
    analyzeFrameworkGaps(policy, acc);
    for (const item of policy.directives) analyzeCriticalSources(policy, item, acc);
    for (const item of scriptRelevantDirectives(policy)) analyzeUnsafeScriptTokens(policy, item, acc);
    analyzeCdnGadgets(policy, acc);
    analyzeNoncesAndHashes(policy, acc, nonceCounts);
    analyzeReporting(policy, acc);
  }
  for (const count of nonceCounts.values()) {
    if (count > 1) {
      acc.add(WARNING, 'REPEATED_NONCE', 'the same nonce value appears repeatedly; repeated or static nonce deployment can make nonce protection worthless', { policyIndex: null, directive: null, recommendation: 'Generate a fresh nonce for every response and never reuse it.' });
      break;
    }
  }

  acc.finish();
  const findings = Object.freeze(acc.findings.slice());
  const errors = acc.counts.error;
  const warnings = acc.counts.warning;
  const notices = acc.counts.notice;
  const policyResults = parsed.policies.map((policy) => {
    const score = parseErrors.length > 0 ? Math.min(scoreFindings(findings, policy.index), 45) : scoreFindings(findings, policy.index);
    return Object.freeze({
      policyIndex: policy.index,
      score,
      grade: gradeFromScore(score),
      strictCsp: strictPolicyShape(policy)
    });
  });
  const score = policyResults.length === 0 ? 0 : Math.min(...policyResults.map((result) => result.score));
  const strict = options.strict === true;
  const safe = errors === 0 && (!strict || warnings === 0);
  return deepFreeze({
    valid: parseErrors.length === 0,
    safe,
    strict,
    strictCsp: parseErrors.length === 0 && policyResults.length > 0 && policyResults.every((result) => result.strictCsp),
    grade: gradeFromScore(score),
    score,
    policyCount: parsed.policyCount,
    policyResults,
    counts: { errors, warnings, notices },
    findings
  });
}

export function isSafeCsp(input, options = {}) {
  return auditCsp(input, options).safe;
}
