import { CSP_DIRECTIVE_ORDER, CSPCAGE_ERROR_CODES } from './constants.mjs';
import { buildCsp, normalizeDirectiveInput } from './builder.mjs';
import { CspCageError } from './errors.mjs';
import { parseCsp } from './parser.mjs';
import { deepFreeze, isPlainObject, truncateDetail, uniqueTokens } from './utils.mjs';

const OPTION_KEYS = new Set(['allowUnsafeInline', 'allowNoneWidening', 'requireCleanAudit']);

function looksParsedCsp(value) {
  return isPlainObject(value) && Array.isArray(value.policies) && typeof value.policyCount === 'number';
}

function mapFromParsed(parsed) {
  if (parsed.policyCount !== 1) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_MERGE_INPUT, 'merge inputs must each contain exactly one policy');
  }
  const map = new Map();
  for (const item of parsed.policies[0].directives) {
    if (!item.ignored) map.set(item.name, item.tokens.slice());
  }
  return map;
}

function mapFromInput(input) {
  if (typeof input === 'string') return mapFromParsed(parseCsp(input));
  if (looksParsedCsp(input)) return mapFromParsed(input);
  if (isPlainObject(input)) return normalizeDirectiveInput(input);
  throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_MERGE_INPUT, 'merge input must be a CSP string, parsed CSP, or directive object');
}

function splitArguments(args) {
  let inputs;
  let options = {};
  if (args.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_MERGE_INPUT, 'at least one policy is required');
  }
  if (Array.isArray(args[0])) {
    inputs = args[0].slice();
    if (args.length > 2) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_MERGE_INPUT, 'merge accepts a policy array and one options object');
    }
    options = args[1] === undefined ? {} : args[1];
  } else {
    inputs = args.slice();
    const last = inputs[inputs.length - 1];
    if (inputs.length > 1 && isPlainObject(last) && Object.keys(last).length > 0 && Object.keys(last).every((key) => OPTION_KEYS.has(key))) {
      options = inputs.pop();
    }
  }
  if (!isPlainObject(options)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'merge options must be a plain object');
  }
  for (const key of Object.keys(options)) {
    if (!OPTION_KEYS.has(key)) {
      throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_OPTIONS, 'unknown merge option ' + truncateDetail(key, 40));
    }
  }
  if (inputs.length === 0) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_MERGE_INPUT, 'at least one policy is required');
  }
  return { inputs, options };
}

function orderedNames(names) {
  const present = new Set(names);
  const known = CSP_DIRECTIVE_ORDER.filter((name) => present.has(name));
  const unknown = [...present].filter((name) => !CSP_DIRECTIVE_ORDER.includes(name)).sort();
  return known.concat(unknown);
}

function noneToken(token) {
  return token.toLowerCase() === "'none'";
}

function unsafeInlineToken(token) {
  return token.toLowerCase() === "'unsafe-inline'";
}

function assertUnsafeInlineAllowed(tokens, options) {
  if (!options.allowUnsafeInline && tokens.some((token) => unsafeInlineToken(token))) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.UNSAFE_INLINE_MERGE, "merged output would contain 'unsafe-inline'; pass allowUnsafeInline true only after explicit review");
  }
}

function mergeTokenSets(tokenSets, options) {
  const union = [];
  for (const tokens of tokenSets) union.push(...tokens);
  const unique = uniqueTokens(union);
  const hasNone = unique.some((token) => noneToken(token));
  let result;
  if (hasNone && !options.allowNoneWidening) {
    result = ["'none'"];
  } else if (hasNone && unique.length > 1) {
    result = unique.filter((token) => !noneToken(token));
  } else {
    result = unique;
  }
  assertUnsafeInlineAllowed(result, options);
  return result;
}

function mapsToObject(map) {
  const output = Object.create(null);
  for (const name of orderedNames(map.keys())) output[name] = map.get(name);
  return output;
}

export function mergeCsp(...args) {
  const { inputs, options } = splitArguments(args);
  const maps = inputs.map((input) => mapFromInput(input));
  const names = [];
  for (const map of maps) names.push(...map.keys());
  const merged = new Map();
  for (const name of orderedNames(names)) {
    const tokenSets = maps.filter((map) => map.has(name)).map((map) => map.get(name));
    merged.set(name, mergeTokenSets(tokenSets, options));
  }
  return buildCsp(mapsToObject(merged), { requireCleanAudit: options.requireCleanAudit === true, allowUnsafeInline: options.allowUnsafeInline === true });
}

export function intersectCsp(...args) {
  const { inputs, options } = splitArguments(args);
  const maps = inputs.map((input) => mapFromInput(input));
  const names = [];
  for (const map of maps) names.push(...map.keys());
  const output = new Map();
  for (const name of orderedNames(names)) {
    const present = maps.filter((map) => map.has(name)).map((map) => map.get(name));
    let tokens;
    if (present.some((items) => items.some((item) => noneToken(item)))) {
      tokens = ["'none'"];
    } else {
      const counts = new Map();
      for (const items of present) {
        for (const token of uniqueTokens(items)) counts.set(token, (counts.get(token) || 0) + 1);
      }
      tokens = [...counts.keys()].filter((token) => counts.get(token) === present.length);
      if (tokens.length === 0) tokens = ["'none'"];
    }
    assertUnsafeInlineAllowed(tokens, options);
    output.set(name, tokens);
  }
  return buildCsp(mapsToObject(output), { requireCleanAudit: options.requireCleanAudit === true, allowUnsafeInline: options.allowUnsafeInline === true });
}

function sortedSetTokens(tokens) {
  return uniqueTokens(tokens).slice().sort();
}

function setDiff(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item));
}

function diffMap(beforeMap, afterMap) {
  const beforeNames = new Set(beforeMap.keys());
  const afterNames = new Set(afterMap.keys());
  const addedDirectives = [...afterNames].filter((name) => !beforeNames.has(name)).sort();
  const removedDirectives = [...beforeNames].filter((name) => !afterNames.has(name)).sort();
  const changedDirectives = [];
  const unchangedDirectives = [];
  for (const name of [...beforeNames].filter((item) => afterNames.has(item)).sort()) {
    const beforeTokens = sortedSetTokens(beforeMap.get(name));
    const afterTokens = sortedSetTokens(afterMap.get(name));
    const addedSources = setDiff(afterTokens, beforeTokens);
    const removedSources = setDiff(beforeTokens, afterTokens);
    if (addedSources.length === 0 && removedSources.length === 0) {
      unchangedDirectives.push(name);
    } else {
      changedDirectives.push(Object.freeze({
        name,
        addedSources: Object.freeze(addedSources),
        removedSources: Object.freeze(removedSources)
      }));
    }
  }
  return Object.freeze({
    addedDirectives: Object.freeze(addedDirectives),
    removedDirectives: Object.freeze(removedDirectives),
    changedDirectives: Object.freeze(changedDirectives),
    unchangedDirectives: Object.freeze(unchangedDirectives),
    summary: Object.freeze({
      addedCount: addedDirectives.length,
      removedCount: removedDirectives.length,
      changedCount: changedDirectives.length,
      unchangedCount: unchangedDirectives.length
    })
  });
}

export function diffCsp(before, after) {
  return deepFreeze(diffMap(mapFromInput(before), mapFromInput(after)));
}
