import cspcage, {
  CODE,
  CSPCAGE_VERSION,
  CspCageError,
  auditCsp,
  buildCsp,
  computeHash,
  createStrictCsp,
  diffCsp,
  generateNonce,
  intersectCsp,
  isSafeCsp,
  mergeCsp,
  parseCsp,
  type CspDirectiveInput,
  type CspMergeInput,
  type CspMergeOptions,
  type CspParseOptions,
  type ParsedCsp
} from '../types/index.js';

const version: string = CSPCAGE_VERSION;
const options: CspParseOptions = { maxBytes: 2048, maxPolicies: 2, strict: true };
const input: CspDirectiveInput = {
  defaultSrc: ["'self'"],
  scriptSrc: "'self'",
  objectSrc: ["'none'"],
  baseUri: ["'none'"],
  frameAncestors: ["'none'"],
  upgradeInsecureRequests: true
};
const parsed: ParsedCsp = parseCsp("default-src 'self'", options);
const audit = auditCsp(parsed, { strict: true });
const header: string = buildCsp(input, { requireCleanAudit: false });
const strictHeader: string = createStrictCsp({ nonce: generateNonce(16), reportTo: 'csp-endpoint' });
const nonce: string = generateNonce();
const digest: string = computeHash('console.log(1)', 'sha256');
const mergeInputs: readonly CspMergeInput[] = [header, strictHeader];
const merged: string = mergeCsp(mergeInputs, { allowNoneWidening: false });
const intersected: string = intersectCsp(mergeInputs);
const mergeOptions: CspMergeOptions = { allowNoneWidening: true, requireCleanAudit: false };
const arrayMerged: string = mergeCsp(mergeInputs, mergeOptions);
const arrayIntersected: string = intersectCsp(mergeInputs, mergeOptions);
const variadicMerged: string = mergeCsp(header, strictHeader, mergeOptions);
const variadicMergedLiteral: string = mergeCsp(header, parsed, input, { allowUnsafeInline: false });
const variadicSingle: string = mergeCsp(header, mergeOptions);
const variadicIntersected: string = intersectCsp(header, strictHeader, mergeOptions);
const variadicIntersectedLiteral: string = intersectCsp(header, parsed, { requireCleanAudit: true });
const variadicPlain: string = mergeCsp(header, strictHeader);
// @ts-expect-error options require at least one preceding policy
mergeCsp(mergeOptions);
// @ts-expect-error options require at least one preceding policy
intersectCsp(mergeOptions);
// @ts-expect-error options must be the final argument
mergeCsp(header, mergeOptions, strictHeader);
// @ts-expect-error unknown option keys are rejected in the array form
mergeCsp(mergeInputs, { allowNoneWidning: true });
// @ts-expect-error unknown option keys are rejected in the array form
intersectCsp(mergeInputs, { unknown: true });
// @ts-expect-error option values must be booleans
mergeCsp(header, strictHeader, { allowNoneWidening: 1 });
// @ts-expect-error option values must be booleans
intersectCsp(header, strictHeader, { requireCleanAudit: 1 });
const diff = diffCsp(header, merged);
const safe: boolean = isSafeCsp(strictHeader);
const failure = new CspCageError(CODE.INVALID_INPUT, 'invalid input');

void version;
void audit;
void nonce;
void digest;
void intersected;
void arrayMerged;
void arrayIntersected;
void variadicMerged;
void variadicMergedLiteral;
void variadicSingle;
void variadicIntersected;
void variadicIntersectedLiteral;
void variadicPlain;
void diff;
void safe;
void failure;
void cspcage;
