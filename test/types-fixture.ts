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
const diff = diffCsp(header, merged);
const safe: boolean = isSafeCsp(strictHeader);
const failure = new CspCageError(CODE.INVALID_INPUT, 'invalid input');

void version;
void audit;
void nonce;
void digest;
void intersected;
void diff;
void safe;
void failure;
void cspcage;
