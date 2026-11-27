import {
  CODE,
  CSP_DIRECTIVES,
  CSP_KEYWORDS,
  CSP_PARSE_BOUNDS,
  CSP_PARSE_HARD_LIMITS,
  CSPCAGE_ERROR_CODES,
  CSPCAGE_SEVERITY,
  CSPCAGE_VERSION,
  DEPRECATED_DIRECTIVES,
  FETCH_DIRECTIVES,
  HASH_ALGORITHMS,
  SCRIPT_GADGET_HOSTS,
  SOURCE_LIST_DIRECTIVES
} from './constants.mjs';
import { CspCageError, isCspCageError } from './errors.mjs';
import { parseCsp } from './parser.mjs';
import { auditCsp, isSafeCsp } from './auditor.mjs';
import { buildCsp, createStrictCsp } from './builder.mjs';
import { computeHash, generateNonce } from './crypto.mjs';
import { diffCsp, intersectCsp, mergeCsp } from './merge.mjs';

export {
  CODE,
  CSP_DIRECTIVES,
  CSP_KEYWORDS,
  CSP_PARSE_BOUNDS,
  CSP_PARSE_HARD_LIMITS,
  CSPCAGE_ERROR_CODES,
  CSPCAGE_SEVERITY,
  CSPCAGE_VERSION,
  DEPRECATED_DIRECTIVES,
  FETCH_DIRECTIVES,
  HASH_ALGORITHMS,
  SCRIPT_GADGET_HOSTS,
  SOURCE_LIST_DIRECTIVES,
  CspCageError,
  isCspCageError,
  parseCsp,
  auditCsp,
  isSafeCsp,
  buildCsp,
  createStrictCsp,
  computeHash,
  generateNonce,
  diffCsp,
  intersectCsp,
  mergeCsp
};

const CspCage = Object.freeze({
  CODE,
  CSP_DIRECTIVES,
  CSP_KEYWORDS,
  CSP_PARSE_BOUNDS,
  CSP_PARSE_HARD_LIMITS,
  CSPCAGE_ERROR_CODES,
  CSPCAGE_SEVERITY,
  CSPCAGE_VERSION,
  DEPRECATED_DIRECTIVES,
  FETCH_DIRECTIVES,
  HASH_ALGORITHMS,
  SCRIPT_GADGET_HOSTS,
  SOURCE_LIST_DIRECTIVES,
  CspCageError,
  isCspCageError,
  parseCsp,
  auditCsp,
  isSafeCsp,
  buildCsp,
  createStrictCsp,
  computeHash,
  generateNonce,
  diffCsp,
  intersectCsp,
  mergeCsp
});

export default CspCage;
