import { createHash, randomBytes } from 'node:crypto';
import { CSPCAGE_ERROR_CODES, HASH_ALGORITHMS } from './constants.mjs';
import { CspCageError } from './errors.mjs';

export function generateNonce(bytes = 16) {
  if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 64) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_NONCE_INPUT, 'nonce size must be an integer from 16 to 64 bytes');
  }
  return randomBytes(bytes).toString('base64');
}

export function computeHash(content, algorithm = 'sha256') {
  if (!HASH_ALGORITHMS.includes(algorithm)) {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HASH_INPUT, 'algorithm must be sha256, sha384, or sha512');
  }
  let bytes;
  if (typeof content === 'string') {
    bytes = Buffer.from(content, 'utf8');
  } else if (content instanceof Uint8Array) {
    bytes = content;
  } else if (content instanceof ArrayBuffer) {
    bytes = new Uint8Array(content);
  } else {
    throw new CspCageError(CSPCAGE_ERROR_CODES.INVALID_HASH_INPUT, 'content must be a string, Uint8Array, or ArrayBuffer');
  }
  return algorithm + '-' + createHash(algorithm).update(bytes).digest('base64');
}
