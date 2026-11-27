import { CSPCAGE_ERROR_CODES } from './constants.mjs';

export class CspCageError extends Error {
  constructor(code, detail = '', context = undefined) {
    const message = detail === '' ? code : code + ': ' + detail;
    super(message);
    this.name = 'CspCageError';
    this.code = code;
    this.detail = detail;
    if (context !== undefined) this.context = context;
  }
}

export function isCspCageError(value) {
  return value instanceof CspCageError;
}

export function invalidInput(detail) {
  return new CspCageError(CSPCAGE_ERROR_CODES.INVALID_INPUT, detail);
}
