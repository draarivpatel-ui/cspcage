import { auditCsp, createStrictCsp, generateNonce } from '../src/index.mjs';

const nonce = generateNonce();
const header = createStrictCsp({ nonce, reportTo: 'csp-endpoint' });
const report = auditCsp(header, { strict: true });

console.log(header);
console.log('strict', report.strictCsp, 'grade', report.grade, 'warnings', report.counts.warnings);
