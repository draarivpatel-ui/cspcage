import { auditCsp } from '../src/index.mjs';

const policy = "default-src 'self'; script-src 'unsafe-inline' cdn.jsdelivr.net; object-src *; report-uri http://127.0.0.1:8080/csp";
const report = auditCsp(policy);

console.log('grade', report.grade, 'score', report.score, 'safe', report.safe);
for (const finding of report.findings) {
  console.log(finding.severity, finding.code, finding.directive || '-');
}
