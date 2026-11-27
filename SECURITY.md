# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/cspcage/security/advisories/new). Do not open a public issue, pull request, or discussion with exploit details, secrets, private endpoints, or personal data.

Include the affected version, a minimal policy input, the API or CLI path used, the expected browser or audit behavior, the actual behavior, and whether the report contains a proof of concept that should remain private during triage.

## Disclosure timeline

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, prepare a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

## Scope

In scope:

- Parser differentials that cause `cspcage` and a CSP Level 3 browser to interpret the same serialized policy differently in a security-relevant way
- Missing validation that lets header injection, NUL bytes, controls, duplicate directives, malformed nonces, malformed hashes, or dangerous directives reach serialized output
- Audit false negatives for documented XSS bypasses, CDN script gadgets, weak nonces, weak hashes, clickjacking gaps, base-uri hijacking, object injection, insecure schemes, or reporting endpoint hazards
- Prototype pollution, denial of service, excessive memory use, or regex backtracking in bounded parsing and building
- Unsafe merging behavior that silently widens `'none'` or introduces `'unsafe-inline'`

## Out of scope

Browser CSP implementation bugs, deployments that intentionally enable unsafe source expressions after explicit review, compromise of the Node.js process or host machine, and failure to send a generated policy to the browser are out of scope.

## Hardening notes

The package has zero runtime dependencies. Input budgets, fail-closed validation, deterministic tests, and property-based fuzz tests are part of the maintenance bar. A report that the library marks unsafe must block the operation in the caller; audit output is a boundary signal, not proof that a downstream system is safe.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
