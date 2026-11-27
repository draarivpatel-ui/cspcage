# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that can be exploited in a real deployment. Use GitHub's private vulnerability reporting for the repository at `https://github.com/draarivpatel-ui/cspcage` when that feature is available. Otherwise open a minimal public issue that asks for a private contact path and does not include exploit details, secrets, private endpoints, or personally identifying information.

## Scope

In scope:

- Parser differentials that cause `cspcage` and a CSP Level 3 browser to interpret the same serialized policy differently in a security-relevant way.
- Missing validation that lets header injection, NUL bytes, controls, duplicate directives, malformed nonces, malformed hashes, or dangerous directives reach serialized output.
- Audit false negatives for documented XSS bypasses, CDN script gadgets, weak nonces, weak hashes, clickjacking gaps, base-uri hijacking, object injection, insecure schemes, or reporting endpoint hazards.
- Prototype pollution, denial of service, excessive memory use, or regex backtracking in bounded parsing and building.
- Unsafe merging behavior that silently widens `'none'` or introduces `'unsafe-inline'`.

Out of scope:

- Browser CSP implementation bugs.
- A deployment that intentionally enables unsafe source expressions after explicit review.
- Findings requiring compromise of the Node.js process, the host machine, or the private reporting endpoint.
- Lack of enforcement when an application generates a policy but does not send it to the browser.

## Operational guidance

- Generate a nonce fresh for every response.
- Never reuse nonces across responses or users.
- Prefer `createStrictCsp` for new applications.
- Treat audit errors as deployment blockers.
- Use `requireCleanAudit` in CI for zero-warning builds.
- Keep reporting endpoints HTTPS-only, unauthenticated in the URL, and tightly scoped.

## Supported versions

Security fixes are applied to the current 1.x release line.
