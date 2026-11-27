# cspcage

Zero-dependency Content-Security-Policy Level 3 security firewall, XSS-bypass auditor, nonce and hash guard, and safe header builder for Node.js.

`cspcage` parses bounded CSP headers, audits real-world bypass conditions, generates cryptographically strong nonces and hashes, builds safe headers, and merges or diffs policies without silently weakening them. It is designed for Express, Fastify, Next.js, Hono, edge adapters, security middleware, CI policy checks, and plain Node HTTP services.

The package has no runtime dependencies. It ships native ESM, generated CommonJS, strict TypeScript declarations, typed errors, a CLI, deterministic serialization, and an eight-configuration CI matrix.

## Install

```sh
npm install cspcage
```

Node.js 18 or newer is required.

## Quick start

```js
import {
  auditCsp,
  buildCsp,
  createStrictCsp,
  generateNonce,
  parseCsp
} from 'cspcage';

const nonce = generateNonce();
const header = createStrictCsp({ nonce });

const parsed = parseCsp(header);
console.log(parsed.policyCount, parsed.directiveCount);

const report = auditCsp(header);
console.log(report.safe, report.grade, report.score);

const custom = buildCsp({
  defaultSrc: ["'self'"],
  scriptSrc: ["'nonce-" + nonce + "'", "'strict-dynamic'"],
  objectSrc: ["'none'"],
  baseUri: ["'none'"],
  frameAncestors: ["'none'"]
});
```

## Strict bounded parser

```js
import { parseCsp, CspCageError } from 'cspcage';

try {
  const parsed = parseCsp("default-src 'self'; script-src 'self' https://cdn.example.com/app.js");
  console.log(parsed.policies[0].directiveMap['script-src'].sources);
} catch (error) {
  if (error instanceof CspCageError) console.log(error.code, error.detail);
}
```

The parser understands comma-separated multi-policy header lists and arrays of header strings. It validates CSP Level 3 directive names, source expressions, nonces, hashes, host sources, scheme sources, sandbox tokens, reporting directives, Trusted Types directives, and valueless directives.

Unsafe input is bounded before interpretation.

| Bound | Default | Hard maximum |
| --- | ---: | ---: |
| Header bytes | 8192 | 65536 |
| Policies | 4 | 16 |
| Directives per policy | 32 | 64 |
| Total directives | 96 | 256 |
| Sources per directive | 64 | 128 |
| Source length | 512 | 2048 |
| Findings | 128 | 512 |

The parser rejects CR, LF, NUL, C0 and C1 controls, non-ASCII input, Unicode bidi or format smuggling, lone UTF-16 surrogate code units, empty policies, empty directives, malformed quoting, malformed nonce base64, wrong hash lengths, SHA-1 and MD5 hashes, invalid host names, bad ports, bad percent encoding, unknown directives, and deprecated directives.

Duplicate directives are rejected because CSP's first-directive-wins rule makes later entries a dangerous shadowing trap. The parsed partial representation used internally marks duplicate entries as ignored, while public strict parsing throws `CSPCAGE_DUPLICATE_DIRECTIVE`.

Deprecated directives rejected by the strict parser include `block-all-mixed-content`, `plugin-types`, and `referrer`. `report-uri` remains parseable for real-world compatibility, but the auditor marks it as legacy and recommends `report-to`.

## XSS-bypass auditor

```js
import { auditCsp } from 'cspcage';

const report = auditCsp("script-src 'unsafe-inline' cdn.jsdelivr.net; object-src *");
for (const finding of report.findings) {
  console.log(finding.severity, finding.code, finding.recommendation);
}
```

`auditCsp` never throws for hostile policy text. It returns a deeply frozen report with errors, warnings, notices, a score from 0 to 100, a letter grade, per-policy results, and a strict-CSP shape indicator.

Detected classes include:

- Active `'unsafe-inline'` in script directives.
- CSP3 nonce or hash shadowing of `'unsafe-inline'`, with the legacy-browser bypass called out separately.
- `'unsafe-eval'`, `'wasm-unsafe-eval'`, and `'unsafe-hashes'`.
- Missing script fallback policy and missing `default-src` fallback.
- Missing `object-src 'none'` and permissive object sources.
- Missing or broad `base-uri` protection against base-tag hijacking.
- Missing or weak `frame-ancestors` clickjacking protection.
- Wildcards, broad `https:` scheme sources, insecure HTTP, `data:`, `blob:`, `filesystem:`, and executable schemes in critical directives.
- JSONP, AngularJS, and CDN script-gadget hosts such as Google-hosted libraries, jsDelivr, unpkg, cdnjs, raw GitHub content, cloud storage, and CDN wildcard hosts when they are not pinned by exact path, hash, or `'strict-dynamic'`.
- Nonces below 128 bits of decoded entropy, malformed nonce encodings, repeated nonces, and predictable placeholders such as test or numeric values.
- SHA-1, MD5, malformed base64 digests, and wrong digest lengths for SHA-256, SHA-384, and SHA-512.
- Legacy `report-uri` use, non-HTTPS reporting endpoints, credential-bearing endpoints, loopback or private-network reporting targets, protocol-relative endpoints, and broad reporting paths.

Strict-CSP shape requires `'strict-dynamic'` paired with a strong nonce or valid hash, `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors 'none'` or `'self'`, without unsafe script keywords.

## Safe builder

```js
import { buildCsp } from 'cspcage';

const header = buildCsp({
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'"],
  objectSrc: ["'none'"],
  baseUri: ["'none'"],
  frameAncestors: ["'self'"],
  upgradeInsecureRequests: true
});
```

The builder accepts canonical hyphenated keys or camelCase keys. It serializes directives in a deterministic CSP-oriented order. Directive keys and values are checked for semicolon injection, comma injection, whitespace smuggling, CR, LF, NUL, controls, backslashes, unknown directives, deprecated directives, duplicate normalized keys, and prototype-pollution keys such as `__proto__`, `constructor`, and `prototype`.

Every serialized header is parsed again and audited before it is returned. Dangerous audit errors throw `CSPCAGE_UNSAFE_BUILD_OUTPUT`. Missing-policy completeness errors do not block partial directives because `buildCsp` may be used to serialize one header fragment that a server later combines with others. Warnings are reported but do not block the base builder because some legitimate transitional policies need explicit exceptions. Pass `{ requireCleanAudit: true }` when warnings must also block the build. `'unsafe-inline'` is blocked by default; pass `{ allowUnsafeInline: true }` only as a deliberate escape hatch after review.

## Strict policy preset

```js
import { createStrictCsp, generateNonce } from 'cspcage';

const header = createStrictCsp({
  nonce: generateNonce(),
  reportTo: 'csp-endpoint'
});
```

The preset uses a strict-dynamic script policy, a fresh 128-bit or stronger nonce, explicit object and base-uri lockdown, clickjacking protection, self-limited subresource directives, form-action protection, and upgrade-insecure-requests. Optional reporting endpoints and tightly scoped source overrides are supported.

## Nonce and hash generation

```js
import { computeHash, generateNonce } from 'cspcage';

const nonce = generateNonce();       // 16 bytes, 128 bits
const longer = generateNonce(32);    // 32 bytes, 256 bits
const hash = computeHash('console.log("ready")', 'sha256');
```

`generateNonce` uses `node:crypto` `randomBytes`. Sizes below 16 bytes are rejected. `computeHash` supports `sha256`, `sha384`, and `sha512` and returns the CSP hash body in the form `sha256-base64digest`. Wrap it in single quotes when placing it in a source list.

## Merging, intersection, and diffing

```js
import { diffCsp, intersectCsp, mergeCsp } from 'cspcage';

const merged = mergeCsp([
  "script-src 'self'; object-src 'none'",
  "script-src https://cdn.example.com/app.js; base-uri 'none'"
]);

const intersection = intersectCsp([
  "script-src 'self' https://cdn.example.com",
  "script-src 'self'"
]);

const diff = diffCsp(intersection, merged);
console.log(diff.summary);
```

`mergeCsp` unions allowlists deterministically. If one input contains `'none'`, the merged directive remains `'none'` unless `allowNoneWidening` is explicitly set. If merged output would contain `'unsafe-inline'`, the merge throws unless `allowUnsafeInline` is explicitly set. These options are deliberate escape hatches, not silent defaults.

`intersectCsp` keeps only source expressions common to every input for shared directives and falls back to `'none'` when the intersection is empty. `diffCsp` reports added, removed, changed, and unchanged directives plus source-level changes.

## CLI

```sh
cspcage parse "default-src 'self'"
cspcage audit "script-src 'unsafe-inline'" --json
cspcage build - <<'JSON'
{"defaultSrc":["'self'"],"objectSrc":["'none'"]}
JSON
cspcage nonce 16
printf 'console.log(1)' | cspcage hash sha256 -
```

Subcommands are `parse`, `audit`, `build`, `nonce`, and `hash`. Use `-` to read policy text, JSON, or hash content from standard input. `--json` emits machine-readable output. `--strict` makes audit warnings blocking for `audit` and `build`. Exit code 0 means pass, 1 means blocked or invalid policy, and 2 means usage or input error. Hostile input produces clean errors rather than uncaught stack traces.

## API summary

- `parseCsp(input, options)` returns a bounded structured parse or throws a typed `CspCageError`.
- `auditCsp(input, options)` returns a non-throwing security report.
- `isSafeCsp(input, options)` returns the report's boolean safe decision.
- `buildCsp(directives, options)` serializes a validated directive object.
- `createStrictCsp(options)` creates a strict-dynamic nonce-based policy.
- `generateNonce(bytes)` creates a CSPRNG nonce.
- `computeHash(content, algorithm)` creates a CSP hash body.
- `mergeCsp(inputs, options)` safely unions policies.
- `intersectCsp(inputs, options)` intersects policies.
- `diffCsp(before, after)` produces a policy diff.
- `CspCageError` exposes `code`, `detail`, and optional structured `context`.

## Security model

`cspcage` is a policy validation and generation layer. It does not replace correct per-response nonce propagation, Trusted Types adoption, XSS output encoding, secure framework templating, or browser enforcement. A nonce must be generated fresh for every response and inserted into both the header and authorized elements in the same response lifecycle.

The library never needs network access and has no runtime dependencies. Parser work is linear in the bounded input size. Token validation avoids nested quantifiers and untrusted catastrophic backtracking patterns.

## Examples

Run the examples directly.

```sh
node examples/audit-policy.mjs
node examples/build-strict-policy.mjs
node examples/merge-and-diff.mjs
```

## License

MIT. See `LICENSE`.
