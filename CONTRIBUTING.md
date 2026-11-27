# Contributing

Contributions are welcome for parser correctness, CSP Level 3 coverage, audit rules, tests, documentation clarity, packaging, and platform compatibility.

## Development setup

Node.js 18 or newer is required. There are no runtime or development package dependencies to install for the core test suite. A TypeScript executable is used when available for declaration verification; otherwise the type check script uses npm execution.

## Required checks

Run every check before submitting a change.

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
for example in examples/*.mjs; do node "$example"; done
npm pack --dry-run
node scripts/check-pack.mjs
```

The generated CommonJS file is committed. Run `node scripts/build-cjs.mjs` after changing `src/*.mjs`, then verify it with `node scripts/build-cjs.mjs --check`.

## Rules for changes

- Keep runtime dependencies at zero.
- Preserve Node.js 18 compatibility.
- Add regression tests for every parser or auditor change.
- Keep input bounds explicit and test hostile inputs.
- Do not weaken `'none'` merging or unsafe-inline merge protection without a deliberate API change and review.
- Do not include secrets, personal data, real private endpoints, or local machine paths in tests or documentation.
- Use ASCII hyphen characters rather than typographic dashes.
- Keep generated files byte-for-byte reproducible with LF line endings.

## Commit and pull request expectations

Small, focused commits are preferred. Pull requests should explain the security impact, list the checks run, and include before and after behavior for parser or audit changes.
