# Changelog

All notable changes to this project are documented in this file.

The format follows Keep a Changelog concepts, and this project uses semantic versioning.

## [1.0.0] - 2026-11-27

### Added

- Strict bounded CSP Level 3 parser with multi-policy support.
- Duplicate directive detection for first-directive-wins shadowing protection.
- Structured directive, host, scheme, keyword, nonce, and hash representation.
- Real-world XSS-bypass auditor with strict-CSP scoring and grading.
- Detection for unsafe inline and eval execution, CDN script gadgets, JSONP and AngularJS bypass hosts, wildcard and insecure schemes, missing object and base-uri protection, clickjacking gaps, weak nonces, invalid hashes, and reporting endpoint hazards.
- Safe deterministic CSP header builder with injection and prototype-pollution defenses.
- Strict-dynamic policy preset.
- CSPRNG nonce generation and SHA-256, SHA-384, and SHA-512 CSP hash generation.
- Safe policy merging, intersection, and diffing.
- CLI with parse, audit, build, nonce, and hash subcommands.
- Native ESM, generated CommonJS, and strict TypeScript declarations.
- Comprehensive Node test suite, examples, package checks, and eight-configuration CI matrix.
