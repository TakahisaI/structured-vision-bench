# AGENTS.md

This repository is public. Every contributor and coding agent must preserve the boundary below.

## Product boundary

`structured-vision-bench` owns provider-neutral benchmark contracts, runner infrastructure,
comparison logic, and reports. A consuming application owns its production prompt, extraction
schema, preprocessing, business validation, API provider, and confidential benchmark corpus.

Do not copy application-specific production logic into this repository merely to make an
integration easier.

## Public-data rule

Only fictional, redistributable fixtures may enter Git history, Issues, pull requests, Actions
artifacts, or logs.

Never commit or paste:

- a real document, screenshot, scan, PDF, truth record, model response, or mismatch value;
- a real name, amount, address, document number, transaction identifier, or file hash;
- an OAuth token, API key, authorization URL or code, account identifier, credential path, or full
  environment dump;
- a local absolute path or a filename copied from a confidential corpus.

Use values clearly labelled synthetic. If a test needs a binary document, generate it from fictional
content and keep the generator or provenance understandable.

## Provider and CI rule

GitHub Actions and automated tests must not invoke a real model or login flow. Use deterministic
mock processes and synthetic inputs.

Provider implementations must not read, copy, migrate, or print a Codex or ChatGPT credential file.
They may use only an upstream-supported, already logged-in process boundary. Tool requests, shell
execution, workspace reads, or approval requests are not valid extraction output unless a future
public specification explicitly changes that rule.

The project has no telemetry and does not upload bundles, attempts, or reports.

## Work unit

Use one Issue, one branch, and one pull request. The Issue body is the current work instruction;
comments retain discussion and history. Keep each pull request inside the named Issue scope.

Before merging:

```bash
npm install
npm run verify
```

Do not use real providers to prove an implementation PR. Optional manual smoke tests use only
synthetic images and leave their output outside Git history.

## Source-of-truth documents

- `docs/architecture.md`: component and trust boundaries.
- `docs/security.md`: prohibited data, credentials, logging, filesystem, and CI rules.
- `docs/bundle-v1.md`: current bundle v1 contract and lifecycle.
- `schemas/bundle-v1.schema.json`: machine-readable manifest schema.
- GitHub Issues: plans, sequencing, and unfinished work.

Change the relevant specification before or with code that changes its contract. Do not duplicate a
normative table in several documents.

## Code conventions

- Node.js ESM and strict TypeScript.
- Use explicit error codes at process boundaries.
- Do not place unbounded provider text, image content, secrets, or absolute paths in errors.
- Treat unavailable metadata as unavailable; never synthesize token usage, model IDs, effort, or
  costs.
- Reject unsafe paths and partial output before starting external work.
- Tests use Node's built-in test runner and complete synthetic fixtures.
- Keep `package.json` private until publication is separately designed and accepted.
