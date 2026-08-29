# AGENTS.md

This repository is the public contract and execution harness for a bounded structured-vision
experiment. It is not a general execution platform.

## Active product boundary

The maintained implementation supports one case and one explicit provider invocation at a time:

- bundle v1 validation;
- immutable single-run attempt creation;
- deterministic mock and shell-free command providers;
- consumer-owned pre-transport approval;
- target-bound pre-finalization sanitization when required;
- approval-bound Codex app-server synthetic/single-run transport;
- exact value-free comparison and explicit rescoring.

A consuming application owns production prompts, extraction schemas, preprocessing, business
validation, API provider implementation, policy bodies, approval decisions, confidential corpus,
and real experiment results.

## Do not rebuild the removed platform

Do not add or restore the following without a new owner-approved Issue that demonstrates an observed
experimental need:

- suites, repeat loops, resume, retries, fallback, parallel execution, or schedulers;
- suite-run manifests, slot events, ledgers, hash chains, or stale-owner recovery;
- aggregate suite reports, dashboards, or distributed execution;
- another identity layer or publication protocol that duplicates an existing single-run contract.

Prefer deleting or simplifying an abstraction over adding a new one. A pull request adding more than
300 non-test lines, a runtime dependency, a persistent identity layer, or a new process-security
framework requires explicit owner approval before implementation.

## Cross-repository compatibility

Eldorad depends on the active single-run contracts. Its bundle integration locks bundle v1 to commit
`807d765202fa2bcb5bce84dece452c2393acf3e8`, and its experiment plan relies on the public runner,
comparison, command-provider, approval, sanitizer, and Codex app-server boundaries.

Do not remove, rename, weaken, or silently replace a public schema, wire member, identity formula,
failure code, lifecycle ordering, or absence rule used by those contracts without:

1. an explicit public Issue describing the compatibility change;
2. a coordinated Eldorad Issue and lock/update plan;
3. contract tests for both the old rejection boundary and the new behavior; and
4. owner approval before implementation.

The maintained scope and precedence rule are in `docs/scope.md`.

## Public-data rule

Only clearly synthetic, redistributable fixtures may enter Git history, Issues, pull requests, CI
artifacts, or logs.

Never commit or paste:

- a real document, screenshot, scan, PDF, truth record, model response, or mismatch value;
- a real name, amount, address, document number, transaction identifier, or confidential digest;
- an OAuth token, API key, authorization URL/code, account identifier, credential path, or full
  environment dump;
- a local absolute path or filename copied from a confidential corpus; or
- a private policy, approval snapshot, runtime audit, or real attempt/report.

Use values clearly labelled synthetic. Automated tests and GitHub Actions must not invoke a real
model, provider network, or login flow.

## Work unit and verification

Use one Issue, one branch, and one pull request. Keep the pull request inside the named Issue scope.
Change the normative document and machine-readable schema with code that changes a contract; do not
duplicate a normative table across several documents.

Before merging:

```bash
npm install
npm run verify
```

Use deterministic fake processes and complete synthetic fixtures. Optional manual smoke tests use
only synthetic images and leave output outside Git history.

## Code conventions

- Node.js ESM and strict TypeScript.
- Use explicit stable error codes at process boundaries.
- Do not put provider text, document values, secrets, digests, or absolute paths in normal errors.
- Treat unavailable metadata as unavailable; never synthesize usage, model IDs, effort, or costs.
- Reject unsafe paths, malformed bytes, and incomplete configuration before external work.
- Preserve the lifecycle order: preflight, approval, one provider invocation, required sanitizer,
  schema validation, immutable attempt, optional comparison.
- Keep `package.json` private until publication is separately designed and accepted.
