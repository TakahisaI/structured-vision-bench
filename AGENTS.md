# AGENTS.md

This repository is a small experiment harness, not a production execution platform.

## Fixed scope

Keep the active implementation limited to one case, one provider invocation, schema-subset
validation, and exact comparison. The repository must remain understandable in one short reading.

Do not add any of the following without a new owner-approved Issue that explains observed need:

- suites, repeats, resume, retries, parallel execution, or schedulers;
- run/attempt/artifact identities, hash chains, ledgers, or atomic publication systems;
- approval gates, sanitizer/policy protocols, or provider-specific security frameworks;
- credential/login management, telemetry, uploads, or production corpus logic.

Prefer deleting or simplifying code over introducing another abstraction. A pull request adding more
than 300 non-test lines requires explicit owner approval before implementation. Runtime dependencies
also require explicit approval.

## Public data

Only clearly synthetic, redistributable fixtures may enter Git history, Issues, pull requests, CI
artifacts, or logs. Never commit real documents, truth records, model outputs, credentials, account
identifiers, private paths, or confidential filenames.

## Verification

```bash
npm test
```

Tests and CI must use only synthetic files and local mock processes. No network, real model, or login
flow is allowed in automated verification.
