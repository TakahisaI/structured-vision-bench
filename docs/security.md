# Security and confidentiality boundary

## Data allowed in this repository

- Source code and public specifications.
- Fictional document images created for this project.
- Fictional truth and fictional provider responses.
- Fake protocol servers and adapters.
- Aggregate examples that cannot identify a real document or corpus.

## Data prohibited from GitHub

Do not put the following in commits, branches, Issues, pull requests, review comments, Actions logs,
or artifacts:

- real scans, photographs, screenshots, PDFs, database rows, truth data, or provider output;
- real names, addresses, amounts, account details, identity-document values, or transaction IDs;
- case IDs, filenames, local paths, or digests derived from a confidential corpus;
- OAuth credentials, API keys, authorization destinations or codes, token timestamps, account IDs,
  cookies, credential-store contents, or full environment dumps.

A digest can identify a known private file and is therefore confidential when derived from real
input. Keep real bundle manifests and reports outside Git history.

## Credential ownership

The harness does not implement login, logout, token refresh, or credential migration for Codex or
ChatGPT. It must not locate or parse an upstream credential file. A future app-server provider may
start an upstream-supported process in an environment where the operator has already logged in.

A ChatGPT subscription credential and an OpenAI Platform API key are different routes and must not
be substituted or reported as one another.

## Filesystem boundary

Bundle paths use normalized forward-slash relative paths. The validator rejects:

- absolute paths;
- empty, current-directory, or parent-directory segments;
- backslash paths;
- symbolic-link bundle roots or referenced files;
- files that resolve outside the bundle root;
- digest mismatches and missing files.

Future attempts are written to staging first and become successful output only after all validation
passes. A provider must not receive a bundle that failed preflight validation.

## Logging boundary

Errors use stable codes and bounded diagnostics. Logs must not include image bytes, full model
responses, prompt contents, secrets, or local absolute paths. A fake value in an automated test must
be visibly synthetic.

Diagnostics are capped in count and message length, with omitted entries summarized instead of
printed. A manifest key that violates `additionalProperties: false` is reported only by its parent
location and a count — an unknown key name itself is never echoed, because it can carry a local path
or secret-shaped text.

Missing usage, model, effort, or stop-reason metadata is represented as unavailable, never zero or a
guess.

## Network and CI boundary

GitHub Actions performs formatting, policy linting, type checking, unit tests, and synthetic bundle
validation. It does not call a hosted model, start a real app-server, run a login flow, or require a
secret.

Provider protocol tests use fake local processes. Optional manual smoke tests are maintainer-run,
use synthetic images only, and keep output untracked.

## Telemetry and uploads

The project has no telemetry. It does not automatically upload bundles, attempts, reports, prompts,
or diagnostics. A future remote feature requires a separate public design and explicit opt-in.

## Reporting a vulnerability

Open a public Issue only when the report contains no secret, credential, private path, or real
benchmark data. For a sensitive report, use GitHub's private vulnerability-reporting channel when
available and provide the smallest sanitized reproduction possible.
