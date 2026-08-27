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

Actual bundle reads use no-follow descriptors and recheck the canonical bundle root; hashing and
strict text validation consume the same opened bytes. Provider inputs are copied into a private
per-run staging directory after approval, with 0700 directories and 0600 files. Each provider input
is bounded to 16 MiB before it is snapshotted;
larger inputs fail with a stable runner error. Provider read callbacks are invalidated whenever
provider execution settles (including timeout), and cleanup disposes the captured snapshots, so a
late in-process provider cannot reopen staging through the request.

When sanitization is required, the runner validates the sanitizer ID, protocol version, and callable
`sanitize` method before provider invocation or input access. It binds the method and freezes one
implementation/settings snapshot for policy preflight, run identity, invocation, response identity,
and manifest creation. A missing or hostile callable accessor fails with a fixed configuration error.
Approval gate callability is validated and snapshotted before approval invocation as well.

Attempt roots must resolve outside the bundle root. The runner opens the root with no-follow directory
flags, changes permissions through that handle, and compares its device/inode with the path through
the last pre-publication validation. Before provider work, the run-identity destination is claimed
with a non-recursive exclusive `mkdir`; an existing entry is reported as `attempt_exists` and the
losing process never cleans it up or invokes the provider. The winning process places a private
owner-nonce marker in the claimed directory, writes and validates `document.json`, and writes the
complete `attempt.json.pending` into a private same-filesystem `<attempt-root>/.claim-<nonce>/`
staging directory owned by that run, without a shared staging-root lifecycle. The owner marker is
removed only immediately before final publication. Document and manifest publication use no-replace
hard links from their complete pending files. The final
manifest link is the sole visibility point for a complete manifest: it changes the run directory in
one syscall from `document.json` to the exact `attempt.json` plus `document.json` shape. Removing
the external pending source is post-publication best effort and cannot turn a published attempt into
a failure.
Cleanup of unpublished final-claim files is permitted only with an explicit root stability guard,
only for the claim owner, only for files owned by that claim, and only while the final manifest is
absent; it uses non-recursive directory removal. The separate external pending source may be removed
after publication only by its recorded file identity, as best-effort staging cleanup.
The reader recognizes only a directory containing the final `attempt.json` and `document.json`;
directories containing only `document.json`, the owner marker, or no manifest are rejected and are
not formal attempts. The
Node-only contract prevents competing harness writers from replacing a claimed run directory;
protection against an adversarial same-UID process replacing the attempt root in the final path-based
syscall window is outside this portable harness threat model. The reader uses no-follow reads,
rejects non-private modes, symlinks, non-regular files, size violations, and any directory entry
other than `attempt.json` and `document.json`.

A provider must not receive a bundle that failed preflight validation, and a provider-facing read
must not reopen the mutable source bundle after staging.

If sanitization is required, all expected sanitizer ID/protocol, policy version/digest, case-input
identity version/digest, and policy-binding digest fields are mandatory. Missing or mismatched
expectations fail before provider input staging.

## Logging boundary

Errors use stable codes and bounded diagnostics. Logs must not include image bytes, full model
responses, prompt contents, secrets, or local absolute paths. A fake value in an automated test must
be visibly synthetic. The security contract is: "no secrets/real providers/network in CI, explicit stable error codes, bounded diagnostics, no absolute paths/raw provider values in outputs."

Diagnostics are capped in count and message length, with omitted entries summarized instead of
printed. A manifest key that violates `additionalProperties: false` is reported only by its parent
location and a count — an unknown key name itself is never echoed, because it can carry a local path
or secret-shaped text.

Missing usage, model, effort, or stop-reason metadata is represented as unavailable, never zero or a
request-derived guess. Provider metadata and sanitizer findings are accepted only as bounded safe
labels; persisted finding paths are null. A successful attempt contains only `attempt.json` and the
formal `document.json` (the strict canonical provider document when sanitization is not required,
otherwise sanitizer output). It never stores raw provider serialization, raw prompt/image contents,
sanitizer policy contents/paths, endpoint/account identifiers, or failure tracebacks. When the
consumer decision says sanitization is not required, sanitizer/policy/target-binding manifest blocks
are absent rather than null-filled. Attempt readers reject symlinks, unknown fields or entries,
non-private modes, digest changes, identity changes, and policy-binding changes.

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
