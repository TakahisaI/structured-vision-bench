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

The Codex app-server protocol never reads either credential form. Issue #25 passes only explicitly
allowlisted environment entries to the absolute executable and uses a fresh empty workspace. Both
layers treat ephemeral thread mode only as data minimization rather than proof of non-persistence.
The complete fixed-protocol boundary is in
[`docs/codex-app-server-transport-v1.md`](codex-app-server-transport-v1.md).

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
per-attempt-invocation staging directory after approval, with 0700 directories and 0600 files. Each provider input
is bounded to 16 MiB before it is snapshotted;
larger inputs fail with a stable runner error. Provider read callbacks are invalidated whenever
provider execution settles (including timeout), and cleanup disposes the captured snapshots, so a
late in-process provider cannot reopen staging through the request.

When sanitization is required, the runner validates the sanitizer ID, protocol version, and callable
`sanitize` method before provider invocation or input access. It binds the method and freezes one
implementation/settings snapshot for policy preflight, run identity, invocation, response identity,
and manifest creation. A missing or hostile callable accessor fails with a fixed configuration error.
Approval gate callability is validated, bound, and snapshotted before approval invocation as well.
Command gates require an absolute executable and use an argument vector with `shell: false`. Every
invocation runs in a fresh private mode-0700 directory below the OS temporary directory and receives
no inherited environment except names in an explicit allowlist. Path-valued arguments must be
absolute; relative paths resolve only inside the fresh empty directory and fail closed. Stdin carries
one request; strict JSON stdout and discarded stderr share a bounded byte budget. Timeouts abort and
terminate the child. The private directory is removed after exit. The adapter creates no protocol
file and never persists its command, arguments, environment names/values, response diagnostics, or
private identities beyond the allowlisted attempt fields.

Approval executes after bundle manifest/path/schema preflight and requirement-decision rederivation,
but before complete provider-input verification, staging, provider process invocation, or image read.
The request excludes image, schema, prompts, truth, comparison, prior attempts, policy, bundle root,
case-input identity, and attempt identities. Every expected gate, snapshot, runtime, scope, phase,
verifier, source, digest, and four-field decision value is compared. Missing required approval,
denial, expiration, timeout, process failure, malformed or extra response data, and any mismatch fail
closed with no provider access or formal attempt. A provider-carried approval attestation cannot
replace this runner gate and, when present, must match its successful response exactly. The full
boundary is in [`docs/approval-v1.md`](approval-v1.md).

The private command sanitizer applies the corresponding post-provider boundary without
materializing its raw document or policy as files. It uses `shell: false`, an allowlist-only
environment, and a fresh private mode-0700 empty working directory. Strict request/response identity
checks bind the current case input, policy target, exact policy identity, and policy binding. Stdout
and stderr share a bound; stderr is discarded; timeout and abort wait for the initial process group
and working-directory cleanup. See [`docs/sanitizer-v1.md`](sanitizer-v1.md).

An applied gate also requires the private provider adapter to implement `prepareTransport()`. That
hook rederives current account/session/endpoint/persistence/runtime/scope state after staging and
immediately before provider invocation. Its attestation must exactly match the gate result. Approval
expiry is checked after this hook, immediately before invocation, and inside every provider-input
callback. Thus a receiver-state change or an adapter that delays image access past expiry cannot use
the earlier gate result. Provider, approval, and sanitizer timeout values are all bounded to Node's
maximum timer delay of 2,147,483,647 milliseconds.

The Phase A command provider follows the same shell-free configuration boundary and accepts only
policy-not-required runs and rejects required sanitizer or policy flags before starting a child.
For approved runs, the private adapter reattests its current transport binding without extraction
inputs at the runner hook and again after callback hashing inside the extraction process. The runner
validates that inline response before creating the five-file request directory, then releases its
path to the same live process over stdin. The adapter must keep the attested binding valid through
transport. Direct-child exit is monitored separately from stdio close and raced through
materialization and path delivery. An observed exit stops remaining staging work, prevents a new
path write, waits for in-flight filesystem settlement, and forces complete private cleanup and
failure. Portable Node.js cannot make child liveness atomic with path materialization; the
consumer-owned adapter boundary therefore includes conforming descendants, which must not scan the
temporary root or inherit/intercept control stdin, request paths, or request descriptors. The
provider then copies the four exact
verified provider inputs plus one bounded manifest into a fresh mode-0700 directory using mode-0600
files. The schema remains byte-exact and is reparsed before spawn. The request directory contains no truth,
comparison, prior-attempt, policy, credential, or original corpus path. The child receives an
allowlist-only environment plus a reserved operation variable and uses a separate fresh empty
directory as `cwd`; relative arguments therefore cannot resolve bundle-controlled inputs. For an
approved run the request path is absent from the spawn environment and is sent only after inline
reattestation; an unapproved run receives it in the reserved request-directory variable.
Allowlist names are unique case-insensitively and cannot use any case variant of a reserved name.
The public provider boundary rejects denied and expired approvals before reading any input callback.
It snapshots the complete provider request and adapter context before any callback, including
callbacks, parsed schema, requested settings, identities, digests, provenance, phase, approval, and
the consumer sanitizer-requirement decision. The decision digest is recomputed from that immutable
snapshot, and later mutation of caller-owned objects cannot change the released request or response
checks. Approval expiry is checked before and after every callback so expiry during one read stops
all later input access and zeroes any returned binary buffer. Callback Promises are raced with the
invocation AbortSignal; abort settles without waiting for a non-cooperative callback, while late
binary results are zeroed and late rejections are observed.
Stdout and stderr have a shared configured bound and are never echoed. Response phase/provider/case-input/requirement/approval
identities and requested settings are exact-match checked. Cancellation or overflow kills the child
process group, timeouts await command cleanup, callback-returned binary buffers and private input
copies are zeroed, and cleanup failure is fail-closed. Adapters that detach or daemonize descendants
outside that group are non-conforming and outside the portable cleanup guarantee; they must not
transfer request data or descriptors to such descendants. See
[`docs/command-provider-v1.md`](command-provider-v1.md).

The sanitizer policy reader opens only bounded private regular files with no-follow and non-blocking
semantics. It fails closed on Windows before opening the configured path because Node's portable
flags do not enforce those semantics for Windows reparse points and special device or pipe paths.
Windows sanitizer-policy support therefore requires a future native secure-open implementation;
digest binding alone does not replace this path-level boundary.

Attempt roots must resolve outside the bundle root. The runner opens the root with no-follow directory
flags, changes permissions through that handle, and compares its device/inode with the path through
the last pre-publication validation. Before provider work, the attempt-identity destination is claimed
with a non-recursive exclusive `mkdir`; an existing entry is reported as `attempt_exists` and the
losing process never cleans it up or invokes the provider. The winning process places a private
owner-nonce marker in the claimed directory, writes and validates `document.json`, and writes the
complete `attempt.json.pending` into a private same-filesystem `<attempt-root>/.claim-<nonce>/`
staging directory owned by that attempt claim, without a shared staging-root lifecycle between
attempt invocations. The owner marker is removed only immediately before final publication. Document
and manifest publication use no-replace
hard links from their complete pending files. The final
manifest link is the sole visibility point for a complete manifest: it changes the attempt directory in
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
Node-only contract prevents competing harness writers from replacing a claimed attempt directory;
protection against an adversarial same-UID process replacing the attempt root in the final path-based
syscall window is outside this portable harness threat model. The reader uses no-follow reads,
rejects non-private modes, symlinks, non-regular files, size violations, and any directory entry
other than `attempt.json` and `document.json`. It recomputes the attempt ID from the stored run ID and
caller key and requires the directory basename to equal that ID. Attempt keys are bounded safe labels;
the key and derived attempt/run IDs are not exposed to provider, approval, or sanitizer requests.

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

Comparison output contains aggregate counts, stable warning codes, and declaration positions only;
it does not contain truth values, extracted values, case IDs, comparison pointers, local paths, or
raw sanitizer paths. Normal comparison requires the exact execution bundle digest. Explicit
rescoring is separately requested and still fixes the case, provenance, four provider inputs,
formal-document digest, and sanitizer identity. Comparison errors never echo mismatched values or
digests.

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
