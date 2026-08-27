# Command provider protocol v1

## Scope

Command provider protocol v1 is the Phase A single-run process boundary from Issue #6. It lets the
public runner invoke a consumer-owned adapter without importing private provider or business code.
The adapter process is local invocation infrastructure, not a hosted-model payload.

Phase A accepts only runs whose consumer-attested sanitizer and policy requirements are both false.
Target-bound pre-sanitized responses are tracked by Issue #18 using sanitizer protocol v1. Suite, repeat, and resume
integration are Phase C work after Issue #5. A Phase A adapter must not turn missing Phase B fields
into empty strings, zeroes, null-filled blocks, or dummy digests.

## Configuration and identity

The operator supplies these values outside the bundle:

- an absolute executable path and an argument vector;
- environment-variable names to copy from the parent environment;
- a bounded stdout/stderr byte limit and runner provider timeout;
- provider ID, stable route, implementation version, and the run's execution phase.

Provider ID, route, implementation version, the fixed protocol label `command-provider-v1`, and
phase are safe labels of 1 to 64 ASCII characters. Phase is part of `runId`, is recorded as
`run.phase`, and must match an applied approval phase. Changing phase creates a different run
identity. Phase A intentionally changes the development-time attempt-v1 reader contract: artifacts
without `run.phase` are not accepted by the current reader.

The factory validates and snapshots its executable, arguments, environment allowlist, byte limit,
and provider identity before returning a provider. The runner snapshots phase separately as a run
setting. Later mutations of the source configuration do not
change an invocation.

## Approval transport revalidation

When approval is applied, the command provider invokes the configured private adapter in a
pre-transport operation before any extraction input is exposed. The child receives a single JSON
object on stdin containing `requestVersion: 1`, `operation: "prepareTransport"`, and the exact
approval response. `SVBENCH_COMMAND_OPERATION` is `prepare-transport`; the request-directory
variable is absent. The child must rederive its current account, session, endpoint, persistence,
runtime, and scope binding and write the exact current approval response to stdout. Echoing the
request without that private rederivation is not a conforming adapter.

The runner-facing `prepareTransport()` hook performs this check. The provider later reads and hashes
the revocable callbacks into its own memory and starts the extraction adapter in a fresh empty
working directory without a request-directory variable. It sends the same `prepareTransport`
object as the first stdin line. The adapter rederives its current binding and returns the exact
approval as one stdout line, but remains alive. Only after the runner validates that line does it
create and materialize the five-file request directory. It then sends a second stdin line containing
`requestVersion: 1`, `operation: "invoke"`, and the absolute `requestDirectory`. That same adapter
process performs extraction. It must hold or revalidate the attested account, session, endpoint,
persistence, runtime, and scope binding through the extraction transport and fail if the binding
changes. The inline check and extraction use one snapshot of the allowlisted environment. A
mismatch, expiration, process failure, or unexpected file in the empty working directory prevents
request release and extraction.

The provider tracks direct-child `exit` separately from stdio `close`. If exit is observed before
materialization begins, no request root is created. If exit is observed while materialization is in
flight, every remaining step fails its liveness guard, the provider waits for already-started
filesystem work to settle, does not begin a new path write, and removes its private roots before
returning failure. Exit is also raced with the second stdin write. Because child liveness and a
multi-syscall path materialization cannot be made atomic in portable Node.js, this contract does not
claim that a private file can never exist transiently across an unobserved exit race.

The consumer-owned adapter and its descendants are one trusted local invocation boundary. A
conforming direct child remains alive from inline attestation through response completion and does
not let descendants scan the temporary root, inherit or intercept control stdin, receive the
request path or open request descriptors, or continue extraction after the direct child exits.
Those behaviors require an OS sandbox or a future non-path protocol and are outside v1.

Both checks reject `sanitizerRequired: true` or `policyRequired: true` before starting a child.
Those runs require Phase B and never start a Phase A command process.
The public provider `invoke()` boundary also rejects a denied or expired approval before calling any
input callback, even if a caller bypasses the runner and omits the `prepareTransport()` hook. It
reads the complete provider request and adapter context once into one immutable validated snapshot
before calling any input callback. This includes the callback functions, media types, parsed schema,
requested settings, phase, bundle/case/input identities and digests, provenance, sanitizer decision,
and approval. The sanitizer decision digest is recomputed while taking the snapshot. The same
snapshot is used for Phase A admission, callback reads, digest checks, approval binding, the
manifest, inline handshake, and final response validation; later source-object mutation has no
effect. Approval activity is rechecked immediately before and after each callback read; expiry
during one callback zeroes any returned binary buffer and prevents every later callback. Each
callback Promise is also raced against the invocation AbortSignal, so cancellation settles the
public invocation without waiting for a non-cooperative callback. A binary buffer returned after
cancellation is zeroed asynchronously, and a late callback rejection is observed and discarded.

## Private request directory

After approval, complete bundle validation, runner input staging, and attempt claiming, the command
provider reads the four revocable provider callbacks. It verifies their exact SHA-256 digests and
creates a fresh mode-0700 directory below the operating-system temporary directory. Every file is a
regular mode-0600 file. The request directory contains exactly:

```text
image.input
schema.json
system.txt
instruction.txt
request.json
```

The schema file contains the exact verified bundle bytes, not a reserialized substitute. The
provider reparses it with the strict JSON contract and requires it to equal the runner's parsed
schema. The other three files likewise contain the exact verified provider inputs. Their fixed
relative names are protocol names and disclose no confidential corpus filename or path.

The extraction process is spawned with `shell: false`, the configured argument vector, and a
separate fresh, empty, mode-0700 directory as `cwd`. The request root is an independently randomized
temporary-directory entry, not a fixed-name `../request` sibling. For an approved run,
`SVBENCH_COMMAND_OPERATION` is `invoke`, the request-directory variable is absent, and the absolute
path is released only in the second stdin line after inline reattestation. For a run without
approval, the process starts after materialization and receives the path in
`SVBENCH_COMMAND_REQUEST_DIRECTORY`. The child receives no other inherited environment except
explicitly allowlisted names, and the reserved names cannot be
allowlisted or overridden. Environment allowlist names must also be unique under ASCII
case-folding, and mixed-case forms of either reserved name are rejected on every platform. The
executable must be absolute. A script or other path-valued argument
must also be absolute because relative arguments resolve inside the empty working directory, never
against bundle-controlled input files or a shared temporary directory.

`request.json` is a single strict JSON object with this shape:

```text
requestVersion: 1
phase
provider: id, route, implementationVersion, protocolVersion
bundle: version, manifestDigest
case: id, documentKind
caseInputIdentity: identityVersion, caseId, documentKind, preparedImage, digest
inputs: image/schema/system/instruction relative path, mediaType, sha256
requested: model, effort, maxTokens
provenance: harness/prompt/preprocess versions and optional commits
sanitizerRequirement: complete consumer decision and verifier identity
approval: exact successful approval response, or null
```

This local manifest contains no truth, comparison declaration/result, policy content/path, prior
attempt, attempt key, attempt ID, run ID, bundle root, credential, endpoint, or account. A private
adapter may use local provenance and binding metadata for validation. If it creates a hosted-model
request, that request may contain only the four extraction inputs and requested model, effort, and
max tokens. Local phase, bundle/case provenance, case-input identity, approval, and sanitizer
requirement metadata must not be forwarded to the hosted model.

## Response

For a run without approval, stdout in its entirety must contain exactly one strict UTF-8 JSON
object. For an approved run, stdout contains exactly two payloads: the first newline-terminated line
is the transport attestation described above, and all bytes after that line through EOF are exactly
one strict UTF-8 response JSON object. No bytes other than the attestation line and final response
are allowed. The final response has this shape:

```text
responseVersion: 1
phase
provider: id, route, implementationVersion, protocolVersion
requested: model, effort, maxTokens
caseInputIdentity: identityVersion, digest
sanitizerRequirement: complete consumer decision and verifier identity
approval: exact request approval response, or null
document: structured JSON document
responded: model, effort, usage, stopReason
```

All listed fields are required and unknown fields are rejected. Provider identity, phase, requested
settings, case-input digest, sanitizer decision, and approval are compared to the runner-owned request. An
applied approval cannot be omitted or replaced by a process's self-assertion. Metadata that the
adapter did not obtain remains null or unavailable; requested values must not be copied into
responded metadata merely to fill a field.

Phase A stdout may carry the parsed structured document for a policy-not-required run. It must never
carry the raw upstream HTTP/app-server body, raw document digest, exact endpoint/account, policy,
credential, or unbounded diagnostic. A policy-required run is outside Phase A and must not start the
command process.

## Failure and cleanup

The provider fails closed on an invalid configuration, approval mismatch, expired approval callback,
input digest mismatch, private-directory or file-mode failure, process error, non-zero exit, signal,
timeout, oversized stdout or stderr, invalid UTF-8/JSON, duplicate JSON member, unknown response
field, identity mismatch, invalid metadata, or cleanup failure. No formal attempt is published.

The initially spawned child process group is terminated on cancellation or byte-limit failure. The
runner waits for command-provider process settlement and private cleanup before returning a timeout.
A conforming adapter must not detach, daemonize, or move descendants into another process group or
session, and must not transfer request data or open request descriptors to such a descendant.
Portable Node.js process-group termination cannot contain a deliberately detached descendant; such
an adapter is outside this protocol and cleanup guarantee. The provider zeroes callback-returned
binary input buffers and its private input copies, and recursively removes only its separate fresh
request and working roots.
Public errors are fixed and bounded; child stderr, response text,
temporary paths, executable, arguments, and environment values are not returned or persisted.

## CI and fixtures

Automated tests use only the fictional local fake adapter and synthetic bundle. CI never invokes a
real provider, network request, login flow, credential file, or private consumer adapter.
