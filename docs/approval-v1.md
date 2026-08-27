# Approval protocol v1

## Scope

Approval v1 is the provider-neutral, consumer-owned gate that runs after bundle preflight and
immediately before provider transport. The public runner compares opaque approval identities; it
does not decide whether an account, endpoint, persistence profile, or document kind is permitted.
Those decisions remain in the private consumer gate and its confidential snapshot.

This document specifies Phase A for one `svbench run` invocation. Every attempt, including attempts
with the same `runId` and different `attemptKey` values, executes the gate again. Suite and resume
integration is Phase B of Issue #9 and follows the suite work in Issue #5.

An optional gate is suitable only when the caller has independently decided that approval is not
required, such as a completely fictional smoke test. Optional success does not authorize a real-data
route. The runner does not infer that classification.

## Lifecycle and fail-closed rule

The order is:

```text
bundle manifest/path/schema preflight
  -> consumer requirement decision rederivation
  -> approval settings and implementation validation
  -> approval gate
  -> complete bundle verification and private input staging
  -> provider transport preparation and current-binding revalidation
  -> provider transport
  -> conditional sanitizer and policy binding
  -> schema validation and attempt publication
```

The gate therefore runs before provider invocation and before prepared-image bytes are opened or
staged for the provider. Missing required approval, an incomplete expected identity, denial,
expiration, timeout, process failure, malformed response, unexpected response field, or identity
mismatch produces no formal attempt and leaves provider invocation and image-read counts at zero.
Approval is not retried and is not a substitute for provider fallback, sanitization, business
validation, or truth comparison.

`required: false` with no gate means approval is not applied. If an optional gate is configured, it
still has the complete required identity settings, executes, and must approve. The manifest then
records `required: false` and `applied: true`. Exactly one implementation may be configured: an
in-process `ApprovalGate` or a command executable.

## Request

The gate receives one JSON object with `requestVersion: 1` and these fields:

- `provider`: safe provider ID, stable route, nullable implementation version, and nullable provider
  protocol version;
- `requested`: nullable model and effort labels and nullable positive `maxTokens`;
- `harness`: harness version and nullable source commit;
- `documentKind` and the bounded consumer-defined `phase`;
- allowlisted `provenance`: prompt version, preprocess version, and nullable consumer source commit;
- the four-field sanitizer requirement decision: version, sanitizer flag, policy flag, and reason;
- `expected`: gate ID/protocol, snapshot digest, runtime binding identity/digest, approved scope
  identity/digest, verifier identity/version, consumer source commit, and requirement decision digest.

The request never contains image bytes or paths, schema, system or instruction text, truth,
comparison policy, prior attempts, bundle root, case ID, case-input identity, sanitizer policy,
`attemptKey`, `attemptId`, or `runId`. The consumer gate must rederive its requirement decision from
consumer-owned source; it must not approve merely because the request declares permissive flags.

The approved-scope identity is opaque to this repository. A private gate may bind it to document
kind, phase, provider route, account class, endpoint class, retention, persistence, environment, and
canary policy without exposing those confidential values in the protocol.

## Response

The gate writes one strict JSON object with `responseVersion: 1` and:

- `approved`;
- gate ID and protocol version;
- snapshot digest;
- observed runtime binding identity and digest;
- observed approved-scope identity and digest;
- phase;
- verifier ID/version, nullable consumer source commit, and decision digest;
- the same four requirement-decision fields;
- optional `checkedAt` and `expiresAt` date-times;
- optional value-free safe-label `reasonCode`.

Unknown fields are rejected. Every identity and decision field is compared with the runner's
validated settings and its independently rederived consumer decision. An expired approval is a
denial. A denial or failure is returned as a stable runner code; process diagnostics and response
values are not copied into the attempt or ordinary error output.

A provider adapter may also return this response as `ProviderResponse.approval` when its private
transport contract carries a pre-approved attestation. That attestation cannot authorize itself or
replace the runner gate: a successful runner gate remains canonical, and the provider copy must
match it field-for-field. A missing provider copy is allowed; a present mismatch is
`approval_response_invalid`.

When a gate is applied, the provider must implement `prepareTransport(approval, signal)`. The runner
calls it after complete input staging and attempt claiming, immediately before `invoke()`. The
private adapter rederives its current account/session/endpoint/persistence/runtime/scope binding and
returns the current v1 attestation. The runner requires it to match the gate result exactly and
rechecks expiration after the call. A missing hook, changed receiver state, mismatch, expiry, or
timeout prevents `invoke()` and provider-input reads. The validated provider snapshots and binds
both `prepareTransport` and `invoke` to the same receiver, so changing method properties after gate
success cannot swap the approved transport implementation.

`prepareTransport()` receives only the frozen approval attestation and an abort signal. It must not
start provider transport, read staged inputs, or retain approval as authorization for a later run;
actual extraction begins only in the immediately following `invoke()`.

The runner also checks expiration immediately before `invoke()` and inside every provider-input
read callback. This covers an adapter that delays its first image read until after an approval
expires. The post-response `ProviderResponse.approval` comparison remains an optional audit and
integrity check, not the transport authorization point.

## Consumer requirement decision digest

`requirementDecisionDigest` v1 is:

```text
SHA256(
  "svbench-sanitizer-requirement-v1" ||
  LP_UTF8(requirementVerifierId) ||
  LP_UTF8(requirementVerifierVersion) ||
  OPT_UTF8(consumerSourceCommit) ||
  LP_UTF8(decimal(sanitizerRequirementVersion)) ||
  LP_UTF8(sanitizerRequired ? "true" : "false") ||
  LP_UTF8(policyRequired ? "true" : "false") ||
  LP_UTF8(sanitizerRequirementReason)
)
```

`LP_UTF8` is a four-byte big-endian byte length followed by UTF-8 bytes. `OPT_UTF8(null)` is the two
bytes `01 00`; a present value is `01 01 || LP_UTF8(value)`. The runner-created v1 decision never
uses the separate undefined encoding. The digest is lowercase hexadecimal. Digest equality does not
replace the required verifier, source-commit, decision-field, and gate-identity comparisons.

## Command transport

`createCommandApprovalGate()` and the CLI command mode use a local child process:

- executable and `argv` are passed separately with `shell: false`;
- the executable must be an absolute path;
- every invocation receives a new private mode-0700 working directory below the operating-system
  temporary directory, which is removed after the child exits;
- the child receives only environment variables named in the explicit allowlist;
- stdin is one UTF-8 JSON request followed by a newline;
- stdout must be exactly one bounded, strict UTF-8 JSON response;
- stdout and stderr share a bounded byte budget; stderr is discarded and never copied to output;
- timeout or abort terminates the child;
- no request, response, or secret-bearing temporary file is created.

The default combined output limit is 64 KiB. The public CLI accepts an explicit positive limit up to
16 MiB. The command, arguments, environment names or values, endpoint, account, secret, provider
home, and canary values are not written to the attempt manifest.

The CLI form is:

```bash
svbench run \
  --bundle <bundle-directory> \
  --provider mock \
  --approval required \
  --approval-command <executable> \
  --approval-arg <argument> \
  --approval-env <allowlisted-name> \
  --approval-gate-id <safe-label> \
  --approval-snapshot-digest <sha256> \
  --approval-runtime-identity <safe-label> \
  --approval-runtime-digest <sha256> \
  --approval-scope-identity <safe-label> \
  --approval-scope-digest <sha256> \
  --approval-phase <safe-label>
```

`--approval-arg` and `--approval-env` are repeatable. Timeout and output limit are set with
`--approval-timeout-ms` and `--approval-output-limit`. Incomplete or malformed CLI approval options
are `invalid_arguments` with exit status 2 and do not enter the runner.
The approval executable must be absolute. Any argument that represents a file path must also be
absolute; relative path arguments resolve only inside the fresh empty private working directory and
therefore fail closed rather than selecting a file from a shared temporary directory. Timeout values
are bounded to `1..2147483647` milliseconds, matching the Node.js timer range.

## Identity and attempt binding

Run identity includes whether approval is required plus the gate ID/version, snapshot digest,
runtime binding identity/digest, approved-scope identity/digest, and phase. It also includes provider
implementation/protocol versions and the complete consumer requirement decision. Changing one of
these values changes `runId`; `attemptKey` then selects one attempt instance of that stable run.

A formal attempt records `required`, `applied`, all compared approval identities, the complete
requirement attestation, and the optional bounded timestamps/reason code. When approval is not
applied, all approval metadata is null. `readAttempt()` validates this discriminator, checks the
approval decision against the stored consumer requirement, and recomputes `runId`.

Only successful attempts are published. Approval failures therefore have no manifest result or
failure record. Their public surface is the bounded stable error code such as `approval_required`,
`approval_configuration_invalid`, `approval_denied`, `approval_timeout`, or
`approval_response_invalid`.

## Security and test boundary

The protocol never carries an approval secret, exact account, exact endpoint, private path,
credential, environment value, or confidential snapshot contents. Public tests use only fictional
identities, a fake local gate, the mock provider, and synthetic bundle inputs. CI never invokes a
real model, login flow, network approval service, or confidential consumer implementation.
