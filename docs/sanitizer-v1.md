# Private sanitizer command protocol v1

## Purpose and scope

Sanitizer command protocol v1 lets a consumer-owned local process inspect a provider document under
a target-bound policy before the runner can publish a formal attempt. It applies only when the
consumer sanitizer-requirement decision has both `sanitizerRequired` and `policyRequired` set to
`true`. A not-required run does not resolve policy bytes, invoke a sanitizer, or emit a sanitizer,
policy, target, or binding block.

The public harness owns wire framing and identity checks. The consumer owns the opaque policy body
and all document-specific sanitization rules. The local process transport is specified separately by
this document. Each `svbench run` applies and records this boundary independently; the public
harness does not propagate sanitizer state through suite or resume orchestration.

## Configuration and process boundary

`createCommandSanitizer()` accepts an absolute executable, an argument vector, an environment-name
allowlist, a bounded output limit, the expected sanitizer ID, and an optional allowlist of stable
failure codes. It snapshots all configuration and allowlisted environment values when the factory
is called. Failure codes are case-sensitive ASCII safe labels, unique, and limited to 100 entries.
The command is started with `shell: false`, an allowlist-only environment, and a fresh empty private
working directory. Environment names must be ASCII identifiers and are unique under ASCII case
folding.

The executable is run configuration, never bundle content. The runner validates and binds the
sanitizer ID, protocol version, and callable method before provider invocation.

## Request framing

The private boundary receives exactly one strict UTF-8 JSON object followed by LF and EOF. The
top-level object has exactly these fields:

```json
{
  "requestVersion": 1,
  "caseInputIdentity": {},
  "documentKind": "synthetic_document",
  "policyEnvelope": {},
  "policyVersion": 1,
  "policyDigest": "<lowercase-sha256>",
  "policyBindingDigest": "<lowercase-sha256>",
  "document": {},
  "provider": {},
  "provenance": {}
}
```

`caseInputIdentity`, `provider`, and `provenance` use the corresponding runner v1 structures.
`policyEnvelope` is a normalized snapshot of the preflighted envelope, including its opaque `policy`
object. `policyDigest` identifies the exact source bytes read by the runner; JSON framing necessarily
re-encodes the parsed envelope, so the receiver must not claim to recompute that exact-byte digest
from the framed object. It verifies the envelope target, current case-input identity, declared policy
identity, and policy-binding digest before applying private rules.

The request excludes truth, comparison policy/results, prior attempts, bundle/attempt roots,
approval data, attempt keys, attempt IDs, and run IDs.

## Response framing

The boundary returns exactly one strict UTF-8 JSON object and no other bytes. The response has these
fields; `findings` is the only optional field:

```json
{
  "responseVersion": 1,
  "sanitizedDocument": {},
  "sanitizerId": "synthetic-sanitizer",
  "protocolVersion": 1,
  "policyVersion": 1,
  "policyDigest": "<lowercase-sha256>",
  "caseInputIdentityVersion": 1,
  "caseInputIdentityDigest": "<lowercase-sha256>",
  "policyTargetIdentityDigest": "<lowercase-sha256>",
  "policyBindingDigest": "<lowercase-sha256>",
  "findings": []
}
```

Unknown or missing fields, duplicate JSON members, invalid UTF-8, trailing payloads, identity
mismatch, and malformed findings fail closed. Findings contain only bounded safe
codes/classifications, severity, a hard-gate boolean, and an optional JSON Pointer. A non-null path
is persisted only when it matches a consumer-owned `allowedFindingPathPatterns` entry. A pattern may
be an exact bounded RFC 6901 pointer or contain one full-segment `*`. A response path is always
concrete and never contains a full-segment wildcard. The wildcard matches exactly one canonical
array index segment only when the corresponding pre-sanitization location is an actual array and the
index is in range. It never authorizes a numeric object member, leading-zero index, out-of-range
index, or multiple path segments. `null` is always
permitted. Missing coverage, unsafe pointers, and malformed patterns fail closed without echoing the
path.

A successful sanitizer manifest records the canonical sorted patterns, allowlist version, and
domain-separated allowlist digest. The run sanitizer binding commits both that digest and the
target-bound policy binding digest. `readAttempt()` recomputes these commitments and requires every
non-null finding path to match the committed exact or single-wildcard pattern shape. The reader does
not rediscover the confidential pre-sanitization document; the runner performs that structural check
before publication. Changing the allowlist and its digest changes the recomputed run identity. This
metadata contains consumer-authorized patterns and concrete value-free finding paths, never a
document value. After sanitization, artifact identity v1 additionally commits the
formal-document digest, sanitizer identity/binding, and ordered canonical
`(code, severity, classification, hardGate, path)` tuples. The manifest records that identity, while
the digest-named artifact child directory supplies the external anchor used by `readAttempt()`.
Coordinated changes to a finding tuple and the manifest identity are rejected while the child
basename remains fixed.

Programmatic and CLI allowlist patterns must contain only Unicode scalar values. An isolated UTF-16
surrogate is rejected during configuration preflight, before approval, provider input access, or
provider invocation, so UTF-8 replacement cannot collapse distinct settings into one digest.

Only `sanitizedDocument` becomes eligible for schema validation and publication. The raw provider
document, raw provider serialization/digest, policy body/path, and failure details are never written
to the attempt or normal output.

## Failure framing

A conforming stable failure uses a non-zero exit status, writes nothing to stderr, and writes exactly
one strict UTF-8 JSON object to stdout with no leading/trailing whitespace, LF, or trailing bytes:

```json
{"failureVersion":1,"code":"synthetic_policy_blocked"}
```

The envelope is independently limited to 256 bytes and has exactly the two fields shown. Message,
path, raw value, digest, and any extra or duplicate member are prohibited. The code must exactly
match a factory-snapshotted `allowedFailureCodes` entry. Only then does the command adapter create a
one-shot, module-private failure capability bound to that exact sanitizer instance. The runner
converts that capability to a fixed-message, empty-details `RunnerError` whose code is the same
allowlisted value. Arbitrary sanitizer exceptions, error properties, or `RunnerError` instances do
not possess this capability and become generic `sanitizer_failed`.

Empty or malformed output, invalid UTF-8, unknown or unsafe codes, wrong versions, oversized
envelopes, zero exits carrying a failure envelope, non-zero exits carrying a success response,
stderr output, signal exits, overflow, abort, and timeout never carry a consumer code. They retain
the existing generic classification; timeout remains `sanitizer_timeout`. A failed run may use the
runner's pre-publication claim and private staging during execution, but cleanup completes before the
error is returned and leaves no formal attempt or staging artifact.

## Cancellation, limits, and cleanup

Stdout and stderr share one configured byte budget; stderr is counted and discarded. Timeout or
abort terminates the initially spawned process group and waits for child settlement and private
working-directory cleanup before the sanitizer Promise settles. On Windows the implementation uses
`taskkill /t` when available. Detached or daemonized descendants outside the initial process group
are non-conforming and must not receive the request or inherited descriptors.

Serialized request and collected output buffers are zeroed on all paths as best-effort memory
hygiene. JavaScript values and strings cannot be promised deterministic erasure, so v1 does not
claim an OS memory-sandbox boundary. The consumer-owned sanitizer and its conforming descendants
are one trusted local invocation boundary.

## CLI

`svbench run --sanitizer required` requires the command, sanitizer ID, policy file, exact policy
identity, expected case-input identity, policy-binding digest, and consumer requirement identity.
The requirement-decision digest is recomputed from the supplied verifier ID/version, source commit,
required flags, and reason before runner execution. Optional timeout, output limit, argv, and
environment-name options use the same bounds as the programmatic factory. Invalid CLI configuration
is `invalid_arguments`; a policy read or runtime sanitizer failure is a classified runner failure and
creates no formal attempt.

The required options are:

- `--sanitizer-command`, repeatable `--sanitizer-arg`, and repeatable `--sanitizer-env`;
- `--sanitizer-id` (protocol version is fixed to v1);
- `--sanitizer-policy`, `--sanitizer-policy-version`, and `--sanitizer-policy-digest`;
- `--sanitizer-case-input-digest` and `--sanitizer-binding-digest`;
- `--requirement-verifier-id`, `--requirement-verifier-version`, `--requirement-reason`, and
  `--requirement-decision-digest`;
- optional `--requirement-consumer-source-commit` when the decision has one.
- repeatable `--sanitizer-finding-path` entries for non-null finding paths the consumer permits the
  runner to persist; omitting it permits only `null` paths.
- optional repeatable `--sanitizer-failure-code` entries for stable codes accepted from the strict
  non-zero failure envelope; omitting it permits no propagated consumer failure code.

`--sanitizer-timeout-ms` and `--sanitizer-output-limit` override bounded defaults. The policy path
is opened as a bounded, no-follow, non-blocking regular file and must not be group/other accessible
on supported Unix platforms. Windows is fail-closed for sanitizer policy reads because Node's
portable open flags do not provide the required no-follow and non-blocking guarantees there. A
future Windows implementation requires a native reparse-point-safe, device-namespace-safe open
boundary before this restriction can be removed. The path is local configuration and is never
written to an attempt or diagnostic.

CI and automated tests use only a fake local sanitizer, fictional policies, and synthetic documents.
They never start a real provider, login flow, or consumer sanitizer.
