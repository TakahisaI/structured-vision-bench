# Private sanitizer command protocol v1

## Purpose and scope

Sanitizer command protocol v1 lets a consumer-owned local process inspect a provider document under
a target-bound policy before the runner can publish a formal attempt. It applies only when the
consumer sanitizer-requirement decision has both `sanitizerRequired` and `policyRequired` set to
`true`. A not-required run does not resolve policy bytes, invoke a sanitizer, or emit a sanitizer,
policy, target, or binding block.

The public harness owns wire framing and identity checks. The consumer owns the opaque policy body
and all document-specific sanitization rules. The local process transport is specified separately by
this document; app-server integration remains Issue #18, and suite/resume propagation remains Issue
#5.

## Configuration and process boundary

`createCommandSanitizer()` accepts an absolute executable, an argument vector, an environment-name
allowlist, a bounded output limit, and the expected sanitizer ID. It snapshots all configuration and
allowlisted environment values when the factory is called. The command is started with `shell:
false`, an allowlist-only environment, and a fresh empty private working directory. Environment
names must be ASCII identifiers and are unique under ASCII case folding.

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
codes/classifications, severity, a hard-gate boolean, and an optional JSON Pointer. The runner
deliberately reduces persisted finding paths to `null`; path text is never echoed in errors or
reports.

Only `sanitizedDocument` becomes eligible for schema validation and publication. The raw provider
document, raw provider serialization/digest, policy body/path, and failure details are never written
to the attempt or normal output.

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

`--sanitizer-timeout-ms` and `--sanitizer-output-limit` override bounded defaults. The policy path
is opened as a bounded, no-follow, non-blocking regular file and must not be group/other accessible
on Unix. It is local configuration and is never written to an attempt or diagnostic.

CI and automated tests use only a fake local sanitizer, fictional policies, and synthetic documents.
They never start a real provider, login flow, or consumer sanitizer.
