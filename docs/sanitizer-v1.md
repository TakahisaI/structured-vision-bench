# Private sanitizer command protocol v1

## Purpose and scope

Sanitizer command protocol v1 lets a consumer-owned local process inspect a provider document under
a target-bound policy before the runner can publish a formal attempt. It applies only when the
consumer sanitizer-requirement decision has both `sanitizerRequired` and `policyRequired` set to
`true`. A not-required run does not resolve policy bytes, invoke a sanitizer, or emit a sanitizer,
policy, target, or binding block.

The public harness owns wire framing and identity checks. The consumer owns the opaque policy body
and all document-specific sanitization rules. The local process transport is specified separately by
Issue #23; app-server integration remains Issue #18, and suite/resume propagation remains Issue #5.

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

CI and automated tests use only fictional policies and synthetic documents. They never start a real
provider, login flow, or consumer sanitizer.
