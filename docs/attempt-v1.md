# Attempt v1 and runner

## Scope

Issue #2 adds a provider-neutral single-case runner. It consumes one already validated bundle and
writes one successful attempt outside the bundle. It does not own a production prompt, business
schema, preprocessing, provider credentials, comparison logic, repeat policy, or resume policy.

The sanitizer and approval process protocols are separate work items (#8 and #9). This milestone
therefore exposes typed injection boundaries and deterministic fakes; it does not implement a real
command, login, or hosted-model adapter.

## CLI

The public synthetic entry point is:

```bash
svbench run \
  --bundle <bundle-directory> \
  --provider mock \
  [--model <id>] \
  [--effort <level>] \
  [--max-tokens <n>] \
  [--attempt-root <directory>] \
  [--json]
```

`--attempt-root` defaults to `attempts` below the current working directory. A successful run
creates a child directory named by the run identity. The CLI prints the case and attempt IDs, never
the model document, input contents, local absolute paths, or provider diagnostics.

Exit status is `0` for a finalized attempt, `1` for a classified bundle/provider/approval/sanitizer
failure, and `2` for invalid CLI arguments or an unexpected internal failure. In JSON mode the
summary is written to stdout; human mode writes failures to stderr.

## Runner lifecycle

`runBundle()` performs the following steps in order:

1. **Preflight and staging.** It validates the bundle using the bundle v1 validator. The image,
   system text, and instruction text are copied into a private temporary staging directory and
   re-verified against the declared digest. The schema value comes from the digest-verified JSON
   read. The provider receives callbacks over staged inputs, never a fresh open of the mutable
   bundle directory.
2. **Identity.** It snapshots `caseId`, `documentKind`, and prepared-image media type and SHA-256
   into `caseInputIdentity` v1. Schema, prompt text, instruction text, truth, comparison policy,
   bundle path, and bundle manifest digest are not part of this case identity.
3. **Policy preflight.** If a sanitizer policy is configured, the runner hashes the exact envelope
   bytes, parses it with strict UTF-8 and JSON rules, recomputes its target identity, and computes
   the policy binding. A missing, malformed, swapped, or mismatched policy fails before provider
   invocation.
4. **Approval.** A required approval gate must be present and match its expected gate ID,
   protocol version, snapshot digest, runtime binding identity, and runtime binding digest. The gate
   request contains run settings and safe provenance only; it contains no image, prompt, schema,
   truth, comparison, or case identity. Approval is complete before the provider callback can read
   the staged image or text.
5. **Provider invocation.** The provider receives two separate typed values:
   - `ProviderModelRequest`: staged prepared image, schema, system text, instruction text, and
     requested model/effort/max tokens;
   - `ProviderAdapterContext`: local case/provenance context and input digests. It is not model
     payload and does not contain truth or comparison data.

   The provider may return a JSON value, strict JSON text, or UTF-8 JSON bytes. Text and bytes are
   decoded and parsed through the public strict JSON contract. Approval, provider, and sanitizer
   timeouts abort their optional `AbortSignal`; no attempt is finalized.
6. **Sanitization and binding.** Raw provider output remains in memory only. When sanitizer policy
   is configured, the sanitizer must return a sanitized document plus the exact current identity,
   policy digest/version, target identity digest, and policy binding digest. Findings are restricted
   to value-free `code`, `severity`, `classification`, `hardGate`, and optional `path` fields.
7. **Schema validation.** Only the sanitizer output (or the formal provider document when the
   optional sanitizer is omitted) is validated against the bundle schema. A
   schema mismatch is a classified failure and cannot create an attempt.
8. **Atomic finalization.** The formal document is serialized to `document.json`, its exact stored
   bytes are hashed, and `attempt.json` is written with the matching digest. Both files are created
   in a temporary attempt directory, which is renamed into place only after all work has succeeded.

A provider, sanitizer, approval failure, timeout, parse error, policy mismatch, or schema mismatch
leaves no formal attempt directory. Temporary input and attempt staging is removed on failure.

## Identity rules

### Case input identity

`caseInputIdentity` is a domain-separated SHA-256 over length-prefixed UTF-8/ASCII fields:

```text
SHA256(
  "svbench-case-input-v1" ||
  LP_UTF8(caseId) ||
  LP_UTF8(documentKind) ||
  LP_UTF8(preparedImage.mediaType) ||
  LP_ASCII(preparedImage.sha256)
)
```

`LP_*` is a four-byte big-endian byte length followed by the encoded bytes. The digest is lowercase
hex. The identity changes when any of those four declared fields changes and remains unchanged when
schema, system, instruction, truth, comparison, or bundle path changes.

### Policy binding

The sanitizer binding is:

```text
SHA256(
  "svbench-sanitizer-policy-binding-v1" ||
  LP_ASCII(caseInputIdentity.digest) ||
  LP_UTF8(decimal(policyVersion)) ||
  LP_ASCII(policyDigest)
)
```

`policyDigest` is the SHA-256 of the exact policy envelope bytes. The envelope target is recomputed
rather than trusted from its declared digest. The manifest stores the policy binding identity tuple
(`caseInputIdentityDigest`, `policyVersion`, `policyDigest`) separately from the derived
`policyBindingDigest`.

### Run identity

`runId` is a separate identity. It includes the case identity, bundle manifest digest, provider ID
and stable route label, requested model/effort/max tokens, and approval/sanitizer binding labels.
Changing a requested execution setting produces a different run ID without changing
`caseInputIdentity`. A route is a stable provider label, not an endpoint or account identifier.

## Attempt layout and manifest

A finalized attempt contains only:

```text
<attempt-root>/<run-id>/
├── attempt.json
└── document.json
```

`attempt.json` conforms to [`schemas/attempt-v1.schema.json`](../schemas/attempt-v1.schema.json).
It records:

- attempt/run/bundle versions and IDs;
- case ID, document kind, bundle manifest digest, and the four provider-input digests/media types;
- the complete case input identity;
- harness version/commit and bundle prompt/preprocess/source metadata;
- provider ID/stable route, requested settings, and only provider metadata actually returned;
- approval and sanitizer status, versions, digests, policy binding identity/binding digest, and
  value-free findings;
- passed stage records for policy-target preflight, approval, provider, parse, sanitizer, target
  binding, and schema validation;
- exact stored `document.json` digest and timing.

Unknown model, effort, token usage, or stop-reason metadata is `null`/unavailable; it is never
invented from a request. The manifest contains no raw provider response, raw document, prompt text,
image bytes, policy content, policy path, endpoint, account, secret, or failure traceback.

`readAttempt()` treats the files as untrusted. It rejects symlinks, size violations, invalid strict
JSON, unknown manifest fields, document digest changes, case identity changes, run identity changes,
and sanitizer policy-binding changes. It hashes the exact stored document bytes, not a reserialized
value.

## TypeScript boundaries

The implementation is split into these public modules:

- `src/runner/run.ts` — lifecycle and finalization;
- `src/runner/types.ts` — provider, approval, sanitizer, and run option types;
- `src/runner/identity.ts` — case, policy, and run identity helpers;
- `src/runner/attempt.ts` — attempt writer/reader and exact document digest;
- `src/runner/sanitizer.ts` — policy envelope preflight and test helper;
- `src/provider/mock.ts` — deterministic synthetic provider double;
- `src/runner/load-bundle.ts` — runner-facing re-export of verified staging.

The mock provider generates a deterministic schema-shaped synthetic document when no explicit test
document is supplied. It never reads the bundle truth or comparison policy.

## CI and data boundary

CI uses only `fixtures/synthetic/` and the mock provider. No real model, login flow, credential file,
network upload, or private corpus is used. Real bundles and attempts remain outside Git history.
