# Attempt v1 and runner

## Scope

Issue #2 adds a provider-neutral single-case runner. It consumes one already validated bundle and
writes one successful attempt outside the bundle. It does not own a production prompt, business
schema, preprocessing, provider credentials, comparison logic, repeat policy, or resume policy.

The command sanitizer protocol remains a separate work item (#8). Approval protocol v1 Phase A is
implemented for this single-run lifecycle: a consumer verifier must derive the requirement decision,
and a configured private gate must approve the expected snapshot, runtime binding, and scope before
the provider runs. Suite/resume approval integration remains Phase B of #9 after #5. This repository
does not implement a real login or hosted-model adapter.

## CLI

The public synthetic entry point is:

```bash
svbench run \
  --bundle <bundle-directory> \
  --provider mock \
  [--model <id>] \
  [--effort <level>] \
  [--max-tokens <n>] \
  [--attempt-key <label>] \
  [--attempt-root <directory>] \
  [--approval required|optional --approval-command <executable> <approval identity options>] \
  [--json]
```

`--attempt-key` is a caller-owned safe label (`[A-Za-z0-9._-]`, 1–64 characters) and defaults to
`single`. `--attempt-root` defaults to `attempts` below the current working directory. A successful
run creates a child directory named by the derived attempt identity. The CLI prints the case,
attempt-key, attempt, and run identities, never the model document, input contents, local absolute
paths, or provider diagnostics.

Command approval options and their exact request/response boundary are specified in
[`docs/approval-v1.md`](approval-v1.md). Incomplete CLI approval options are invalid arguments and do
not enter the runner.

Exit status is `0` for a finalized attempt, `1` for a classified bundle/provider/approval/sanitizer
failure, and `2` for invalid CLI arguments or an unexpected internal failure. In JSON mode the
summary is written to stdout; human mode writes failures to stderr.

## Runner lifecycle

`runBundle()` performs the following steps in order:

1. **Manifest/path preflight.** It validates the bundle manifest, referenced path syntax, and the
   output-schema definition without opening provider input contents. It also rejects an attempt root
   that resolves to the bundle or one of its descendants. This phase computes the declared image
   metadata needed for the case identity.
2. **Identity.** It snapshots `caseId`, `documentKind`, and prepared-image media type and SHA-256
   into `caseInputIdentity` v1. Schema, prompt text, instruction text, truth, comparison policy,
   bundle path, and bundle manifest digest are not part of this case identity.
   Both attempt `caseId` fields preserve the bundle-v1 identifier contract, including its 128-character
   maximum; other safe provenance and route labels remain bounded to 64 characters.
3. **Consumer requirement decision.** The caller supplies a consumer-owned verifier and an immutable
   decision. The verifier derives the decision from `documentKind`; the runner compares every field,
   recomputes `requirementDecisionDigest`, and rejects a caller downgrade. The decision records
   `sanitizerRequirementVersion`, `sanitizerRequired`, `policyRequired`, a safe reason code, verifier
   identity/version, and optional consumer source commit.
4. **Policy preflight.** When the decision requires sanitization, the runner first validates that the
   sanitizer ID/version are safe and `sanitize` is callable. It binds that method to its
   implementation and freezes one snapshot used by run identity, policy preflight, invocation,
   response checks, and the attempt manifest. Missing, non-callable, or
   accessor-throwing implementations fail before provider invocation or provider input access. The
   approval gate's `approve` method is validated, bound, and snapshotted at its corresponding
   preflight. A command gate is spawned without a shell and with only explicitly allowlisted
   environment variables. The
   runner then hashes the exact policy envelope bytes, parses it with strict UTF-8 and JSON rules,
   recomputes its target identity, and
   computes the policy binding. A missing, malformed, swapped, or mismatched policy fails before
   provider invocation.
5. **Approval.** A required approval gate must be present and match its expected gate ID, protocol
   version, snapshot digest, runtime binding identity/digest, approved-scope identity/digest, phase,
   and complete consumer requirement attestation. A configured optional gate is held to the same
   checks. The gate request contains run settings and safe provenance only; it contains no image,
   prompt, schema, truth, comparison, prior attempt, policy, case identity, or attempt identity.
   Denial, expiration, timeout, process failure, malformed output, and every identity mismatch fail
   before provider invocation or image access. See [`docs/approval-v1.md`](approval-v1.md).
6. **Complete verification and staging.** After approval, the runner revalidates the complete bundle,
   verifies all declared digests and truth projection, and copies image/system/instruction bytes into a
   private per-attempt-invocation staging directory. It then claims
   `<attempt-root>/<attempt-id>` with a non-recursive
   exclusive directory create. An existing entry is `attempt_exists`; only the process that wins this
   claim may build or clean up the unpublished attempt. The claim contains a private nonce marker
   until the final manifest publication. The provider receives callbacks over staged inputs, never a
   fresh open of the mutable bundle directory. If the manifest or declared image identity changed
   after approval, the run fails before provider invocation.
7. **Provider invocation.** The provider receives two separate typed values:
   - `ProviderModelRequest`: allowlisted staged prepared image, output schema snapshot, system text,
     instruction text, and requested model/effort/max tokens;
   - `ProviderAdapterContext`: local case/provenance context and input digests. It is not model
     payload and does not contain truth or comparison data.

   The provider may return a JSON value, strict JSON text, or UTF-8 JSON bytes. All forms are
   immediately converted to one bounded, strict canonical JSON value before validation. Approval,
   provider, and sanitizer timeouts abort their optional `AbortSignal`; provider reads are invalidated
   when provider execution settles or a timeout fires, and no attempt is finalized. Each staged
   provider input is bounded by the runner's 16 MiB snapshot limit.
8. **Sanitization and binding.** When the consumer decision requires sanitization, the sanitizer must
   return a sanitized document plus the exact current identity, policy digest/version, target identity
   digest, and policy binding digest. Findings are reduced to bounded value-free codes/classifications;
   persisted finding paths are always null. When sanitization is not required, the strict canonical
   provider document becomes the formal document and no sanitizer/policy/target-binding block is
   emitted.
9. **Schema validation.** Only the formal canonical document is validated against the preflighted
   bundle output schema. A schema mismatch is a classified failure and cannot create an attempt.
10. **Atomic finalization.** The formal document is serialized to `document.json.part`, its exact
    bytes are hashed, and a no-replace hard link publishes it as `document.json` inside the claimed
    directory. The matching manifest is written to the private same-filesystem staging path
    `<attempt-root>/.claim-<owner-nonce>/attempt.json.pending` and self-validated together with the
    document while the private owner marker is present. Before publication, final-claim cleanup may
    remove only files owned by the claim, only when the claim owner is proven, and only while
    `attempt.json` does not exist. The owner marker is then removed and a no-replace hard link
    publishes the complete external pending manifest as `attempt.json`. That final link is the
    one-syscall visibility point: the claimed attempt directory changes directly from `document.json` to
    the exact final two-file shape. Removing the
    external pending source is a separate post-publication best-effort cleanup, keyed by its recorded
    file identity, and cannot turn a published attempt into a failure.

A provider, sanitizer, approval failure, timeout, parse error, policy mismatch, or schema mismatch
leaves no formal attempt. An unpublished claim directory may remain after a crash or after an
attempt-root identity change prevents safe cleanup; because it has no final `attempt.json`, it is not
a formal attempt and must not be consumed. Temporary input staging is removed on failure. A provider
that ignores abort may finish in memory, but all staged-input callbacks reject after timeout.

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

`runId` is a separate identity. It includes the case identity, bundle manifest digest, provider ID,
stable route label, provider implementation/protocol versions, requested model/effort/max tokens,
the complete approval metadata, the
sanitizer identity/binding metadata, and the complete consumer sanitizer-requirement decision. All
optional tuple members use an explicit presence tag, so absent and null/empty values cannot collide.
Changing a requested execution or security setting produces a different run ID without changing
`caseInputIdentity`. A route is a stable provider label, not an endpoint or account identifier.

### Attempt instance identity

`runId` identifies stable execution settings; it is not a uniqueness nonce. A caller selects one
instance of that run with `attemptKey`. Attempt identity v1 is:

```text
SHA256(
  "svbench-attempt-v1" ||
  LP_ASCII(runId) ||
  LP_UTF8(attemptKey)
)
```

The lowercase-hex result is `attemptId`. The manifest records `attemptIdentityVersion: 1`,
`attemptKey`, `attemptId`, and `runId` separately. The default key `single` preserves one-attempt
behavior for callers that do not select a key. The same run with different keys may coexist; the
same run and key derives the same destination and is rejected as `attempt_exists` before provider
invocation. `attemptKey`, `attemptId`, and `runId` are runner metadata and are not added to provider,
approval, or sanitizer requests.

### Consumer sanitizer requirement

Every run carries a consumer-owned `sanitizerRequirement` decision. The consumer supplies a verifier
whose `derive(documentKind)` result is compared field-by-field with the supplied attestation. The
attestation contains:

- `sanitizerRequirementVersion`;
- `sanitizerRequired` and `policyRequired` (v1 requires these flags to agree);
- a bounded `sanitizerRequirementReason` code;
- `requirementVerifierId` and `requirementVerifierVersion`;
- optional bounded `consumerSourceCommit`;
- `requirementDecisionDigest`, computed over the ordered version, verifier identity, flags, reason,
  and source-commit presence/value tuple defined in
  [`docs/approval-v1.md`](approval-v1.md#consumer-requirement-decision-digest).

The runner rejects a missing, malformed, stale, or downgraded decision before provider invocation.
The attempt schema is a discriminator: a not-required decision omits `sanitizer` and the
policy-target/sanitizer/target-binding stages; a required decision requires all of them.
When `sanitizer.required` is true, the runner also requires explicit expected bindings for the
sanitizer ID, protocol version, policy version, policy digest, case-input identity version and
digest, and policy-binding digest; omitted expectations are configuration failures before input
staging.

### Output schema subset

The public validator implements a deliberately bounded JSON Schema subset. It supports local `$ref`,
`type` (including type arrays), `const`, `enum`, string/number/array/object bounds, `pattern`,
`date-time`, `properties`, `required`, boolean or schema-valued `additionalProperties`, `items`,
`anyOf`, `oneOf`, `allOf`, and `not`. Local references must be acyclic, and schema nesting is bounded
to keep evaluation resource use finite. A bundle output schema is meta-validated against this subset
before provider invocation; unsupported keywords, malformed references, invalid patterns, malformed
keyword shapes, cyclic references, and excessive nesting are stable `output_schema_invalid` failures.
This is not a claim of full Draft 2020-12 coverage.

## Attempt layout and manifest

A finalized attempt contains only:

```text
<attempt-root>/<attempt-id>/
├── attempt.json
└── document.json
```

`attempt.json` conforms to [`schemas/attempt-v1.schema.json`](../schemas/attempt-v1.schema.json).
It records:

- attempt identity, attempt/run/bundle versions, the caller key, and separate attempt/run IDs;
- case ID, document kind, bundle manifest digest, and the four provider-input digests/media types;
- the complete case input identity;
- the consumer-owned sanitizer requirement decision and its decision digest;
- harness version/commit and bundle prompt/preprocess/source metadata;
- provider ID/stable route, implementation/protocol versions, requested settings, and only provider
  metadata actually returned;
- approval status, gate/protocol/snapshot/runtime/scope/phase metadata and the complete mirrored
  consumer requirement attestation;
- when sanitizer is required, sanitizer status/version, policy digests, policy binding identity/
  binding digest, and bounded value-free findings;
- passed stage records for approval, provider, parse, and schema validation, plus policy-target
  preflight/sanitizer/target binding only when sanitizer is required;
- exact stored `document.json` digest and timing.

Unknown model, effort, token usage, or stop-reason metadata is `null`/unavailable; it is never
invented from a request. The manifest contains no raw provider response bytes/text, prompt text, image
bytes, policy content, policy path, endpoint, account, secret, or failure traceback. The no-sanitizer
formal document is a strict canonical JSON value, not the raw provider serialization; sanitizer
findings never persist a provider-supplied path.

`readAttempt()` treats the files as untrusted. It rejects symlinks, size violations, invalid strict
JSON, unknown manifest fields or directory entries, non-private modes, document digest changes, case
identity changes, attempt key/ID changes, run identity changes, attempt-directory name mismatches,
consumer-decision changes, and sanitizer policy-binding changes. Pass the consumer verifier in
`readAttempt(path, { requirementVerifier })` to rederive the
decision from `documentKind`; without it, the stored decision digest and shape are still checked. It
hashes the exact stored document bytes, not a reserialized value.

The reader recognizes only a directory containing the final `attempt.json` and `document.json` as a
published attempt. A directory containing only `document.json`, the owner marker, or neither
manifest is an unpublished claim and is rejected as an attempt. Each external `.claim-<nonce>`
staging directory belongs to one attempt claim and is never part of a formal attempt; staging
directories are not shared between attempt invocations. The runner uses a no-follow attempt root
handle and device/inode checks through the last pre-publication validation. The Node-only
contract prevents competing harness writers from replacing a claimed attempt directory. Final document
and manifest creation use no-replace filesystem operations, and cleanup uses owned-file unlink plus
non-recursive directory removal so a newly created final file cannot be deleted by cleanup. Protection
against an adversarial same-UID process replacing the attempt root in the final path-based syscall
window is outside this portable harness threat model.

## TypeScript boundaries

The implementation is split into these public modules:

- `src/runner/run.ts` — lifecycle and finalization;
- `src/runner/types.ts` — provider, approval, sanitizer, and run option types;
- `src/runner/identity.ts` — case, policy, run, and attempt identity helpers;
- `src/runner/attempt.ts` — attempt writer/reader and exact document digest;
- `src/runner/approval.ts` — shell-free bounded command approval adapter;
- `src/runner/sanitizer.ts` — policy envelope preflight and test helper;
- `src/provider/mock.ts` — deterministic synthetic provider double;
- `src/runner/load-bundle.ts` — runner-facing re-export of verified staging.

The mock provider generates a deterministic schema-shaped synthetic document when no explicit test
document is supplied. Its synthesis is best-effort within the validated subset: local `$ref` with
sibling constraints, type arrays, `anyOf`, `oneOf`, and the simple intersecting constraints supported
by `allOf` are covered. An unsatisfied or unsupported synthesis path returns the mock's invalid
document, which the runner rejects before publication. It never reads the bundle truth or comparison
policy.

## Development compatibility

Attempt v1 was changed before package publication while the package remains private at version
`0.0.0`. Artifacts written by the earlier Issue #2 development shape—where `attemptId` equaled
`runId` and the manifest had no attempt identity fields—are intentionally incompatible with this
reader. Phase A approval development also adds provider implementation/protocol versions, expanded
approval metadata, and the corrected ordered requirement-decision digest tuple; artifacts from the
preceding development shape are likewise incompatible. There is no migration or legacy-reader path
in this repository. Development users retaining those artifacts must read them with the matching
earlier revision or use a fresh attempt root. The current schema remains v1 because no earlier
attempt contract was released as a stable external artifact.

## CI and data boundary

CI uses only `fixtures/synthetic/` and the mock provider. No real model, login flow, credential file,
network upload, or private corpus is used. Real bundles and attempts remain outside Git history.
