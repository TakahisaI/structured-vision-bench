# Suite run manifest v1

The suite run manifest is the immutable, value-free identity snapshot produced from a fully
preflighted suite plan. It is a pure contract: creating, encoding, and reading it does not create a
directory or start an approval, provider, or sanitizer process. Its private atomic publication is
defined in [`docs/suite-run-directory-v1.md`](suite-run-directory-v1.md); the mutable slot ledger is
a separate lifecycle contract.

The machine-readable shape is
[`schemas/suite-run-v1.schema.json`](../schemas/suite-run-v1.schema.json). The strict reader also
enforces relationships that JSON Schema cannot express: derived digests, ordered case indices, the
complete case-major/repeat-minor slot grid, deterministic attempt keys, run identities, and attempt
identities.

## Value-free projection

The manifest fixes:

- suite version, ID, exact suite digest, suite-plan digest, and case-policy-map digest;
- provider route and requested settings, phase, repeat, and requirement-verifier identity;
- approval gate, protocol, snapshot, runtime-binding, scope, and phase identities when configured;
- sanitizer ID, protocol, finding-path allowlist identity, canonical patterns, and value-free
  failure-code allowlist when required by at least one case;
- one ordered case identity entry containing the bundle-manifest digest, case-input digest,
  complete consumer requirement decision, and optional policy target/binding identity; and
- every deterministic slot with its position, attempt key, per-case run ID, and per-repeat attempt
  ID.

It never stores a case ID, document kind, prepared-image identity fields, bundle or policy
reference, command executable/arguments/environment, local or absolute path, raw document, policy
value, truth value, provider response, or secret. The case-input digest and suite digest commit the
private inputs without copying them into this public contract.

A mixed suite has one top-level sanitizer identity because the suite configuration is shared.
Not-required cases still bind their negative consumer decision but derive their run ID with null
sanitizer identity and binding. Required cases derive the execution binding from their own policy
binding and the common finding-path allowlist digest.

## Identities

Each case's `casePolicyMapDigest` is independently recomputed from the identity-only case entries
using the `svbench-case-policy-map-v1` tuple defined by
[`docs/suite-v1.md`](suite-v1.md). `suitePlanDigest` is then recomputed from the exact suite digest
and that mapping digest.

For each case, the reader reconstructs the exact existing `svbench-run-v1` input, including suite
context. Repeat index is excluded from `runId`; therefore repeats of one case share a run identity.
The canonical attempt key `c<case-base36>-r<repeat-base36>` includes repeat index, so every repeat
has a distinct `attemptId` under the existing `svbench-attempt-v1` contract.

`suiteRunId` is SHA-256 over:

1. the raw ASCII domain `svbench-suite-run-v1`;
2. a four-byte unsigned big-endian length; and
3. compact UTF-8 JSON for a freshly constructed identity object containing every manifest member
   except `suiteRunId`, in the schema member order used by the encoder.

Nested objects are freshly constructed in their documented order. Arrays retain their semantic
order. The identity input therefore does not depend on caller object member order or whitespace.
The v1 fixed vector used by the synthetic mixed-suite contract test is:

```text
case 0 runId = 507e4b2d9343d3c8c16d72d05d13f3f74e883dc1562a7b019df4269bbb2d9b9a
case 0 repeat 0 attemptId = b2116be2b819a98426c26aa45263318b8500dddc6dd38f612d81929bb6e672b3
case 0 repeat 1 attemptId = ea21c3a8668ceef3ca26320c9e8d92cf09121b2809d7677b826748b1a4ff8a59
case 1 runId = 6f8576ac3249f8936316cf2b010ba3c522aae6417959910d67f2a6adbe69d745
case 1 repeat 0 attemptId = 4639844bfd88268d2d9139f9307d059a53bd8e7d91b80396d77ed43e37101910
case 1 repeat 1 attemptId = 0f29ee02ea2a2aadc06b07119db04cf1abb0bd006ae75bd3d9356cd38792a97d
suiteRunId = 2b16533842fe5a7a56b78c32dd61dac28fc4840646a5c750b5b61e0bf5cba2b7
```

The encoder emits compact JSON in the same fixed order plus one trailing newline. Equal preflight
plans consequently produce byte-for-byte equal manifest files. The reader accepts insignificant
JSON whitespace and member order but always reconstructs the same canonical identity object.
The builder measures that canonical encoded form, including JSON escape expansion and the trailing
newline, before returning. A projection whose bytes would exceed 4 MiB is rejected with
`suite_run_manifest_invalid`; consequently every successful builder result is accepted by the
official encoder's size boundary.

## Reader boundary

The reader bounds input at 4 MiB before UTF-8 decoding or copying, rejects a BOM, invalid UTF-8,
duplicate members, partial or concatenated JSON, unknown members, sparse arrays, accessors in
runtime builder input, schema-invalid values, and every identity mismatch. It returns fresh deeply
frozen data.

The private run-directory reader passes the digest-named parent basename as expected `suiteRunId`.
This external anchor rejects a coordinated, internally self-consistent replacement of the whole
manifest.

Failures expose only `suite_run_manifest_invalid` or `suite_run_identity_mismatch`; diagnostics do
not include a field value, digest, case identifier, or path.
