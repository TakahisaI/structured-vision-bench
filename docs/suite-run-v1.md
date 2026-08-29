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
- provider route and requested settings, phase, suite-declared repeat, bounded effective repeat,
  and requirement-verifier identity;
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
[`docs/suite-v1.md`](suite-v1.md). `suitePlanDigest` is then recomputed from the exact suite digest,
that mapping digest, and the effective repeat. The manifest preserves the suite-declared repeat
separately while deriving its complete slot grid from the effective repeat.

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
case 0 runId = d5f23f42ef26451f62bf10f0a970f7d819a7a1ca6dd4228d7db2e352d927bde7
case 0 repeat 0 attemptId = 15cb3d09019ab5c87266a795f7c3e0c2c99e2e57656e3783379d168477dca0a6
case 0 repeat 1 attemptId = 7ab77d7564701a4fba11358136654ff99423cd09dd5177c7498cce1c564c46cc
case 1 runId = 49da4fa6576e9c9bdeae616a21e4902954d51afa82327f1b551b1ce864cb8554
case 1 repeat 0 attemptId = f86bef99db39ccdfed4cea55a7bf7d383030eb49d2b5fca945c78d812c6654e0
case 1 repeat 1 attemptId = 9a110441f8e6d544f320af0b8330e8b036b524cb298075b95d5acbbcbd1d3bbd
suiteRunId = 213d6611f3951d9d5dabe5a5375e81462fcef14110007a8c89dcfd3002847442
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
