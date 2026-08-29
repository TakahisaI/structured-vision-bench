# Suite v1 preflight

Suite v1 is the immutable input contract for ordered multi-case execution. This revision defines
the manifest, all-case preflight, case-policy mapping identity, and deterministic slot descriptors.
It does not execute approval, provider, or sanitizer processes; create a suite run ledger; publish
attempts; resume a run; or render a report. Those lifecycle steps remain separate Issues under #5.

The machine-readable contract is [`schemas/suite-v1.schema.json`](../schemas/suite-v1.schema.json).
Readers reject unknown members, duplicate JSON members, invalid UTF-8, non-finite numbers, unsafe
references, and manifests larger than 4 MiB.

## Ownership and placement

A suite is run configuration, never bundle content. It fixes:

- suite ID and exact suite bytes;
- provider identity, execution phase, and requested model, effort, and maximum tokens;
- declared repeat count;
- consumer requirement-verifier identity;
- optional approval command and expected gate, snapshot, runtime, scope, and phase identities;
- a common sanitizer command and its value-free finding-path/failure-code allowlists when at least
  one case requires sanitization;
- an ordered list of bundle and requirement identities; and
- a separate, case-specific target-bound policy reference for every required case.

The suite directory may be confidential. `suite.json` and every referenced policy must be private
regular files with no group or other permission bits. A policy reference is a normalized relative
path beneath that directory. The reader rejects symlinks in every reference segment. Policy
contents and local paths never enter diagnostics, the case-policy mapping digest, or a future formal
attempt/report.

Approval and sanitizer executables use absolute paths and retain the existing shell-free command
limits, including case-insensitive uniqueness for environment variable names. They are
identity-bearing private configuration: preflight snapshots them but never starts them.

## Case entries

Every `cases[]` entry records:

- a normalized bundle-relative path and expected exact `bundle.json` digest;
- expected case-input identity version and digest;
- the four-field sanitizer requirement decision and its expected digest; and
- for a required case only, expected policy version, exact-byte digest, target identity digest, and
  policy-binding digest.

Requirement verifier ID, verifier version, and nullable consumer source commit are suite-wide. The
caller must supply the matching verifier implementation. The reader invokes it for every current
bundle document kind, compares the full derived decision with the manifest, and recomputes every
`requirementDecisionDigest` using the single-run v1 function. A case is
either fully not-required (`sanitizerRequired=false`, `policyRequired=false`, no `policy`) or fully
required (`true`, `true`, one `policy`). Empty digests and dummy identities are invalid.

A top-level sanitizer configuration exists if and only if at least one case is required. This lets a
mixed suite share one executable while retaining a distinct policy target and binding per case.

## Preflight order

Before any external process or provider work, the reader:

1. strictly reads and schema-validates the exact `suite.json` bytes;
2. bounds the complete `caseIndex × repeatIndex` slot count;
3. inspects every bundle manifest and referenced-file metadata without opening provider input,
   truth, schema, prompt, or instruction contents, then recomputes its case-input identity;
4. invokes the supplied verifier and compares and recomputes every requirement decision;
5. privately reads and verifies every required policy envelope against the current case identity;
6. recomputes every policy-binding digest;
7. derives the ordered case-policy mapping digest; and
8. derives and checks every deterministic attempt key.

Failure diagnostics contain a stable code plus a zero-based case/repeat position where applicable.
They do not include case IDs, digest values, policy or bundle references, document values, or
absolute paths.

## Identities

`suiteDigest` is SHA-256 over the exact `suite.json` bytes. Whitespace is therefore part of this
input identity.

`casePolicyMapDigest` is SHA-256 over the ASCII domain `svbench-case-policy-map-v1`, the ordered case
count, then one length-prefixed tuple per case:

```text
caseIndex
caseInputIdentityDigest
sanitizerRequirementVersion
sanitizerRequired
policyRequired
sanitizerRequirementReason
requirementVerifierId
requirementVerifierVersion
nullable consumerSourceCommit
requirementDecisionDigest
required | not-required discriminator
```

For a required case only, that tuple continues with policy version, exact-byte policy digest,
policy-target identity digest, and policy-binding digest. A not-required tuple ends immediately
after its discriminator; no empty policy fields are synthesized.

`suitePlanDigest` is SHA-256 over the raw ASCII domain `svbench-suite-plan-v1`, followed by the
length-prefixed `suiteDigest` and length-prefixed `casePolicyMapDigest`. Consequently
provider/request settings, approval or sanitizer configuration, repeat, order, bundle expectations,
requirement decisions, and policies cannot be changed while retaining the same plan identity.

The v1 deterministic attempt key for zero-based indices is:

```text
c<caseIndex-base36>-r<repeatIndex-base36>
```

The schema and reader jointly cap a plan at 10,000 slots. `createSuiteAttemptContext()` projects a
preflighted slot into the bounded formal-attempt context: suite version/ID, exact suite digest,
suite-plan digest, case-policy-map digest, and zero-based case/repeat indices. The runner commits all
of those values except repeat index into `runId`; repeat index enters the deterministic attempt key
and therefore `attemptId`. Repeats of one case consequently share a run identity while retaining
distinct attempt identities. Direct single-run attempts omit the suite block and preserve their
existing identity bytes. Ledger ownership remains defined by later Issues.

## Public-data and CI boundary

Repository tests create only fictional bundles, policies, commands, identities, and values. Suite
preflight never starts a command, invokes a provider, reads credentials, or uses network access.
Real suite files, policy envelopes, bundle paths, and corpus data remain outside Git history, Issues,
pull requests, Actions artifacts, and logs.
