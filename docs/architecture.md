# Architecture

## Purpose

`structured-vision-bench` is a public, provider-neutral harness for evaluating schema-guided
structured extraction from document images. It is not an OCR production service and does not own a
consumer's business schema or provider credentials.

## Components

### Consumer adapter

A consuming application owns the production extraction request. Its bundle-facing content is:

- prepared image;
- stable system preamble;
- document-specific instruction;
- JSON Schema;
- prompt, preprocessing, and source version metadata;
- optional human-created truth and comparison policy.

Its run-facing settings are separate and never enter a bundle:

- provider route, requested model, effort, and token limit;
- execution phase;
- repeat and retry policy;
- approval command, phase, snapshot, runtime binding, and approved-scope expectations;
- sanitizer command;
- consumer-owned sanitizer requirement verifier and attestation.

The final contract splits ownership as follows: the **bundle** carries image, schema, system,
instruction, optional truth, comparison policy, and consumer metadata; **run or suite
configuration** carries provider, model, effort, max tokens, and repeats; an **attempt** records the
requested and effective execution settings together with the result. The consumer exports only the
bundle-facing values into this repository without moving its production source of truth here. A
later private command adapter may invoke the consumer's production API provider for calibration.

### Bundle validator

The validator validates the manifest contract, path containment, regular-file boundary, digests,
strict UTF-8, JSON syntax, and the supported output-schema definition before a provider can see the
case. Runner-facing loading stages provider inputs from the verified read path rather than reopening
the mutable bundle for a provider; input staging occurs only after approval.

### Runner

The Issue #2 runner turns one validated bundle into one immutable attempt. It owns provider-input
staging, case/run/attempt identity, consumer requirement attestation, approval and sanitizer
binding checks, cancellation/timeout signaling, exclusive attempt claiming, final-manifest
publication, and machine-readable attempt metadata. It does not own application-specific validation.
A provider, approval, sanitizer, parse, policy, or schema failure creates no formal attempt.

### Approval gate

Approval v1 is a consumer-owned pre-transport decision boundary. After public bundle preflight and
consumer requirement rederivation, the runner invokes either a validated in-process gate or a
shell-free local command. The request contains only bounded run provenance and expected opaque
snapshot/runtime/scope identities. It excludes provider inputs, truth, comparison, policy, case and
attempt identities, and paths. The public harness compares identities but does not interpret private
account, endpoint, persistence, retention, or scope policy. See
[`docs/approval-v1.md`](approval-v1.md).

The successful gate response is bound into `runId` and the attempt manifest. Immediately before
transport, an applied gate also requires the private provider adapter to rederive its current opaque
binding through `prepareTransport()`; changed receiver state or expiry fails before `invoke()` or
input reads. A provider-carried post-response copy may be checked against the gate response but
cannot replace these pre-transport checks or self-authorize transport. Suite and resume propagation
is intentionally deferred to Phase B of Issue #9 after Issue #5.

### Provider

A provider accepts the prepared image, instructions, schema, and requested execution metadata. It
returns a structured document plus metadata that the upstream protocol actually exposes. Missing
metadata remains unknown. The public implementation ships a deterministic mock provider and the
Phase A shell-free command provider. The command provider stages the four exact verified inputs plus
a versioned local manifest in a fresh private directory only after the consumer-owned adapter
reattests approved transport, then releases the request path to that same live process and strictly
binds its response to phase, requested settings, provider identity, case-input identity, sanitizer
requirement, and approval. See [`docs/command-provider-v1.md`](command-provider-v1.md). Real
app-server adapters remain later work. The v1 local adapter and its descendants are one trusted
invocation boundary: the direct child must remain live through extraction and must not delegate the
control pipe, request path, or request descriptors. Portable termination is limited to the initially
spawned process group; detached or daemonized descendants are non-conforming.

Two distinct invocation surfaces must not be conflated:

- **Provider-adapter invocation** (local, never hosted-model input): a separate model request carries
  the four extraction inputs; its separate context carries phase, run settings, input digests, and a
  narrowly allowlisted set of bundle/consumer provenance needed for local validation and attempt
  recording.
- **Hosted-model payload**: only the prepared image, schema, system preamble, instruction, and the
  requested model / effort / max tokens.

Case ID, bundle version/digest, source commit, prompt/preprocess version, phase, approval metadata,
sanitizer metadata, truth, comparison policy or results, and prior attempts are never sent to the
hosted model. Truth, comparison policy or results, and prior attempts are also never sent to the
local adapter or sanitizer. Caller-owned attempt keys and derived attempt/run IDs are runner storage
metadata and are never sent to the local adapter, hosted model, approval gate, or sanitizer. The
sanitizer command is run/suite configuration, not bundle content.

Providers are transport adapters, not autonomous agents. The Codex app-server protocol uses one
fixed-version ephemeral turn and fails rather than answer tool, shell, file-change, workspace, or
approval requests. Its process client requires an isolation-capable app-server to disable managed
configuration and plugin startup before an in-process readiness proof, runs it in an isolated empty
workspace with a fixed no-host-tool catalog, excludes account and extension prompt contributors,
and tears down its single process before settlement. The stock CLI fails closed at this boundary.
The public Provider wrapper requires a consumer-owned revalidator, binds one exact approval
attestation to only the next invocation, and revalidates again through a process start guard after
private workspace/catalog preparation and immediately before app-server spawn. It waits for
process/workspace cleanup on abort. A later prepare invalidates the prior one-shot
authorization. Policy-required runs remain deferred to Issue #18.
The protocol lifecycle and fixed identity are in
[`docs/codex-app-server-transport-v1.md`](codex-app-server-transport-v1.md).

### Sanitizer

When the consumer decision requires sanitization, the runner passes the canonical provider document
and preflighted target-bound policy envelope to a validated sanitizer. The private command adapter
uses one versioned stdin request, a fresh private empty working directory, and an allowlist-only
environment. Only a strictly bound sanitized document can reach schema validation and formal
publication. See [`docs/sanitizer-v1.md`](sanitizer-v1.md).

### Comparison

Comparison, introduced by Issue #4, consumes truth, a structured result, and an explicit comparison
policy. It separates missed, fabricated, wrong, missing-item, extra-item, and comparison-error
outcomes; enforces critical and sanitizer hard gates outside averages; and renders JSON plus Markdown
without field values or pointer text. Normal scoring requires the execution bundle identity. Explicit
rescoring permits only truth/comparison changes while the four provider inputs, case identity, and
provenance remain fixed. Semantic or LLM-judged equivalence is outside bundle v1.

### Report

Case and suite reports are derived output. They must identify the provider route, requested and
responded model, requested and effective effort, input digests, harness version, and unavailable
metadata. Reports never rewrite the input bundle.

## Trust boundaries

```text
Private consumer repository                 Public harness repository
┌──────────────────────────────┐            ┌──────────────────────────────┐
│ production prompt/schema     │  bundle    │ validator                    │
│ preprocessing/business rules ├───────────▶│ runner/provider adapters     │
│ production API provider      │            │ comparison/report            │
└──────────────┬───────────────┘            └──────────────┬───────────────┘
               │                                            │
               ▼                                            ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│ private corpus and results   │            │ synthetic fixtures and CI    │
│ outside Git history          │            │ no credentials or real model │
└──────────────────────────────┘            └──────────────────────────────┘
```

The repository boundary does not make a bundle public. A real bundle remains in the consumer's
confidential storage and is passed to a local checkout of the public harness.

## Data flow

1. The consumer freezes one source revision and exports a bundle to confidential storage.
2. The validator rejects malformed, incomplete, changed, or escaping inputs and preflights the output schema.
3. The consumer verifier derives the sanitizer requirement from document kind; the runner attests every
   decision field and digest.
4. Approval and sanitizer implementations are runtime-validated into bound immutable snapshots. The
   approval gate rederives its private decision and its snapshot/runtime/scope identities are checked
   before provider invocation or provider-input access.
5. After approval, the runner stages verified provider inputs outside the bundle (bounded to 16 MiB
   per provider input), derives a caller-keyed attempt ID from the stable run ID, and claims the
   attempt directory. The provider then revalidates the current approval binding immediately before
   transport.
6. The selected provider returns structured data or a classified failure.
7. The runner canonicalizes, sanitizes when required, schema-validates, and publishes the attempt by
   no-replace linking its fully validated manifest from the private same-filesystem `.claim-<nonce>/`
   staging area to `attempt.json`; the final link changes the claimed attempt directory directly to its
   exact two-file reader shape, and source cleanup is best effort.
8. Comparison and reports derive results without mutating bundle or attempt input.
9. Only anonymized aggregate facts may be copied to a public Issue.

## Dependency direction

The harness must not import a private consumer package. Integration uses files or a versioned
process protocol. This preserves independent release cycles and prevents a public dependency from
becoming the owner of production behavior.
