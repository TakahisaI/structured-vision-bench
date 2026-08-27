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
- repeat and retry policy;
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

### Provider

A provider accepts the prepared image, instructions, schema, and requested execution metadata. It
returns a structured document plus metadata that the upstream protocol actually exposes. Missing
metadata remains unknown. The public implementation currently ships a deterministic mock provider;
real process/app-server adapters are later work.

Two distinct invocation surfaces must not be conflated:

- **Provider-adapter invocation** (local, never hosted-model input): a separate model request carries
  the four extraction inputs; its separate context carries run settings, input digests, and a
  narrowly allowlisted set of bundle/consumer provenance needed for local validation and attempt
  recording.
- **Hosted-model payload**: only the prepared image, schema, system preamble, instruction, and the
  requested model / effort / max tokens.

Case ID, bundle version/digest, source commit, prompt/preprocess version, approval metadata,
sanitizer metadata, truth, comparison policy or results, and prior attempts are never sent to the
hosted model. Truth, comparison policy or results, and prior attempts are also never sent to the
local adapter or sanitizer. Caller-owned attempt keys and derived attempt/run IDs are runner storage
metadata and are never sent to the local adapter, hosted model, approval gate, or sanitizer. The
sanitizer command is run/suite configuration, not bundle content.

Providers are transport adapters, not autonomous agents. The Codex app-server provider planned in
Issue #3 must fail rather than execute tool requests, shell commands, workspace reads, or approval
requests.

### Comparison

Comparison, introduced by Issue #4, consumes truth, a structured result, and an explicit comparison
policy. It separates missed, fabricated, wrong, missing-item, and extra-item outcomes. Semantic or
LLM-judged equivalence is outside bundle v1.

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
4. Approval and sanitizer implementations are runtime-validated into bound immutable snapshots, and
   their policy/runtime bindings are checked before the relevant boundary is crossed.
5. After approval, the runner stages verified provider inputs outside the bundle (bounded to 16 MiB
   per provider input), derives a caller-keyed attempt ID from the stable run ID, and claims the
   attempt directory before provider work.
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
