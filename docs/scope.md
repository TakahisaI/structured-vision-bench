# Maintained scope

This document is the active-scope decision for `structured-vision-bench` after the August 2026
simplification. It distinguishes the public contracts already used by Eldorad from the suite
platform work that was stopped.

When an older Issue or document describes future suite behavior, this document controls whether that
behavior belongs in the active tree. The detailed single-run contract documents remain normative for
their own schemas, identities, and lifecycle boundaries.

## Purpose

The repository exists to support small, reproducible structured-vision experiments without moving a
consumer's production logic or confidential data into a public project. One invocation validates one
bundle, invokes one selected provider once, and records one independently inspectable result.

It is not intended to be a scheduler, workflow engine, distributed benchmark service, or production
OCR platform.

## Maintained public contracts

### Bundle v1

[`bundle v1`](bundle-v1.md) is the portable consumer/public boundary. Eldorad locks this behavior to
merge commit `807d765202fa2bcb5bce84dece452c2393acf3e8` and validates generated bundles with the public
CLI. Its manifest shape, byte-exactness rules, pointer grammar, normalization, truth projection, and
failure categories must not change accidentally.

### Single-run attempt

[`attempt v1`](attempt-v1.md) records one explicit execution instance. The maintained boundary
includes case-input identity, consumer requirement decision, provider/requested settings, approval
identity, required sanitizer/policy binding, immutable formal document, and caller-owned attempt key.
It does not require a suite context.

### Comparison

[`comparison v1`](comparison-v1.md) compares a verified attempt with its execution bundle, classifies
missed/fabricated/wrong/missing-item/extra-item/comparison-error outcomes, preserves hard gates, and
supports explicit truth/comparison-only rescoring. It does not aggregate a suite.

### Local provider boundary

The deterministic mock provider and [`command provider v1`](command-provider-v1.md) remain active.
The command provider is a shell-free local adapter boundary, not a hosted-model payload definition.
It permits Eldorad to keep its production OpenAI provider private while the public runner verifies
one request/response and attempt.

### Approval

[`approval v1`](approval-v1.md) remains the consumer-owned pre-transport boundary. A required gate
must match the expected opaque snapshot, runtime, scope, phase, and requirement decision before the
provider process or provider-input read begins. The public harness compares identities but does not
own Eldorad's private approval policy.

### Sanitizer

[`sanitizer v1`](sanitizer-v1.md) remains the target-bound pre-finalization boundary. Required runs
must verify current case-input identity, policy target, exact policy identity, and binding before a
sanitized document can become a formal attempt. Not-required runs omit this block; they do not use
empty or dummy identities.

### Codex app-server experiment route

[`codex-app-server-transport-v1`](codex-app-server-transport-v1.md) remains available for synthetic
smoke tests and explicitly approved single-run exploration. The fixed protocol, no-host-tool process
boundary, one-shot approval binding, timeout/cancellation cleanup, and value-free diagnostics remain
part of that public contract. Automated verification uses only fake local processes.

Whether a real Eldorad document may use that route is a private Eldorad approval and persistence-audit
decision. This repository does not manage login credentials or infer non-persistence from a temporary
home directory.

## Removed from the active implementation

The following work is intentionally inactive:

- suite manifests and all-case suite preflight;
- automatic repeat orchestration;
- suite execution loops, schedulers, parallelism, retry, and fallback;
- resume and stale-running ownership recovery;
- suite-run directory publication;
- slot event state machines, append-only ledgers, and hash chains;
- suite-level identities, reports, and aggregate dashboards.

Their prior code and discussion remain in Git history for reference. They must not be copied back
piecemeal. A new owner-approved Issue must first show why manual single-run execution is inadequate
for an observed experiment.

## Compatibility rule

A change to a maintained public contract requires all of the following:

1. identify the exact schema, wire, identity, failure-code, or lifecycle behavior changing;
2. check every Eldorad Issue or lock that names the public contract;
3. update the public implementation, schema, normative document, fixed vectors, and mutation tests
   together;
4. coordinate the Eldorad adapter/lock update before removing old behavior; and
5. obtain owner approval before implementation when the change expands scope.

A refactor that preserves externally observable bytes and behavior does not need a version change,
but it still must pass the complete synthetic contract suite.

## Data and CI boundary

Only fictional, redistributable fixtures belong in this repository. Real bundles, truth, provider
outputs, approval snapshots, policies, evaluator records, runtime audit details, credentials, and
local paths remain in the consuming application's confidential storage.

GitHub Actions and automated tests use deterministic mock/fake processes and no network model call or
login flow. The public harness has no telemetry and does not upload bundles, attempts, or reports.
