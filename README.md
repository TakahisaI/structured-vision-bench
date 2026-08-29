# structured-vision-bench

A bounded public harness for schema-guided structured extraction experiments on one document case at
a time.

The repository validates a portable bundle, performs one explicitly selected provider invocation,
records one immutable attempt, and compares the result with optional truth. Production prompts,
schemas, preprocessing, provider credentials, policy bodies, and real benchmark data remain in the
consuming application.

> **Active scope:** single-case execution only. Suite scheduling, repeat orchestration, resume,
> ledgers, hash chains, and aggregate suite reporting are intentionally absent from the active tree.
> Their earlier implementations remain available in Git history but are not part of the supported
> contract.

## Why the single-run contracts remain

Eldorad uses this repository as the public side of its OCR experiment boundary. Its bundle exporter,
private provider adapter, route approval, target-bound sanitizer, and private evaluator depend on the
single-run contracts documented here. In particular, Eldorad locks bundle v1 to commit
`807d765202fa2bcb5bce84dece452c2393acf3e8`.

The following active contracts must therefore remain compatible unless both repositories coordinate
a deliberate version change:

- [`bundle v1`](docs/bundle-v1.md) and its strict validator;
- one immutable single-case [`attempt v1`](docs/attempt-v1.md);
- value-free [`comparison v1`](docs/comparison-v1.md) and explicit rescoring;
- the deterministic mock provider and shell-free command provider;
- consumer-owned [`approval v1`](docs/approval-v1.md) before provider input is released;
- target-bound [`sanitizer v1`](docs/sanitizer-v1.md) before a required result is finalized; and
- the approval-bound Codex app-server synthetic/single-run transport described in
  [`codex-app-server-transport-v1`](docs/codex-app-server-transport-v1.md).

See [`docs/scope.md`](docs/scope.md) for the maintained boundary and change-control rule.

## Supported workflow

One invocation performs this bounded lifecycle:

```text
bundle preflight
→ consumer requirement decision
→ optional/required pre-transport approval
→ exactly one provider invocation
→ required sanitizer and target-binding check, when applicable
→ output-schema validation
→ immutable attempt publication
→ optional exact comparison or explicit rescore
```

There is no hidden retry, fallback, parallel execution, or scheduler.

## Quick start

Requirements: Node.js 24.15.0 or later, below Node.js 25, and npm 10, 11, or 12.

```bash
npm install
npm run verify
```

Validate the complete synthetic bundle:

```bash
npm run bundle:check -- fixtures/synthetic/invoice-basic
npm run bundle:check -- fixtures/synthetic/invoice-basic --json
```

Run one deterministic synthetic attempt:

```bash
./scripts/svbench.mjs run \
  --bundle fixtures/synthetic/invoice-basic \
  --provider mock \
  --model mock-v1 \
  --effort medium \
  --max-tokens 512 \
  --attempt-key dev-001 \
  --attempt-root /tmp/svbench-attempts \
  --json
```

Compare the finalized attempt with its execution bundle:

```bash
./scripts/svbench.mjs compare \
  --bundle fixtures/synthetic/invoice-basic \
  --attempt /tmp/svbench-attempts/<attempt-id> \
  --json
```

CI and public tests use only synthetic fixtures and fake local processes. They never invoke a real
model, login flow, or network provider.

## Bundle and data boundary

A bundle contains the prepared image, output schema, system preamble, document-specific instruction,
optional truth projection, comparison policy, and bounded consumer metadata. Provider/model/effort,
approval, sanitizer, policy, and attempt settings are run configuration and never enter the bundle.

```text
case-directory/
├── bundle.json
├── prepared-image.png
├── schema.json
├── system.txt
├── instruction.txt
└── truth.json          # optional
```

The validator checks the manifest schema, path containment, regular-file boundary, exact digests,
strict UTF-8/JSON, the supported output-schema definition, comparison pointers, and optional truth
projection before provider work. The full rules are in [`docs/bundle-v1.md`](docs/bundle-v1.md).

Real documents, truth, model output, policy, approval snapshots, credentials, account metadata, and
private paths must remain outside Git history. A real bundle is passed to a local checkout from
confidential storage; this public repository does not upload it.

## Provider and policy boundaries

The mock provider is deterministic and exists for contract tests. The command provider invokes a
consumer-owned local adapter without a shell and exposes only the verified extraction inputs after
the adapter reattests its approved transport binding. Hosted model payloads must contain only the
prepared image, schema, system, instruction, and requested model settings.

Approval is a pre-transport decision. A required gate must succeed and match the expected opaque
snapshot/runtime/scope identities before any provider input is released. Sanitization is a separate
post-provider, pre-finalization decision. Required runs finalize only the sanitized document after
current target, policy target, and binding identities match. Policy-not-required runs omit the
sanitizer/policy block rather than creating empty or dummy identities.

The Codex app-server route is an explicitly selected experimental transport. Automated tests use a
fake process only. Real-data use additionally depends on the consuming application's private
approval and persistence-audit decisions; this repository does not manage credentials or declare an
upstream runtime safe by itself.

## Intentionally unsupported

The active implementation does not include:

- suite manifests or all-case preflight;
- repeat loops, retry, fallback, or parallel execution;
- resume or stale-owner recovery;
- suite-run directories, slot events, ledgers, or hash chains;
- aggregate suite reports or dashboards; or
- production prompt/schema/business-validation logic.

Observed experimental need and explicit owner approval are required before any of these return.

## Development

Read [`AGENTS.md`](AGENTS.md) before changing the repository. Use one Issue, one branch, and one pull
request. Contract changes must update their normative document, schema, implementation, tests, and
any affected Eldorad lock in one coordinated change.

## License and affiliation

MIT licensed. This project is not affiliated with or endorsed by OpenAI, ChatGPT, Codex, Anthropic,
or another model provider.
