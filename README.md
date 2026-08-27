# structured-vision-bench

Reproducible benchmarks for schema-guided structured extraction from document images.

`structured-vision-bench` defines a portable case bundle, validates that bundle without following
unsafe paths, and provides a public home for model-runner and comparison tooling. It is designed for
teams that must keep real documents, truth data, prompts, provider credentials, and production
adapters outside a public repository.

> **Status:** bundle v1 validation and the deterministic single-case mock runner are available.
> Codex app-server support, comparison reports, repeat runs, and private command adapters remain
> tracked in Issues [#3](https://github.com/TakahisaI/structured-vision-bench/issues/3) through
> [#6](https://github.com/TakahisaI/structured-vision-bench/issues/6). Approval and sanitizer
> process protocols are tracked separately in Issues #8 and #9.

## What belongs here

- A versioned, provider-neutral benchmark bundle contract.
- Safe local validation of bundle manifests and referenced files.
- Synthetic fixtures that contain no real person, transaction, document, or model response.
- Provider interfaces and test doubles.
- Single-case `svbench run --provider mock` execution with consumer-attested sanitizer requirements,
  atomic formal attempts, and sanitizer output when the consumer requires it.
- Comparison, reporting, repeat, and resume logic implemented by later issues.

## What does not belong here

- Production prompts, schemas, preprocessing rules, or API clients owned by another application.
- Real document images, human-created truth for real documents, or real model output.
- OAuth credentials, API keys, authorization URLs or codes, account identifiers, or token stores.
- CI jobs that call Codex, ChatGPT, OpenAI Platform, Anthropic, or another hosted model.
- Telemetry or automatic upload of bundles, attempts, or reports.

See [the security boundary](docs/security.md) before adding fixtures or provider code.

## Quick start

Requirements: Node.js 24.15.0 or later, below Node.js 25, and npm 10, 11, or 12.

```bash
npm install
npm run verify
```

Validate the complete synthetic bundle directly:

```bash
npm run bundle:check -- fixtures/synthetic/invoice-basic
npm run bundle:check -- fixtures/synthetic/invoice-basic --json
```

Run the public synthetic fixture with the deterministic mock provider:

```bash
./scripts/svbench.mjs run \
  --bundle fixtures/synthetic/invoice-basic \
  --provider mock \
  --model mock-v1 \
  --effort medium \
  --max-tokens 512 \
  --attempt-root /tmp/svbench-attempts \
  --json
```

The runner exclusively claims the run-identity directory before provider work. The successful attempt
contains only `attempt.json` and the formal `document.json` under the chosen attempt root; the final
manifest is published with a no-replace filesystem operation only after its complete bytes have been
validated. The pending manifest is staged outside the final run directory in a private
`.claims/<nonce>/` directory, so the final manifest link is the sole transition to the reader-visible
shape; cleanup of that source is best effort after publication. When the consumer decision requires a
sanitizer, that document is the sanitizer output.
Not-required attempts omit sanitizer/policy/target-binding blocks rather than storing null placeholders.
The runner bounds each staged provider input to 16 MiB and revokes provider read callbacks after
provider execution settles.
See [`docs/attempt-v1.md`](docs/attempt-v1.md) and
[`schemas/attempt-v1.schema.json`](schemas/attempt-v1.schema.json) for the lifecycle and manifest
contract. CI and public fixtures use the mock provider only; no real model or login flow is run.
The mock provider is deterministic and schema-valid for the validator's supported synthesis subset,
including local `$ref` with supported sibling constraints and simple `allOf` intersections; it is not
a general-purpose JSON Schema instance generator.

The validator performs these checks before the selected provider can run:

1. `bundle.json` conforms to [`schemas/bundle-v1.schema.json`](schemas/bundle-v1.schema.json).
2. The output schema is a supported, locally referenced JSON Schema subset and is meta-validated
   before provider invocation.
3. Every reference is a normalized relative path inside the bundle root.
4. Referenced inputs are regular files, not symbolic links.
5. Each referenced file matches its declared SHA-256 digest, read from the same bytes that are
   parsed or handed onward.
6. Referenced schema and optional truth files contain valid JSON under the byte-exactness contract
   (strict UTF-8 without a leading BOM, Unicode scalar strings, no duplicate object members,
   binary64 numbers only), and system/instruction text files use the same UTF-8-without-BOM rule.
7. The comparison pointer contract holds: RFC 6901 pointers with at most one whole-segment `*`
   wildcard, allowed only in `critical` entries and only pointing at declared arrays and compared
   fields (`comparison_contract_invalid` otherwise).
8. When truth exists, its projection is validated before provider invocation — every declared scalar, array,
   key, and compared field must resolve with sound keys and types
   (`truth_contract_invalid` otherwise).

## Bundle overview

```text
case-directory/
├── bundle.json
├── prepared-image.png
├── schema.json
├── system.txt
├── instruction.txt
└── truth.json          # optional
```

A bundle is immutable input. Attempt output is stored outside the bundle and must not silently
rewrite it. The full contract, path rules, validation order, and versioning policy are in
[`docs/bundle-v1.md`](docs/bundle-v1.md).

## Repository layout

```text
.github/workflows/     Public CI; never invokes a real provider
schemas/               Machine-readable public contracts
docs/                  Architecture, security, bundle, and attempt specifications
fixtures/synthetic/    Fictional, redistributable test cases
src/bundle/             Contract validation library
src/cli/                Local command-line entry points
scripts/                Dependency-light development tooling
test/                   Node.js test-runner suites
```

## Design principles

- **Production stays private.** A consuming application remains the source of truth for its prompt,
  schema, preprocessing, validation, and API provider.
- **The route is part of the result.** Subscription-backed exploration and production API
  calibration are distinct provider routes even when model names look similar.
- **Unknown is not zero.** Missing usage, model, effort, or stop-reason metadata is recorded as
  unavailable rather than guessed.
- **Fabrication is not a missed field.** Later comparison work keeps invented values and extra rows
  visible instead of hiding them in one average score.
- **CI is offline with respect to models.** Public automation uses synthetic fixtures and fake
  providers only.

## Development

Read [`AGENTS.md`](AGENTS.md) before changing the repository. Work is tracked as one Issue, one
branch, and one pull request. The first contract and repository bootstrap are defined by
[Issue #1](https://github.com/TakahisaI/structured-vision-bench/issues/1); the single-case runner
is defined by [Issue #2](https://github.com/TakahisaI/structured-vision-bench/issues/2).

## License and affiliation

MIT licensed. This project is not affiliated with or endorsed by OpenAI, ChatGPT, Codex, Anthropic,
or any other model provider.
