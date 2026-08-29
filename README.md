# structured-vision-bench

A deliberately small harness for one structured-vision experiment at a time.

It reads one case, invokes either a checked-in mock output or one local provider command, validates
the returned JSON against a small documented JSON Schema subset, and optionally compares it with an
exact truth document.

## Scope

The active implementation intentionally supports only:

- one case per invocation;
- one provider invocation, with no retry;
- mock output for CI or a local stdin/stdout command;
- a small JSON Schema subset;
- exact JSON comparison with path-only diagnostics.

It does **not** implement suites, repeats, resume, ledgers, hash chains, approval gates, sanitizer
protocols, provider-specific transports, credential management, or production-grade isolation. Git
history retains the earlier experiments; they are not part of the active contract.

## Case format

A case directory contains `case.json`:

```json
{
  "image": "image.svg",
  "schema": "schema.json",
  "system": "system.txt",
  "instruction": "instruction.txt",
  "truth": "truth.json",
  "mockOutput": "mock-output.json"
}
```

`image`, `schema`, and `instruction` are required. `system`, `truth`, and `mockOutput` are optional.
All references must resolve to regular files inside the case directory.

The supported schema keywords are:

```text
$schema, title, description, type, required, properties,
additionalProperties, items, enum, const
```

Supported types are `object`, `array`, `string`, `number`, `integer`, `boolean`, and `null`.
Anything else is rejected as `unsupported_schema` rather than being silently ignored.

## Run with the synthetic mock

```bash
npm test
node src/svbench.js run --case fixtures/synthetic-invoice --mock
```

Exit status is `0` for a pass, `1` for schema/truth failure, and `2` for invalid configuration or a
provider failure.

## Run a local provider command

```bash
node src/svbench.js run \
  --case fixtures/synthetic-invoice \
  --provider node \
  --provider-arg examples/mock-provider.js
```

The provider receives one JSON object on stdin:

```json
{
  "version": 1,
  "imagePath": "/absolute/local/path/image.svg",
  "schema": {},
  "system": "...",
  "instruction": "..."
}
```

It must write exactly one JSON document to stdout and exit `0`. The harness invokes the command
without a shell. A real provider adapter, login flow, API client, and retention policy belong outside
this repository.

## Results

Results contain status flags plus bounded issue records such as:

```json
{
  "path": "/total",
  "kind": "different"
}
```

Truth and output values are deliberately omitted from diagnostics. Use `--output result.json` to
also write the result locally. Do not commit private cases or results.
