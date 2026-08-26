# Benchmark bundle v1

## Role

A bundle is immutable input for one schema-guided extraction case. It captures what a model should
receive and how a later comparison should align the result with optional truth. It does not contain
provider credentials, an executable command, or attempt output.

The machine-readable manifest contract is
[`schemas/bundle-v1.schema.json`](../schemas/bundle-v1.schema.json).

## Directory layout

```text
case-directory/
├── bundle.json             required manifest
├── prepared-image.png      required image or PDF selected by the manifest
├── schema.json             required expected-output JSON Schema
├── system.txt              required stable system preamble
├── instruction.txt         required document-specific instruction
└── truth.json              optional human-created truth
```

Filenames are examples. The manifest is authoritative.

## Manifest fields

### Identity

- `bundleVersion`: integer `1`.
- `caseId`: stable opaque identifier using lowercase ASCII letters, digits, `.`, `_`, or `-`.

A public fixture may have a descriptive case ID. A real confidential case ID must not be copied to
GitHub.

### Inputs

`inputs` contains four required file references and one optional truth reference:

- `image`: prepared image or PDF and its media type;
- `schema`: JSON Schema for the structured model output;
- `system`: stable system preamble;
- `instruction`: case or document-kind instruction;
- `truth`: optional JSON truth.

Each reference contains:

- `path`: normalized forward-slash relative path inside the bundle root;
- `sha256`: lowercase SHA-256 digest of the exact file bytes;
- `mediaType`: explicit content type.

The original source document does not need to be copied into a bundle. A consumer may export only
the exact prepared representation used for model input, while retaining provenance privately.

### Comparison

`comparison` declares data alignment without implementing the comparison algorithm:

- `scalars`: pointers compared as scalar values;
- `arrays`: array paths, element key paths, and compared fields;
- `critical`: pointers whose failure is evaluated separately from an average score;
- `normalization`: explicit string operations and exact number comparison.

Bundle v1 does not define semantic similarity, edit-distance acceptance, fuzzy row matching, or an
LLM judge. A missing or duplicate array key must not be silently paired with an arbitrary element.

#### Comparison pointer language

Comparison paths are RFC 6901 JSON Pointer strings with one extension:

1. Every pointer starts with `/`, has at least one segment, and is at most 512 characters.
2. A segment that is exactly `*` matches every element of the array addressed by the preceding
   segments (a wildcard). A `*` inside a segment, such as `/li*nes`, is always a literal property
   name.
3. `~0` and `~1` escapes follow RFC 6901. Any other `~` sequence is invalid.
4. Wildcards appear only in `critical` entries — at most one per pointer, never as the last
   segment. `scalars`, `arrays[].path`, `arrays[].key`, and `arrays[].fields[]` are plain pointers
   without wildcards; `key` and `fields[]` name fields of one array element with a single segment.
5. A `critical` entry must be either a declared scalar (`comparison.scalars`) or
   `<declared-array-path>/*/<field>`, where `<field>` equals that array's `key` or one of its
   declared `fields`. A critical entry must not address a whole array.

The schema rejects syntax violations. Cross-field rules — duplicate array paths, scalars that
duplicate an array path, and critical entries referencing undeclared arrays or un-compared fields —
fail validation with the stable code `comparison_contract_invalid`.

### Metadata

Required metadata identifies the consumer-owned extraction contract:

- `documentKind`;
- `promptVersion`;
- `preprocessVersion`.

`sourceCommit` is optional. It may be a source revision or another immutable consumer version. Real
bundle metadata remains confidential when it can identify a private corpus or repository state.

## JSON size limits

A conforming reader refuses to parse any of the three JSON files above 4 MiB (`4194304` bytes):

| File | Limit | Failure code |
| --- | --- | --- |
| `bundle.json` (manifest) | 4 MiB | `json_file_too_large` |
| referenced output schema (`inputs.schema`) | 4 MiB | `json_file_too_large` |
| referenced truth (`inputs.truth`) | 4 MiB | `json_file_too_large` |

Image and text inputs have no size limit at this layer; their bytes are verified by digest only.
Raising or lowering a limit changes machine behavior and requires a new `bundleVersion`.

## Path rules

A file reference is valid only when all of these are true:

1. It is non-empty and relative.
2. It uses `/`, not `\`.
3. It contains no empty, `.`, or `..` segment.
4. Its normalized form is identical to the declared value.
5. The referenced entry is a regular file, not a symbolic link.
6. Its canonical location remains under the canonical bundle root.
7. Its bytes match the declared SHA-256 digest.

The bundle root itself must not be a symbolic link.

## Validation order

A conforming implementation validates in this order:

1. Bundle root exists, is a directory, and is not a symbolic link.
2. `bundle.json` is bounded in size and parses as JSON.
3. The manifest conforms to bundle v1 and uses a known version.
4. Every reference passes path and regular-file checks.
5. Every referenced digest matches.
6. Referenced schema and optional truth files parse as JSON.
7. Runner-specific or provider-specific checks occur only after bundle preflight succeeds.

A failed preflight must not call a provider.

## Input and output lifecycle

Bundle files are input and remain unchanged for the lifetime of a measurement. An attempt is a
separate directory with its own manifest and digests. Future runner work will stage an attempt,
validate it, and then rename it to a final location.

Retries are not hidden. A repeat or retry is a new attempt with a distinct identity and recorded
reason. Failed output is not rewritten as success.

## Versioning

Bundle v1 is closed to unknown top-level and nested manifest properties. A backward-incompatible
change requires a new `bundleVersion` and schema file. Readers fail closed on unknown versions.

Documentation corrections that do not change machine behavior may update this document without
changing the bundle version.

## Synthetic example

[`fixtures/synthetic/invoice-basic`](../fixtures/synthetic/invoice-basic) is a complete fictional
bundle. Its image is visibly marked as synthetic and does not represent a real transaction.
