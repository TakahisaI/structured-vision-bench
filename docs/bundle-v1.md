# Benchmark bundle v1

## Role

A bundle is immutable input for one schema-guided extraction case. It captures what a model should
receive and how a later comparison should align the result with optional truth. It does not contain
provider credentials, an executable command, or attempt output, and it does not select execution
settings. Requested model, effort, token limit, and repeat settings belong to runner or suite
configuration and are recorded in the attempt, not in the bundle.

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
- `caseId`: stable opaque identifier of 1 to 128 characters, beginning with a lowercase ASCII
  letter or digit and continuing with lowercase ASCII letters, digits, `.`, `_`, or `-`.

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

#### Truth shape

Optional `truth` is a **comparison projection**, not a full output-schema instance:

1. It must contain a value at every declared `scalars` pointer.
2. For each declared array, it must contain an array at the array path whose elements carry that
   array's `key`, and each field listed in `fields[]`. Elements are not required to appear in any
   particular order.
3. Fields outside `scalars` and the declared arrays' `key`/`fields` may be omitted — including
   model-only fields such as self-reported confidence, which must never be invented as human truth
   or added to a score denominator.

Because the truth file is part of the bundle and exists at preflight time, the projection contract
is validated during bundle preflight. When `inputs.truth` is present, a conforming reader checks all
of the following before any provider call:

- the truth root is an object;
- every declared scalar pointer resolves to a JSON scalar (string, number, boolean) or `null`;
- every declared array path resolves to an array;
- every element of each such array is an object carrying that array's `key` and every field listed
  in its `fields[]`; unrelated extra fields on an element are allowed;
- each key value is a string or number that is not `null`, and a string key is not empty after
  normalization;
- each projected `fields[]` value is a JSON scalar or `null`; an object or array is not a scalar
  comparison value;
- normalized key values are unique within the array.

Any violation fails preflight with the stable code `truth_contract_invalid`. An invalid truth must
never reach a paid provider run.

An intentionally absent value is represented as explicit `null` at the projected path, never by an
empty string or a missing key inside a projected object. The provider never receives the truth,
comparison policy, or any past attempt output; they stay on the comparison side of the boundary.

### Comparison

`comparison` declares data alignment without implementing the comparison algorithm:

- `scalars`: pointers compared as scalar values;
- `arrays`: array paths, element key paths, and compared fields;
- `critical`: pointers whose failure is evaluated separately from an average score;
- `normalization`: explicit string operations and exact number comparison.

`normalization.strings` may contain each of these operations at most once. Only operations declared
in that array are enabled. Enabled operations are applied to the truth string and the actual string
independently, in this canonical order regardless of declaration order:

- `nfkc`: Unicode NFKC normalization;
- `trim`: remove leading and trailing whitespace;
- `collapse-whitespace`: replace each whitespace run with a single U+0020 SPACE.

Omitting `nfkc` therefore preserves compatibility characters exactly; it is never applied as an
implicit baseline operation.

`trim` and `collapse-whitespace` use one fixed set of Unicode whitespace characters: U+0009, U+000A,
U+000B, U+000C, U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000 through U+200A, U+2028, U+2029,
U+202F, U+205F, and U+3000.

Normalization applies only to strings. Numbers are compared exactly
(`normalization.numbers: "exact"`). Number `1` and string `"1"` do not match; normalization never
converts between numbers and strings. Only JSON `null` means "no value": a normalized empty string
is still a string and is never treated as `null`, so truth `null` against actual `" "` is a
fabricated value, not a match. Bundle v1 defines no other normalization — no currency or digit-group
stripping. A consumer that needs formatted-number normalization must wait for a new `bundleVersion`
that names the affected paths explicitly.

### Absence and field denominators

Field-level `total`, `matched`, `missed`, `fabricated`, and `wrong` use the following rules after
applying declared normalization:

| Truth value | Actual value | Outcome | Field `total` |
| --- | --- | --- | --- |
| `null` | `null` | no mismatch; not `matched` | do not increment |
| `null` | present scalar | `fabricated` | increment once |
| present scalar | `null` | `missed` | increment once |
| present scalar | present scalar | `matched` or `wrong` | increment once |
| missing path | any | preflight failure for truth, or `comparison_error` for output | do not treat as a normal field value |

An empty string, number `0`, and boolean `false` are present values. A string that becomes empty
after normalization remains a present string. Different JSON scalar types are `wrong`; they are not
coerced.

Array membership and field denominators are separate:

- every truth element absent from output increments array `missing` once as `missing_item`;
- for that missing element, only truth-side non-`null` entries explicitly listed in `fields[]`
  increment their field `missed` and `total`;
- every output element absent from truth increments array `extra` once as `extra_item`;
- for that extra element, only actual-side non-`null` entries explicitly listed in `fields[]`
  increment their field `fabricated` and `total`;
- `null` fields inside missing or extra elements do not enter a field denominator;
- the alignment `key` belongs to membership accounting and key-critical gates. It enters ordinary
  field accounting only when the same pointer is also explicitly listed in `fields[]`.

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

#### Critical membership

A wildcard critical entry whose field is the array's **key**
(`<array-path>/*/<key>`) makes that array *membership-critical*. For such an array, all of the
following are critical failures:

- a truth element missing from the result (`missing_item`);
- a result element missing from truth (`extra_item`);
- an unresolved array path;
- a missing key on either side;
- a `null` key;
- a string key that is empty after normalization;
- duplicate keys — including duplicates that appear only after normalization.

A wildcard critical entry naming any other declared field
(`<array-path>/*/<field>`) marks every field mismatch on already-paired items as critical —
including `missed` (truth value present, actual `null`) and `fabricated` (truth `null`, actual
present), not only `wrong`. By itself it does not make element surplus or shortage critical. An
unresolved critical path is a comparison failure and, for critical entries, a hard-gate failure; it
is never silently converted to an ordinary value. A consumer that treats line-item surplus or
shortage as a hard gate must declare `<array-path>/*/<key>` in `critical` for that document kind.

The schema rejects syntax violations. Cross-field rules — duplicate array paths, scalars that
duplicate an array path, and critical entries referencing undeclared arrays or un-compared fields —
fail validation with the stable code `comparison_contract_invalid`.

Evaluation context is always the bundle root. `scalars` and whole-array `arrays[].path` entries are
root-relative. `arrays[].key` and `arrays[].fields[]` are evaluated against one array element.
Wildcard evaluation resolves the array at its prefix, then applies `<field>` to each element.

An unresolved comparison path is a comparison error, not a bundle error, **for provider output**:
whether `/totalAmount` will exist in a particular model result is decided when the comparison runs.
Bundle validation checks only the syntax and cross-field rules above. The exception is the optional
truth file, which already exists inside the bundle and is therefore validated against its projection
contract during preflight (see Truth shape).

### Metadata

Required metadata identifies the consumer-owned extraction contract. Each metadata identifier is
bounded to 64 ASCII characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`, so copied attempt
metadata cannot carry a local path or unbounded diagnostic:

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

Image and text inputs have no bundle-v1 source-file size limit. Image bytes are verified by digest;
text bytes are verified by digest and strict UTF-8 decoding. The Issue #2 runner applies a separate
16 MiB per-provider-input staging/snapshot limit and reports `runner_input_too_large` when it is
exceeded. Changing the JSON limits changes bundle-v1 behavior and requires a new `bundleVersion`;
changing the runner staging limit is a runner contract change.

## Byte-exactness contract

Bundle v1 is portable input: every conforming reader of the same bytes must see the same values.

- **Encoding.** `bundle.json`, the referenced schema, truth, `system.txt`, and `instruction.txt`
  are UTF-8 without a leading UTF-8 BOM. Invalid UTF-8 byte sequences and a leading BOM are
  validation failures — readers must not silently replace invalid bytes with U+FFFD or strip a
  BOM, because the same digest would then yield different values or prompts per platform.
- **Unicode scalar values.** JSON strings, including object member names, contain only Unicode
  scalar values. An escaped high surrogate is valid only when immediately followed by an escaped
  low surrogate; a lone low surrogate and every other unpaired surrogate escape are invalid.
  Valid surrogate pairs represent their corresponding scalar value.
- **Duplicate object members.** A JSON object with two occurrences of the same member name is
  invalid. Last-wins silently changes values while the digest stays identical.
- **Number domain.** JSON numbers are IEEE-754 binary64 values. Numbers whose parse overflows to
  an infinity (for example `1e400`) are invalid. Values that binary64 rounds (for example
  `9007199254740993` reading as `9007199254740992`) are valid, and that rounding is part of the
  contract: number comparison happens after it, never before. Number keys and string keys never
  equal each other even when their digits match.
- **Read-once rule for validators.** A validator computes digests and parses each bounded JSON file
  from one read of the same bytes, and re-verifies the digest when it opens a referenced JSON file
  again, so projection and syntax checks cannot apply to different bytes than the manifest
  committed to. The runner (Issue #2) owns the corresponding rule for provider inputs: after
  preflight succeeds, provider inputs come from the verified bytes or staged copies — never from a
  fresh open of the original bundle directory. For unbounded text inputs, digesting and strict
  UTF-8 validation use the same streaming read.

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
5. Every referenced digest matches; `system.txt` and `instruction.txt` are decoded as strict UTF-8
   without a leading BOM during that same streaming read.
6. Referenced schema and optional truth files parse as JSON.
7. Runner-specific or provider-specific checks occur only after bundle preflight succeeds.

A failed preflight must not call a provider.

## Input and output lifecycle

Bundle files are input and remain unchanged for the lifetime of a measurement. An attempt is a
separate directory with its own manifest and digests. The Issue #2 runner stages provider inputs
outside the bundle, exclusively claims the run-identity directory, validates the formal document
(sanitizer output when configured), and writes `attempt.json.pending` to a private same-filesystem
`.claim-<nonce>/` staging directory before publishing it by no-replace hard link as `attempt.json`.
The final link is the visibility point for the exact two-file attempt shape; source cleanup is best
effort. The runner bounds each staged provider input to 16 MiB; this is an operational runner limit
and does not change bundle-v1 source-file validation.
Failed runs and directories without the final manifest do not become formal attempts.

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
