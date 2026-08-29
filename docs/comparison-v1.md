# Comparison result v1

## Scope

Comparison v1 scores one finalized attempt against one validated bundle truth projection. It owns
scalar and array alignment, error classification, critical hard gates, a machine-readable result,
and a deterministic single-case Markdown view. It does not invoke a provider or sanitizer, change an
attempt, implement semantic similarity, or aggregate multiple attempts.

The normative pointer, normalization, absence, denominator, and critical-membership rules remain in
[`bundle-v1.md`](bundle-v1.md). The machine-readable result shape is
[`comparison-v1.schema.json`](../schemas/comparison-v1.schema.json).

## CLI

Normal comparison requires the exact execution bundle:

```bash
svbench compare \
  --bundle <bundle-directory> \
  --attempt <attempt-directory> \
  [--json]
```

Human mode prints Markdown. `--json` prints `{ "ok": true, "result": ... }`. Neither form includes
truth values, extracted values, case IDs, comparison pointers, or local paths. JSON may copy a
concrete value-free sanitizer finding path that the runner already matched against the consumer's
exact or single-array-wildcard allowlist. Markdown does not render finding paths. Field and array
locations are represented only by their
zero-based declaration positions.

An old attempt may be scored against corrected truth or comparison policy only through explicit
rescoring:

```bash
svbench compare \
  --bundle <scoring-bundle-directory> \
  --attempt <attempt-directory> \
  --rescore \
  --rescore-reason <safe-label> \
  [--json]
```

The reason is an opaque `[A-Za-z0-9._-]` label of 1–64 characters. `--rescore` without a reason, or a
reason without `--rescore`, is an invalid CLI argument.

## Identity boundary

`readAttempt()` first verifies the attempt-ID parent, its sole artifact-ID child, the immutable
two-file artifact, attempt/run/artifact identities, exact stored document digest, requirement
decision, and sanitizer policy binding. The scoring bundle then passes
the complete bundle validator before comparison.

Normal mode requires all of these values to match:

- bundle version and exact execution bundle manifest digest;
- case ID and document kind;
- prompt, preprocess, and source-commit provenance;
- media type and digest for image, schema, system, and instruction inputs.

Explicit rescoring permits the scoring bundle manifest digest to differ, but still requires every
other value above to match. Thus only truth, comparison policy, or manifest references caused by
those scoring inputs may change. A prepared image, schema, system, instruction, case identity, or
provenance change requires a new provider attempt.

The result records execution and scoring bundle digests separately, the four provider-input
identities, attempt/run/artifact/case-input identities, exact formal document digest, sanitizer identity and
value-free findings, and the explicit rescore reason.

## Classification and aggregation

Scalar and declared array fields use the bundle-v1 classifications `missed`, `fabricated`, `wrong`,
and `comparison_error`. Array alignment additionally records `missing_item` and `extra_item`.
Alignment is order-independent and uses the declared key after only the declared string
normalizations. String and numeric keys remain different types.

Missing paths, non-scalar compared values, invalid keys, duplicate normalized keys, and unresolved
array paths are comparison errors; they are never converted to `null` or arbitrarily paired. A
truth/output `null` pair is neither a mismatch nor part of the field denominator. Missing and extra
items add only their non-null declared fields to field totals; the alignment key is not implicitly a
field.

Critical scalar and matched-item field mismatches fail the comparison hard gate. Missing or extra
items fail it only when the declared array key is critical. A sanitizer finding with `hardGate: true`
also fails the hard gate but is never folded into field accuracy. Its bounded value-free path is
copied from the validated attempt as either `null` or a concrete JSON Pointer matched by the
committed exact or single-wildcard consumer pattern; comparison never reconstructs a path from
document values.

The JSON result contains:

- aggregate field and array statistics;
- aggregate outcome counts;
- per-declaration-position field and array statistics;
- comparison and sanitizer hard-gate counts;
- bounded, value-free warning codes and declaration positions;
- scoring revision and result digest.

Markdown numbers are rendered directly from this JSON result, so its principal metrics can be
recomputed from the machine-readable artifact.

## Revision and result digests

`scoringRevision` is a domain-separated digest of the exact scoring bundle manifest digest:

```text
SHA256("svbench-scoring-revision-v1" || LP_UTF8(scoringBundleDigest))
```

`resultDigest` covers the complete result except `resultDigest` itself:

```text
SHA256("svbench-comparison-result-v1" || LP_UTF8(canonicalJson(resultCore)))
```

`LP_UTF8` is a four-byte big-endian byte length followed by UTF-8 bytes. `canonicalJson` preserves
array order and sorts every object key lexicographically before compact JSON encoding. Digests are
lowercase hexadecimal.

Each scoring revision creates a new result; comparison never overwrites or silently combines an
older revision. Frozen-study acceptance policy remains consumer-owned and must not be rescued by a
post-holdout scoring change.

## Data boundary

The comparer never sends truth, comparison policy, attempt content, or findings to a provider or
sanitizer. Diagnostics use fixed messages and stable codes without echoing pointers, values, digests,
or absolute paths. Automated tests use only fictional bundles, documents, truth corrections, and
sanitizer findings.
