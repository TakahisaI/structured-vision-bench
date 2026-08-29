# Suite slot event v1

Suite slot event v1 is the pure, value-free transition contract for the deterministic slots in a
validated suite-run manifest. This contract defines record identity and reduction only. Ledger
directories, filesystem reads, and atomic append are separate lifecycle boundaries.

The machine-readable shape is
[`schemas/suite-slot-event-v1.schema.json`](../schemas/suite-slot-event-v1.schema.json).

## Record shape and identity

Each event fixes the suite-run ID; global sequence and previous event ID; canonical UTC timestamp;
case/repeat position; attempt key, run ID, and attempt ID; previous and next status; a bounded stable
failure code; and a value-free outcome identity digest. `running` has neither failure code nor
outcome digest. `succeeded` has an outcome digest and no failure code. `failed`, `cancelled`, and
`interrupted` have both.

The outcome digest is derived rather than supplied by the caller. It is SHA-256 over the raw ASCII
domain `svbench-suite-slot-outcome-v1`, a four-byte unsigned big-endian byte length, and compact
UTF-8 JSON in this exact order: `suiteRunId`, `recordedAt`, `caseIndex`, `repeatIndex`, `attemptKey`,
`runId`, `attemptId`, `status`, and `failureCode`. It identifies each value-free non-running
transition outcome independently of its ledger sequence and previous-event link. It is not a
terminal-state marker: an `interrupted` outcome has a digest and remains resumable. The exported
helper and event builder use the same derivation.

For the synthetic succeeded event at `2026-01-02T03:04:08.000Z`, the fixed outcome identity is:

```text
aae6b3af26587b1554844ff338d3ec9a10e30364858efee242669c4b27afe433
```

`eventId` is SHA-256 over the raw ASCII domain `svbench-suite-slot-event-v1`, a four-byte unsigned
big-endian byte length, and compact UTF-8 JSON for a freshly constructed event object containing
every member except `eventId`, in schema order. The canonical encoder inserts `eventId` after
`previousEventId` and appends one newline.

For the synthetic one-slot suite manifest used by the contract tests, the first `pending → running`
event at `2026-01-02T03:04:05.006Z` has this fixed identity:

```text
b6e2992791930149bcfbfa5e8e9a29a1441160cab5781a994cf99ec83dfc8056
```

The reader bounds each record at 8 KiB before strict UTF-8 decoding. It rejects a BOM, duplicate or
unknown members, accessors in runtime input, partial or concatenated JSON, noncanonical timestamps,
invalid status-dependent fields, and identity mismatch. Successful reads return fresh frozen data.
Byte readers accept local-realm `Uint8Array` views (including `Buffer`), use intrinsic typed-array
metadata, reject shared, detached, proxy-wrapped, and foreign-realm storage, enforce the byte bound
before copying, and never trust caller shadow properties.

## Reduction

The immutable manifest supplies every slot and its initial `pending` state; no pending event is
stored. Events form one suite-wide sequence starting at zero. The first record has a null previous
ID, and each later record names the immediately preceding event ID. Timestamps may be equal but
must not move backwards.

The legal transitions are:

- `pending → running`
- `running → succeeded | failed | cancelled | interrupted`
- `interrupted → running`

`succeeded`, `failed`, and `cancelled` are terminal. An interrupted slot may resume, but its complete
history remains in the reduced result. Failure codes are limited to the versioned built-in runner
codes or sanitizer failure codes already fixed by the suite-run manifest.
`cancelled` uses only `execution_cancelled`, `interrupted` uses only `execution_interrupted`, and
those two state-control codes are invalid for `failed`. Sanitizer codes retain the existing
suite-manifest safe-label alphabet.

The reducer rejects a foreign suite or slot identity, gaps, forks, replay, illegal transition,
duplicate terminal outcome, timestamp rollback, and failure code outside the preflighted set. It
returns the complete ordered event chain and one frozen current-state/history view per manifest
slot.

## Security boundary

Records contain no raw document, policy, case ID, path, secret, or absolute path. Errors expose only
stable codes and fixed messages.

The chain detects modification, gaps, middle deletion, and reordering in the records presented to
the reducer. The official append API will not expose delete or overwrite operations. Without a
signed or externally trusted monotonic head, however, a hash chain alone cannot prove that a tail
was never truncated, and it does not protect against a same-UID attacker rewriting an entire
suffix. Those stronger threats require a separate design.
