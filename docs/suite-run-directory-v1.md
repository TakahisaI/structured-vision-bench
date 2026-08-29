# Private suite run directory v1

This contract publishes one verified [`suite-run-v1`](suite-run-v1.md) manifest and initializes its
private suite-slot ledger as one immutable local run layout. It also defines the local atomic append
boundary for value-free suite-slot events. It performs no approval, provider, sanitizer, slot
execution, resume decision, or report work.

## Final layout and visibility

Given a caller-owned private root, the final layout is exactly:

```text
<root>/<suiteRunId>/suite-run.json
<root>/<suiteRunId>/slot-ledger/
```

The root, run directory, and ledger directory have exact mode `0700`; the manifest and ledger
records have exact mode `0600`. Entries must be owned by the current effective user. The
run-directory basename is the external suite-run identity anchor. A directory is formal only when
it contains exactly the final manifest plus the private ledger directory and the strict manifest
reader confirms that its recomputed `suiteRunId` equals that basename.

The publisher canonicalizes, bounds, and strictly rereads the supplied manifest before changing the
filesystem. It then:

1. opens and records the stable private root;
2. claims `<suiteRunId>` with a non-recursive exclusive directory creation;
3. writes a private owner-nonce marker in that claim;
4. creates a private same-filesystem sibling `.suite-run-claim-<nonce>` directory;
5. writes, syncs, rereads, byte-compares, and identity-validates `suite-run.json.pending` there;
6. creates `slot-ledger/`, records its identity, verifies that it is empty, and syncs both the ledger
   and its parent run directory;
7. removes the owner marker and revalidates the ledger-only final directory and every recorded
   identity;
8. creates `suite-run.json` with a no-replace hard link from the complete pending file; and
9. syncs the final directory and root before best-effort removal of the staging source.

The hard link in step 8 is the sole commit and visibility point. An existing digest claim or final
entry is never replaced. Two publishers therefore have at most one winner. Publication reports
ordinary success only after final file/path verification and the required file, run-directory, and
root syncs complete. A failure in that post-link completion boundary reports
`suite_run_publication_uncertain` and leaves the possible publication untouched. Once completion is
confirmed, later staging-cleanup or test-hook failure cannot reverse publication or turn it into a
failure.

## Reader and failure boundary

The ledger is empty at publication; every manifest slot therefore starts implicitly as `pending`.
The strict reader later accepts only regular record files named `00000.json` through `99999.json`
without gaps. Each file is limited to 8 KiB, the complete ledger is limited to 100,000 records and
64 MiB of stored record bytes, and each filename sequence must equal the canonical record sequence.
Stored bytes must equal the canonical event encoding. The reader applies the complete sequence to
the suite-slot reducer and returns the frozen event chain and current slot state.

The reader opens directories and files with no-follow flags, bounds enumeration and bytes before
parsing, requires exact private modes, current ownership, one filesystem device, stable
device/inode identity, canonical stored bytes, and a basename-bound manifest identity. It rejects
incomplete or marker-only claims, missing or replaced ledgers, symlinks, FIFOs, unknown entries,
filename gaps, partial or oversized bytes, permission drift, record or chain tamper, and coordinated
manifest replacement.

## Atomic event append

`appendSuiteSlotEvent` accepts a canonical event plus the caller's exact
`expectedNextSequence` and `expectedPreviousEventId`. Those expected values must equal the event's
own chain fields. Before filesystem mutation, the append boundary strictly reopens the formal run,
requires its current record count and last event identity to equal the expected head, and applies
the existing pure reducer to the complete prefix plus the candidate event. A stale head reports a
conflict; a foreign identity, illegal transition, timestamp rollback, or otherwise invalid event is
rejected before staging.

Staging never appears inside the formal run or ledger layout. The appender creates a random private
same-filesystem sibling directory under the suite root, writes one mode-0600 canonical pending
record, syncs it, syncs the staging directory and root, rereads and byte-compares it, and revalidates
the root, run, manifest, ledger, complete current head, and staging identities. It then creates the
fixed five-digit ledger filename with a no-replace hard link. That hard link is the sole event
visibility point. Existing records are never unlinked, replaced, chmodded, or rewritten.

Writers may all validate the same expected head, but only one can create the fixed destination.
`EEXIST` is a conflict only when the strict reader confirms a valid competing record at that
sequence; malformed occupation remains a filesystem failure. Other link failures are pre-publication
write failures because POSIX `link` did not create the destination. A losing writer does not modify
the winner. After a successful link, the appender verifies that the destination is the exact staged
inode and canonical bytes, syncs the record, ledger, run, and root, revalidates the recorded
directory and manifest identities, and obtains a strict formal-ledger read containing its fixed
canonical record. The strict read is retried a bounded number of times when a concurrent append
changes enumeration during the read. A later valid suffix is allowed during this confirmation:
success depends on the appended record remaining canonical at its fixed sequence, not on it still
being the ledger tail. Persistent unknown, malformed, gapped, or chain-invalid suffixes prevent
confirmation.

Any failure after the link but before those verification and durability steps complete reports
`suite_slot_event_publication_uncertain`; the destination is never rolled back. Once confirmed,
staging cleanup or cleanup-hook failure cannot reverse success. Cleanup may unlink only the random
pending source with its recorded device/inode/owner/mode identity and may remove only its recorded
empty staging directory, using bounded enumeration and identity revalidation. Stale or replaced
staging is left untouched, and stale recovery remains outside v1.

Before publication, cleanup is allowed only while the recorded root and claim identities still
match. It removes only recorded owned files and empty directories, never recursively. A crash may
leave an incomplete claim or sibling staging directory; neither is a formal run, and stale recovery
is outside v1. After publication, staging cleanup is identity-guarded best effort.

Portable Node.js lacks descriptor-relative link/unlink/rmdir operations. Protection from an
adversarial same-UID process swapping a validated path in the final path-based syscall window is
outside v1; recorded identity checks still reject accidental and checkpoint-observable drift. The
event chain detects retained-record tamper, gaps, middle deletion, and reordering, but without an
external trusted head it does not prove that a tail was never truncated or prevent a same-UID
attacker from replacing a complete suffix.

Manifest publication reports only `suite_run_exists`, `suite_run_write_failed`, or
`suite_run_publication_uncertain`. Reading reports only `suite_run_directory_invalid`. These errors
contain no manifest value, digest, entry name supplied by an attacker, or local path. The strong v1
filesystem contract is POSIX-only and fails closed where no-follow directory and file operations are
unavailable. Event append reports only `suite_slot_event_invalid`, `suite_slot_event_conflict`,
`suite_slot_event_write_failed`, or `suite_slot_event_publication_uncertain`, with fixed messages
that contain no event value, identity, sequence, entry name, or local path.
