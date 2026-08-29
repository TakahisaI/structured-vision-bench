# Private suite run directory v1

This contract publishes one verified [`suite-run-v1`](suite-run-v1.md) manifest as an immutable
local run identity. It performs no approval, provider, sanitizer, slot execution, resume, or report
work.

## Final layout and visibility

Given a caller-owned private root, the final layout is exactly:

```text
<root>/<suiteRunId>/suite-run.json
```

The root and run directory have exact mode `0700`; the manifest has exact mode `0600`. Entries must
be owned by the current effective user. The run-directory basename is the external suite-run
identity anchor. A directory is formal only when it contains exactly the final manifest and the
strict manifest reader confirms that its recomputed `suiteRunId` equals that basename.

The publisher canonicalizes, bounds, and strictly rereads the supplied manifest before changing the
filesystem. It then:

1. opens and records the stable private root;
2. claims `<suiteRunId>` with a non-recursive exclusive directory creation;
3. writes a private owner-nonce marker in that claim;
4. creates a private same-filesystem sibling `.suite-run-claim-<nonce>` directory;
5. writes, syncs, rereads, byte-compares, and identity-validates `suite-run.json.pending` there;
6. removes the owner marker and revalidates the empty final directory and all recorded identities;
7. creates `suite-run.json` with a no-replace hard link from the complete pending file; and
8. syncs the final directory and root before best-effort removal of the staging source.

The hard link in step 7 is the sole commit and visibility point. An existing digest claim or final
entry is never replaced. Two publishers therefore have at most one winner. Publication reports
ordinary success only after final file/path verification and the required file, run-directory, and
root syncs complete. A failure in that post-link completion boundary reports
`suite_run_publication_uncertain` and leaves the possible publication untouched. Once completion is
confirmed, later staging-cleanup or test-hook failure cannot reverse publication or turn it into a
failure.

## Reader and failure boundary

The reader opens directories and files with no-follow flags, bounds bytes before parsing, requires
exact private modes, current ownership, one filesystem device, stable device/inode identity, one
regular final file, canonical stored bytes, and a basename-bound manifest identity. It rejects
incomplete or marker-only claims, symlinks, FIFOs, unknown entries, partial or oversized bytes,
permission drift, and coordinated manifest replacement.

Before publication, cleanup is allowed only while the recorded root and claim identities still
match. It removes only recorded owned files and empty directories, never recursively. A crash may
leave an incomplete claim or sibling staging directory; neither is a formal run, and stale recovery
is outside v1. After publication, staging cleanup is identity-guarded best effort.

Portable Node.js lacks descriptor-relative link/unlink/rmdir operations. Protection from an
adversarial same-UID process swapping a validated path in the final path-based syscall window is
outside v1; recorded identity checks still reject accidental and checkpoint-observable drift.

Publication reports only `suite_run_exists`, `suite_run_write_failed`, or
`suite_run_publication_uncertain`. Reading reports only `suite_run_directory_invalid`. These errors
contain no manifest value, digest, entry name supplied by an attacker, or local path. The strong v1
filesystem contract is POSIX-only and fails closed where no-follow directory and file operations are
unavailable.
