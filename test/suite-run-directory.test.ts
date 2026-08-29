import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SuiteRunDirectoryError,
  SUITE_SLOT_LEDGER_DIRECTORY_NAME,
  publishSuiteRunDirectory,
  readSuiteRunDirectory,
  type SuiteRunPublicationCheckpoint,
  type SuiteRunPublicationHooks,
} from "../src/suite/run-directory.js";
import { encodeSuiteRunManifest } from "../src/suite/run-manifest.js";
import {
  MAX_SUITE_SLOT_EVENT_BYTES,
  createSuiteSlotEvent,
  encodeSuiteSlotEvent,
  type SuiteSlotEvent,
} from "../src/suite/slot-event.js";
import { syntheticSuiteRunManifest } from "./support/synthetic-suite-run.js";

const PRE_PUBLICATION_POINTS: readonly SuiteRunPublicationCheckpoint[] = [
  "directory-claimed",
  "owner-marker-written",
  "staging-created",
  "manifest-written",
  "manifest-synced",
  "manifest-verified",
  "slot-ledger-created",
  "slot-ledger-synced",
  "slot-ledger-parent-synced",
  "slot-ledger-verified",
  "owner-marker-removed",
  "before-publish",
];
const POST_PUBLICATION_POINTS: readonly SuiteRunPublicationCheckpoint[] = [
  "manifest-published",
  "run-directory-synced",
  "root-directory-synced",
  "staging-file-removed",
  "staging-directory-removed",
];

test("publishes one canonical private run directory and strictly reopens it", async (t) => {
  const root = await privateRoot(t);
  const manifest = syntheticSuiteRunManifest();
  const result = await publishSuiteRunDirectory(root, manifest);

  assert.equal(result.runDirectory, path.join(root, manifest.suiteRunId));
  assert.equal(result.manifestPath, path.join(result.runDirectory, "suite-run.json"));
  assert.equal(
    result.slotLedgerDirectory,
    path.join(result.runDirectory, SUITE_SLOT_LEDGER_DIRECTORY_NAME),
  );
  assert.deepEqual(result.manifest, manifest);
  assert.deepEqual(await readdir(root), [manifest.suiteRunId]);
  assert.deepEqual(
    (await readdir(result.runDirectory)).sort(),
    [SUITE_SLOT_LEDGER_DIRECTORY_NAME, "suite-run.json"],
  );
  assert.deepEqual(await readdir(result.slotLedgerDirectory), []);
  assert.deepEqual(await readFile(result.manifestPath), encodeSuiteRunManifest(manifest));
  assert.equal((await lstat(root)).mode & 0o777, 0o700);
  assert.equal((await lstat(result.runDirectory)).mode & 0o777, 0o700);
  assert.equal((await lstat(result.manifestPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(result.slotLedgerDirectory)).mode & 0o777, 0o700);
  assert.equal(result.slotState.lastEventId, null);
  assert.equal(result.slotState.slots[0]!.status, "pending");
  assert.deepEqual(result.slotState.events, []);

  const reopened = await readSuiteRunDirectory(result.runDirectory);
  assert.deepEqual(reopened, result);
  assert.equal(Object.isFrozen(reopened), true);
  assert.equal(Object.isFrozen(reopened.manifest), true);
  assert.equal(Object.isFrozen(reopened.slotState), true);
  assert.equal(Object.isFrozen(reopened.slotState.slots), true);
  assert.equal(Object.isFrozen(reopened.slotState.slots[0]!.history), true);
});

test("exclusive claims allow one concurrent publisher and preserve its bytes", async (t) => {
  const root = await privateRoot(t);
  const manifest = syntheticSuiteRunManifest();
  const settled = await Promise.allSettled([
    publishSuiteRunDirectory(root, manifest),
    publishSuiteRunDirectory(root, manifest),
  ]);
  const fulfilled = settled.filter((entry) => entry.status === "fulfilled");
  const rejected = settled.filter((entry) => entry.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(isDirectoryError(rejected[0]!.reason, "suite_run_exists"), true);
  const runDirectory = path.join(root, manifest.suiteRunId);
  assert.deepEqual(await readFile(path.join(runDirectory, "suite-run.json")), encodeSuiteRunManifest(manifest));
  assert.deepEqual(await readdir(path.join(runDirectory, SUITE_SLOT_LEDGER_DIRECTORY_NAME)), []);
  assert.deepEqual((await readSuiteRunDirectory(runDirectory)).manifest, manifest);
});

test("ordinary failures before the hard-link commit clean only the owned claim", async (t) => {
  for (const point of PRE_PUBLICATION_POINTS) {
    const root = await privateRoot(t);
    await assert.rejects(
      publishSuiteRunDirectory(root, syntheticSuiteRunManifest(), {
        checkpoint: (current) => {
          if (current === point) throw new Error("synthetic checkpoint failure");
        },
      }),
      isDirectoryErrorPredicate("suite_run_write_failed"),
    );
    assert.deepEqual(await readdir(root), []);
  }
});

test("pre-link cleanup leaves a ledger after an unowned entry is injected", async (t) => {
  const root = await privateRoot(t);
  const manifest = syntheticSuiteRunManifest();
  await assert.rejects(
    publishSuiteRunDirectory(root, manifest, {
      checkpoint: async (point) => {
        if (point !== "before-publish") return;
        const ledger = path.join(root, manifest.suiteRunId, SUITE_SLOT_LEDGER_DIRECTORY_NAME);
        await writeFile(path.join(ledger, "synthetic-unowned-entry"), "synthetic\n", { mode: 0o600 });
        throw new Error("synthetic checkpoint failure");
      },
    }),
    isDirectoryErrorPredicate("suite_run_write_failed"),
  );

  const runDirectory = path.join(root, manifest.suiteRunId);
  assert.deepEqual(await readdir(path.join(runDirectory, SUITE_SLOT_LEDGER_DIRECTORY_NAME)), [
    "synthetic-unowned-entry",
  ]);
  await expectInvalid(runDirectory);
});

test("crash checkpoints expose no formal run before commit and a complete run after commit", async (t) => {
  const manifest = syntheticSuiteRunManifest();
  for (const point of PRE_PUBLICATION_POINTS) {
    const root = await privateRoot(t);
    assert.equal(await runCrashChild(root, point), 77);
    const runDirectory = path.join(root, manifest.suiteRunId);
    await assert.rejects(
      readSuiteRunDirectory(runDirectory),
      isDirectoryErrorPredicate("suite_run_directory_invalid"),
    );
  }
  for (const point of POST_PUBLICATION_POINTS) {
    const root = await privateRoot(t);
    assert.equal(await runCrashChild(root, point), 77);
    const runDirectory = path.join(root, manifest.suiteRunId);
    assert.deepEqual((await readSuiteRunDirectory(runDirectory)).manifest, manifest);
  }
});

test("post-commit hook and cleanup failures cannot turn publication into failure", async (t) => {
  const root = await privateRoot(t);
  const manifest = syntheticSuiteRunManifest();
  const result = await publishSuiteRunDirectory(root, manifest, {
    checkpoint: (point) => {
      if (point === "manifest-published" || point === "staging-file-removed") {
        throw new Error("synthetic post-commit failure");
      }
    },
  });
  assert.deepEqual((await readSuiteRunDirectory(result.runDirectory)).manifest, manifest);
});

test("reader rejects unknown entries, mode drift, partial bytes, symlinks, and basename drift", async (t) => {
  await withPublished(t, async ({ result }) => {
    const extra = path.join(result.runDirectory, "synthetic-extra");
    await writeFile(extra, "synthetic\n", { mode: 0o600 });
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    await chmod(result.manifestPath, 0o640);
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    await chmod(result.runDirectory, 0o1700);
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    await writeFile(result.manifestPath, "{\"partial\":", { mode: 0o600 });
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ root, result }) => {
    const target = path.join(root, "synthetic-target");
    await writeFile(target, encodeSuiteRunManifest(result.manifest), { mode: 0o600 });
    await rm(result.manifestPath);
    await symlink(target, result.manifestPath);
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ root, result }) => {
    const renamed = path.join(root, "d".repeat(64));
    await rename(result.runDirectory, renamed);
    await expectInvalid(renamed);
  });
});

test("strict reader reduces canonical slot ledger records", async (t) => {
  await withPublished(t, async ({ result }) => {
    const running = firstRunningEvent(result.manifest);
    const succeeded = succeededEvent(result.manifest, running);
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      encodeSuiteSlotEvent(running),
      { mode: 0o600 },
    );
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(1)),
      encodeSuiteSlotEvent(succeeded),
      { mode: 0o600 },
    );

    const reopened = await readSuiteRunDirectory(result.runDirectory);
    assert.deepEqual(reopened.slotState.events, [running, succeeded]);
    assert.equal(reopened.slotState.lastEventId, succeeded.eventId);
    assert.equal(reopened.slotState.slots[0]!.status, "succeeded");
    assert.deepEqual(reopened.slotState.slots[0]!.history, [running, succeeded]);
  });
});

test("reader rejects malformed ledger shape, records, and sequence binding", async (t) => {
  await withPublished(t, async ({ result }) => {
    const marker = "SYNTHETIC_PRIVATE_UNKNOWN_LEDGER_ENTRY";
    await writeFile(path.join(result.slotLedgerDirectory, marker), "synthetic\n", {
      mode: 0o600,
    });
    const error = await captureRejection(readSuiteRunDirectory(result.runDirectory));
    assert.equal(isDirectoryError(error, "suite_run_directory_invalid"), true);
    assert.equal(String(error).includes(marker), false);
    assert.equal(String(error).includes(result.runDirectory), false);
    assert.equal(String(error).includes(result.manifest.suiteRunId), false);
  });
  await withPublished(t, async ({ result }) => {
    await writeFile(
      path.join(result.slotLedgerDirectory, "0.json"),
      encodeSuiteSlotEvent(firstRunningEvent(result.manifest)),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const event = firstRunningEvent(result.manifest, {
      sequence: 1,
      previousEventId: "f".repeat(64),
    });
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(1)),
      encodeSuiteSlotEvent(event),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const file = path.join(result.slotLedgerDirectory, ledgerRecordName(0));
    await writeFile(file, "{\"partial\":", { mode: 0o600 });
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const file = path.join(result.slotLedgerDirectory, ledgerRecordName(0));
    await writeFile(file, encodeSuiteSlotEvent(firstRunningEvent(result.manifest)), { mode: 0o640 });
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const event = firstRunningEvent(result.manifest, {
      sequence: 1,
      previousEventId: "f".repeat(64),
    });
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      encodeSuiteSlotEvent(event),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const event = firstRunningEvent(result.manifest, { suiteRunId: "f".repeat(64) });
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      encodeSuiteSlotEvent(event),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const running = firstRunningEvent(result.manifest);
    const tampered = succeededEvent(result.manifest, running, {
      previousEventId: "f".repeat(64),
    });
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      encodeSuiteSlotEvent(running),
      { mode: 0o600 },
    );
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(1)),
      encodeSuiteSlotEvent(tampered),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const running = firstRunningEvent(result.manifest);
    const succeeded = succeededEvent(result.manifest, running);
    const afterTerminal = succeededEvent(result.manifest, succeeded, {
      previousStatus: "succeeded",
      status: "failed",
      failureCode: "provider_failed",
      recordedAt: "2026-01-02T03:04:07.000Z",
    });
    for (const event of [running, succeeded, afterTerminal]) {
      await writeFile(
        path.join(result.slotLedgerDirectory, ledgerRecordName(event.sequence)),
        encodeSuiteSlotEvent(event),
        { mode: 0o600 },
      );
    }
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ root, result }) => {
    const target = path.join(root, "synthetic-record-target");
    await writeFile(target, encodeSuiteSlotEvent(firstRunningEvent(result.manifest)), { mode: 0o600 });
    await symlink(target, path.join(result.slotLedgerDirectory, ledgerRecordName(0)));
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      Buffer.alloc(MAX_SUITE_SLOT_EVENT_BYTES + 1, 0x20),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    const event = firstRunningEvent(result.manifest);
    await writeFile(
      path.join(result.slotLedgerDirectory, ledgerRecordName(0)),
      Buffer.concat([encodeSuiteSlotEvent(event), Buffer.from("\n")]),
      { mode: 0o600 },
    );
    await expectInvalid(result.runDirectory);
  });
});

test("reader rejects missing, replaced, and non-private ledger directories", async (t) => {
  await withPublished(t, async ({ result }) => {
    await rm(result.slotLedgerDirectory, { recursive: true });
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ result }) => {
    await chmod(result.slotLedgerDirectory, 0o755);
    await expectInvalid(result.runDirectory);
  });
  await withPublished(t, async ({ root, result }) => {
    const target = path.join(root, "synthetic-ledger-target");
    await mkdir(target, { mode: 0o700 });
    await rm(result.slotLedgerDirectory, { recursive: true });
    await symlink(target, result.slotLedgerDirectory);
    await expectInvalid(result.runDirectory);
  });
});

test("publisher rejects unsafe roots and checkpoint accessors without leaking paths or values", async (t) => {
  const root = await privateRoot(t);
  await chmod(root, 0o755);
  const rootError = await captureRejection(publishSuiteRunDirectory(root, syntheticSuiteRunManifest()));
  assert.equal(isDirectoryError(rootError, "suite_run_write_failed"), true);
  assert.equal(String(rootError).includes(root), false);

  const privateAgain = await privateRoot(t);
  let accessorCalled = false;
  const hostile = Object.defineProperty({}, "checkpoint", {
    enumerable: true,
    get() {
      accessorCalled = true;
      return undefined;
    },
  });
  const hookError = await captureRejection(
    publishSuiteRunDirectory(privateAgain, syntheticSuiteRunManifest(), hostile),
  );
  assert.equal(accessorCalled, false);
  assert.equal(isDirectoryError(hookError, "suite_run_write_failed"), true);
  assert.deepEqual(await readdir(privateAgain), []);

  const proxyRoot = await privateRoot(t);
  const privateMarker = "SYNTHETIC_PRIVATE_PROXY_MARKER";
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error(privateMarker);
      },
    },
  ) as SuiteRunPublicationHooks;
  const proxyError = await captureRejection(
    publishSuiteRunDirectory(proxyRoot, syntheticSuiteRunManifest(), proxy),
  );
  assert.equal(isDirectoryError(proxyError, "suite_run_write_failed"), true);
  assert.equal(String(proxyError).includes(privateMarker), false);
  assert.deepEqual(await readdir(proxyRoot), []);

  const invalidRoot = await privateRoot(t);
  const invalidManifestError = await captureRejection(
    publishSuiteRunDirectory(invalidRoot, {} as ReturnType<typeof syntheticSuiteRunManifest>),
  );
  assert.equal(isDirectoryError(invalidManifestError, "suite_run_write_failed"), true);
  assert.deepEqual(await readdir(invalidRoot), []);

  const forgedRoot = await privateRoot(t);
  const forgedMarker = "SYNTHETIC_PRIVATE_FORGED_ERROR";
  const forgedError = await captureRejection(
    publishSuiteRunDirectory(forgedRoot, syntheticSuiteRunManifest(), {
      checkpoint: () => {
        throw new SuiteRunDirectoryError("suite_run_exists", forgedMarker);
      },
    }),
  );
  assert.equal(isDirectoryError(forgedError, "suite_run_write_failed"), true);
  assert.equal(String(forgedError).includes(forgedMarker), false);
  assert.deepEqual(await readdir(forgedRoot), []);
});

test("pending-file replacement at the last test checkpoint fails closed", async (t) => {
  const root = await privateRoot(t);
  await assert.rejects(
    publishSuiteRunDirectory(root, syntheticSuiteRunManifest(), {
      checkpoint: async (point) => {
        if (point !== "before-publish") return;
        const staging = (await readdir(root)).find((entry) => entry.startsWith(".suite-run-claim-"));
        assert.notEqual(staging, undefined);
        const pending = path.join(root, staging!, "suite-run.json.pending");
        await rename(pending, `${pending}.replaced`);
        await writeFile(pending, "{\"synthetic\":true}\n", { mode: 0o600 });
      },
    }),
    isDirectoryErrorPredicate("suite_run_write_failed"),
  );
  const runDirectory = path.join(root, syntheticSuiteRunManifest().suiteRunId);
  await expectInvalid(runDirectory);
});

test("same-inode pending overwrite at the last checkpoint fails before publication", async (t) => {
  const root = await privateRoot(t);
  await assert.rejects(
    publishSuiteRunDirectory(root, syntheticSuiteRunManifest(), {
      checkpoint: async (point) => {
        if (point !== "before-publish") return;
        const staging = (await readdir(root)).find((entry) => entry.startsWith(".suite-run-claim-"));
        assert.notEqual(staging, undefined);
        await writeFile(path.join(root, staging!, "suite-run.json.pending"), "{\"synthetic\":true}\n");
      },
    }),
    isDirectoryErrorPredicate("suite_run_write_failed"),
  );
  assert.deepEqual(await readdir(root), []);
});

test("post-link path drift reports an uncertain outcome instead of success", async (t) => {
  const root = await privateRoot(t);
  const movedRoot = `${root}-moved`;
  t.after(() => rm(movedRoot, { recursive: true, force: true }));
  const manifest = syntheticSuiteRunManifest();
  await assert.rejects(
    publishSuiteRunDirectory(root, manifest, {
      checkpoint: async (point) => {
        if (point !== "manifest-published") return;
        await rename(root, movedRoot);
        await mkdir(root, { mode: 0o700 });
      },
    }),
    isDirectoryErrorPredicate("suite_run_publication_uncertain"),
  );
  assert.deepEqual(
    (await readSuiteRunDirectory(path.join(movedRoot, manifest.suiteRunId))).manifest,
    manifest,
  );
});

function ledgerRecordName(sequence: number): string {
  return `${sequence.toString(10).padStart(5, "0")}.json`;
}

function firstRunningEvent(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
  overrides: Partial<Parameters<typeof createSuiteSlotEvent>[0]> = {},
) {
  const slot = manifest.slots[0]!;
  const input: Parameters<typeof createSuiteSlotEvent>[0] = {
    suiteRunId: manifest.suiteRunId,
    sequence: 0,
    previousEventId: null,
    recordedAt: "2026-01-02T03:04:05.006Z",
    caseIndex: slot.caseIndex,
    repeatIndex: slot.repeatIndex,
    attemptKey: slot.attemptKey,
    runId: slot.runId,
    attemptId: slot.attemptId,
    previousStatus: "pending",
    status: "running",
    failureCode: null,
    ...overrides,
  };
  return createSuiteSlotEvent(input);
}

function succeededEvent(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
  previous: SuiteSlotEvent,
  overrides: Partial<Parameters<typeof createSuiteSlotEvent>[0]> = {},
) {
  const slot = manifest.slots[0]!;
  const input: Parameters<typeof createSuiteSlotEvent>[0] = {
    suiteRunId: manifest.suiteRunId,
    sequence: previous.sequence + 1,
    previousEventId: previous.eventId,
    recordedAt: "2026-01-02T03:04:06.000Z",
    caseIndex: slot.caseIndex,
    repeatIndex: slot.repeatIndex,
    attemptKey: slot.attemptKey,
    runId: slot.runId,
    attemptId: slot.attemptId,
    previousStatus: "running",
    status: "succeeded",
    failureCode: null,
    ...overrides,
  };
  return createSuiteSlotEvent(input);
}

async function privateRoot(t: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "svbench-synthetic-suite-run-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function withPublished(
  t: test.TestContext,
  callback: (context: {
    root: string;
    result: Awaited<ReturnType<typeof publishSuiteRunDirectory>>;
  }) => Promise<void>,
): Promise<void> {
  const root = await privateRoot(t);
  const result = await publishSuiteRunDirectory(root, syntheticSuiteRunManifest());
  await callback({ root, result });
}

async function expectInvalid(runDirectory: string): Promise<void> {
  await assert.rejects(
    readSuiteRunDirectory(runDirectory),
    isDirectoryErrorPredicate("suite_run_directory_invalid"),
  );
}

async function runCrashChild(root: string, point: SuiteRunPublicationCheckpoint): Promise<number | null> {
  const childPath = path.join(process.cwd(), ".tmp/build/test/support/suite-run-publisher-child.js");
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [childPath, root, point], { stdio: "ignore" });
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
}

function isDirectoryError(error: unknown, code: SuiteRunDirectoryError["code"]): boolean {
  return error instanceof SuiteRunDirectoryError && error.code === code;
}

function isDirectoryErrorPredicate(
  code: SuiteRunDirectoryError["code"],
): (error: unknown) => boolean {
  return (error) => isDirectoryError(error, code);
}

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected rejection");
}
