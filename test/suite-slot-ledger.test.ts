import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SuiteSlotLedgerError,
  appendSuiteSlotEvent,
  type SuiteSlotEventAppendCheckpoint,
} from "../src/suite/slot-ledger.js";
import { publishSuiteRunDirectory, readSuiteRunDirectory } from "../src/suite/run-directory.js";
import { encodeSuiteRunManifest } from "../src/suite/run-manifest.js";
import {
  createSuiteSlotEvent,
  encodeSuiteSlotEvent,
  type CreateSuiteSlotEventInput,
  type SuiteSlotEvent,
} from "../src/suite/slot-event.js";
import { syntheticSuiteRunManifest } from "./support/synthetic-suite-run.js";

const PRE_PUBLICATION_POINTS: readonly SuiteSlotEventAppendCheckpoint[] = [
  "head-verified",
  "staging-created",
  "record-written",
  "record-synced",
  "record-verified",
  "root-synced-before-publish",
  "before-publish",
  "link-ready",
];
const POST_PUBLICATION_POINTS: readonly SuiteSlotEventAppendCheckpoint[] = [
  "record-published",
  "record-synced-after-publish",
  "ledger-synced",
  "run-synced",
  "root-synced-after-publish",
  "record-verified-after-publish",
  "staging-file-removed",
  "staging-directory-removed",
  "cleanup-root-synced",
];

test("appends canonical events and preserves the existing prefix", async (t) => {
  const { root, published } = await publishedRun(t);
  const running = runningEvent(published.manifest);
  const first = await appendSuiteSlotEvent(published.runDirectory, appendInput(running));
  assert.equal(Object.isFrozen(first), true);
  assert.deepEqual(first.event, running);
  const firstRecordPath = path.join(published.slotLedgerDirectory, "00000.json");
  assert.equal((await lstat(firstRecordPath)).mode & 0o777, 0o600);
  assert.deepEqual(await readFile(firstRecordPath), encodeSuiteSlotEvent(running));
  const firstInfo = await lstat(firstRecordPath);
  const firstBytes = await readFile(firstRecordPath);

  const succeeded = outcomeEvent(published.manifest, running);
  await appendSuiteSlotEvent(published.runDirectory, appendInput(succeeded));
  const reopened = await readSuiteRunDirectory(published.runDirectory);
  assert.deepEqual(reopened.slotState.events, [running, succeeded]);
  assert.equal(reopened.slotState.slots[0]!.status, "succeeded");
  assert.deepEqual(await readFile(firstRecordPath), firstBytes);
  assert.equal((await lstat(firstRecordPath)).ino, firstInfo.ino);
  assert.deepEqual(await readdir(root), [published.manifest.suiteRunId]);
});

test("rejects stale heads and invalid candidates before filesystem mutation", async (t) => {
  const { root, published } = await publishedRun(t);
  const running = runningEvent(published.manifest);
  const stale = runningEvent(published.manifest, {
    sequence: 1,
    previousEventId: "f".repeat(64),
  });
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, appendInput(stale)),
    ledgerError("suite_slot_event_conflict"),
  );

  const foreign = runningEvent(published.manifest, { suiteRunId: "f".repeat(64) });
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, appendInput(foreign)),
    ledgerError("suite_slot_event_invalid"),
  );
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, {
      expectedNextSequence: 1,
      expectedPreviousEventId: null,
      event: running,
    }),
    ledgerError("suite_slot_event_invalid"),
  );
  assert.deepEqual(await readdir(published.slotLedgerDirectory), []);
  assert.deepEqual(await readdir(root), [published.manifest.suiteRunId]);
});

test("allows one in-process writer for the same sequence", async (t) => {
  const { published } = await publishedRun(t);
  const running = runningEvent(published.manifest);
  const settled = await Promise.allSettled([
    appendSuiteSlotEvent(published.runDirectory, appendInput(running)),
    appendSuiteSlotEvent(published.runDirectory, appendInput(running)),
  ]);
  assert.equal(settled.filter((entry) => entry.status === "fulfilled").length, 1);
  const rejected = settled.find((entry) => entry.status === "rejected");
  assert.equal(
    rejected?.status === "rejected" &&
      rejected.reason instanceof SuiteSlotLedgerError &&
      rejected.reason.code === "suite_slot_event_conflict",
    true,
  );
  assert.deepEqual(
    (await readSuiteRunDirectory(published.runDirectory)).slotState.events,
    [running],
  );
});

test("allows one multi-process writer for the same sequence", async (t) => {
  const { root, published } = await publishedRun(t);
  const control = await mkdtemp(path.join(tmpdir(), "svbench-synthetic-slot-control-"));
  await chmod(control, 0o700);
  t.after(() => rm(control, { recursive: true, force: true }));
  const gate = path.join(control, "gate");
  const readyA = path.join(control, "ready-a");
  const readyB = path.join(control, "ready-b");
  const childPath = path.join(process.cwd(), ".tmp/build/test/support/suite-slot-ledger-child.js");
  const first = spawnExit(childPath, ["contend", published.runDirectory, "synthetic-a", readyA, gate]);
  const second = spawnExit(childPath, ["contend", published.runDirectory, "synthetic-b", readyB, gate]);
  await waitForFiles([readyA, readyB]);
  await writeFile(gate, "synthetic-go\n", { flag: "wx", mode: 0o600 });
  assert.deepEqual((await Promise.all([first, second])).sort((a, b) => (a ?? 99) - (b ?? 99)), [0, 42]);
  const reopened = await readSuiteRunDirectory(published.runDirectory);
  assert.equal(reopened.slotState.events.length, 1);
  assert.equal(
    ["2026-01-02T03:04:05.006Z", "2026-01-02T03:04:05.007Z"].includes(
      reopened.slotState.events[0]!.recordedAt,
    ),
    true,
  );
  const recordPath = path.join(published.slotLedgerDirectory, "00000.json");
  const winningBytes = await readFile(recordPath);
  const winningIdentity = await lstat(recordPath);
  assert.deepEqual(winningBytes, encodeSuiteSlotEvent(reopened.slotState.events[0]!));
  await assert.rejects(
    appendSuiteSlotEvent(
      published.runDirectory,
      appendInput(runningEvent(published.manifest, { recordedAt: "2026-01-02T03:04:05.008Z" })),
    ),
    ledgerError("suite_slot_event_conflict"),
  );
  assert.deepEqual(await readFile(recordPath), winningBytes);
  assert.equal((await lstat(recordPath)).ino, winningIdentity.ino);
  assert.deepEqual(await readdir(root), [published.manifest.suiteRunId]);
});

test("crash checkpoints expose only the old or new complete ledger", async (t) => {
  for (const point of PRE_PUBLICATION_POINTS) {
    const { published } = await publishedRun(t);
    assert.equal(await runCrashChild(published.runDirectory, point), 77);
    assert.deepEqual(
      (await readSuiteRunDirectory(published.runDirectory)).slotState.events,
      [],
    );
  }
  for (const point of POST_PUBLICATION_POINTS) {
    const { published } = await publishedRun(t);
    assert.equal(await runCrashChild(published.runDirectory, point), 77);
    assert.equal(
      (await readSuiteRunDirectory(published.runDirectory)).slotState.events.length,
      1,
    );
  }
});

test("reports post-link uncertainty without removing the complete record", async (t) => {
  const { published } = await publishedRun(t);
  const marker = "SYNTHETIC_PRIVATE_POST_LINK_MARKER";
  const error = await captureRejection(
    appendSuiteSlotEvent(published.runDirectory, appendInput(runningEvent(published.manifest)), {
      checkpoint: (point) => {
        if (point === "record-published") throw new Error(marker);
      },
    }),
  );
  assert.equal(isLedgerError(error, "suite_slot_event_publication_uncertain"), true);
  assert.equal(String(error).includes(marker), false);
  assert.equal(String(error).includes(published.runDirectory), false);
  assert.equal((await readSuiteRunDirectory(published.runDirectory)).slotState.events.length, 1);
});

test("post-link malformed suffixes are uncertain and remain untouched", async (t) => {
  for (const injectedName of ["synthetic-unknown", "00001.json"]) {
    const { published } = await publishedRun(t);
    const event = runningEvent(published.manifest);
    const injected = path.join(published.slotLedgerDirectory, injectedName);
    const injectedBytes = Buffer.from("synthetic-malformed\n", "utf8");
    await assert.rejects(
      appendSuiteSlotEvent(published.runDirectory, appendInput(event), {
        checkpoint: async (point) => {
          if (point === "record-published") {
            await writeFile(injected, injectedBytes, { mode: 0o600 });
          }
        },
      }),
      ledgerError("suite_slot_event_publication_uncertain"),
    );
    assert.deepEqual(
      await readFile(path.join(published.slotLedgerDirectory, "00000.json")),
      encodeSuiteSlotEvent(event),
    );
    assert.deepEqual(await readFile(injected), injectedBytes);
    await assert.rejects(readSuiteRunDirectory(published.runDirectory));
  }
});

test("pre-link failure removes only owned staging", async (t) => {
  const { root, published } = await publishedRun(t);
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, appendInput(runningEvent(published.manifest)), {
      checkpoint: (point) => {
        if (point === "before-publish") throw new Error("synthetic pre-link failure");
      },
    }),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.deepEqual(await readdir(published.slotLedgerDirectory), []);
  assert.deepEqual(await readdir(root), [published.manifest.suiteRunId]);
});

test("leaves a replaced staging entry and never deletes an injected target", async (t) => {
  const first = await publishedRun(t);
  await assert.rejects(
    appendSuiteSlotEvent(
      first.published.runDirectory,
      appendInput(runningEvent(first.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point !== "record-verified") return;
          const staging = (await readdir(first.root)).find((name) =>
            name.startsWith(".suite-slot-event-claim-"),
          );
          assert.notEqual(staging, undefined);
          const pending = path.join(first.root, staging!, "slot-event.json.pending");
          await rename(pending, `${pending}.owned-original`);
          await writeFile(pending, "synthetic-foreign\n", { mode: 0o600 });
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.equal(
    (await readdir(first.root)).some((name) => name.startsWith(".suite-slot-event-claim-")),
    true,
  );
  assert.deepEqual(await readdir(first.published.slotLedgerDirectory), []);

  const second = await publishedRun(t);
  const injected = path.join(second.published.slotLedgerDirectory, "00000.json");
  await assert.rejects(
    appendSuiteSlotEvent(
      second.published.runDirectory,
      appendInput(runningEvent(second.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point === "before-publish") {
            await writeFile(injected, "synthetic-junk\n", { mode: 0o600 });
          }
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.equal((await readFile(injected, "utf8")), "synthetic-junk\n");
});

test("confirms while a legitimate suffix is visible but not yet confirmed", async (t) => {
  const { published } = await publishedRun(t);
  const running = runningEvent(published.manifest);
  const succeeded = outcomeEvent(published.manifest, running);
  let releaseSuffix!: () => void;
  let suffixPromise: Promise<unknown> | undefined;
  let markSuffixPublished!: () => void;
  const suffixPublished = new Promise<void>((resolve) => {
    markSuffixPublished = resolve;
  });
  await appendSuiteSlotEvent(published.runDirectory, appendInput(running), {
    checkpoint: async (point) => {
      if (point !== "record-published" || suffixPromise !== undefined) return;
      suffixPromise = appendSuiteSlotEvent(published.runDirectory, appendInput(succeeded), {
        checkpoint: async (suffixPoint) => {
          if (suffixPoint !== "record-published") return;
          markSuffixPublished();
          await new Promise<void>((resolve) => {
            releaseSuffix = resolve;
          });
        },
      });
      await suffixPublished;
    },
  });
  releaseSuffix();
  await suffixPromise;
  assert.deepEqual(
    (await readSuiteRunDirectory(published.runDirectory)).slotState.events,
    [running, succeeded],
  );
});

test("classifies a failed link as unpublished after root path drift", async (t) => {
  const { root, published } = await publishedRun(t);
  const movedRoot = `${root}-moved`;
  t.after(() => rm(movedRoot, { recursive: true, force: true }));
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, appendInput(runningEvent(published.manifest)), {
      checkpoint: async (point) => {
        if (point !== "link-ready") return;
        await rename(root, movedRoot);
        await mkdir(root, { mode: 0o700 });
      },
    }),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.deepEqual(
    (await readSuiteRunDirectory(path.join(movedRoot, published.manifest.suiteRunId))).slotState.events,
    [],
  );
});

test("rejects run-directory identity swap without touching the replacement", async (t) => {
  const { root, published } = await publishedRun(t);
  const movedParent = `${root}-moved-parent`;
  const movedRun = path.join(movedParent, published.manifest.suiteRunId);
  await mkdir(movedParent, { mode: 0o700 });
  t.after(() => rm(movedParent, { recursive: true, force: true }));
  await assert.rejects(
    appendSuiteSlotEvent(published.runDirectory, appendInput(runningEvent(published.manifest)), {
      checkpoint: async (point) => {
        if (point !== "before-publish") return;
        await rename(published.runDirectory, movedRun);
        await mkdir(published.runDirectory, { mode: 0o700 });
        await writeFile(path.join(published.runDirectory, "synthetic-foreign"), "synthetic\n", {
          mode: 0o600,
        });
      },
    }),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.equal(
    await readFile(path.join(published.runDirectory, "synthetic-foreign"), "utf8"),
    "synthetic\n",
  );
  assert.deepEqual((await readSuiteRunDirectory(movedRun)).slotState.events, []);
});

test("reports ledger identity swap and post-link target drift without cleanup", async (t) => {
  const first = await publishedRun(t);
  const movedLedger = `${first.published.slotLedgerDirectory}-moved`;
  t.after(() => rm(movedLedger, { recursive: true, force: true }));
  const firstEvent = runningEvent(first.published.manifest);
  await assert.rejects(
    appendSuiteSlotEvent(first.published.runDirectory, appendInput(firstEvent), {
      checkpoint: async (point) => {
        if (point !== "link-ready") return;
        await rename(first.published.slotLedgerDirectory, movedLedger);
        await mkdir(first.published.slotLedgerDirectory, { mode: 0o700 });
      },
    }),
    ledgerError("suite_slot_event_publication_uncertain"),
  );
  assert.deepEqual(
    await readFile(path.join(first.published.slotLedgerDirectory, "00000.json")),
    encodeSuiteSlotEvent(firstEvent),
  );

  const second = await publishedRun(t);
  const secondEvent = runningEvent(second.published.manifest);
  const movedRecord = path.join(second.published.slotLedgerDirectory, "synthetic-moved-record");
  await assert.rejects(
    appendSuiteSlotEvent(second.published.runDirectory, appendInput(secondEvent), {
      checkpoint: async (point) => {
        if (point === "record-published") {
          await rename(path.join(second.published.slotLedgerDirectory, "00000.json"), movedRecord);
        }
      },
    }),
    ledgerError("suite_slot_event_publication_uncertain"),
  );
  assert.deepEqual(await readFile(movedRecord), encodeSuiteSlotEvent(secondEvent));
});

test("rejects manifest symlinks, unknown entries, and staging directory replacement", async (t) => {
  const first = await publishedRun(t);
  const savedManifest = `${first.published.manifestPath}.saved`;
  await assert.rejects(
    appendSuiteSlotEvent(
      first.published.runDirectory,
      appendInput(runningEvent(first.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point !== "before-publish") return;
          await rename(first.published.manifestPath, savedManifest);
          await symlink(savedManifest, first.published.manifestPath);
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.deepEqual(await readFile(savedManifest), encodeSuiteRunManifest(first.published.manifest));

  const second = await publishedRun(t);
  const unknown = path.join(second.published.slotLedgerDirectory, "synthetic-unknown");
  await assert.rejects(
    appendSuiteSlotEvent(
      second.published.runDirectory,
      appendInput(runningEvent(second.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point === "before-publish") {
            await writeFile(unknown, "synthetic-unknown\n", { mode: 0o600 });
          }
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.equal(await readFile(unknown, "utf8"), "synthetic-unknown\n");

  const symlinked = await publishedRun(t);
  const target = path.join(symlinked.root, "synthetic-target");
  const destination = path.join(symlinked.published.slotLedgerDirectory, "00000.json");
  await writeFile(target, "synthetic-target\n", { mode: 0o600 });
  await assert.rejects(
    appendSuiteSlotEvent(
      symlinked.published.runDirectory,
      appendInput(runningEvent(symlinked.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point === "link-ready") await symlink(target, destination);
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.equal((await lstat(destination)).isSymbolicLink(), true);

  const third = await publishedRun(t);
  let replacementDirectory: string | undefined;
  let movedStaging: string | undefined;
  await assert.rejects(
    appendSuiteSlotEvent(
      third.published.runDirectory,
      appendInput(runningEvent(third.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point !== "record-verified") return;
          replacementDirectory = (await readdir(third.root)).find((name) =>
            name.startsWith(".suite-slot-event-claim-"),
          );
          assert.notEqual(replacementDirectory, undefined);
          const stagingPath = path.join(third.root, replacementDirectory!);
          movedStaging = `${stagingPath}-moved`;
          await rename(stagingPath, movedStaging);
          await mkdir(stagingPath, { mode: 0o700 });
          await writeFile(path.join(stagingPath, "synthetic-foreign"), "synthetic\n", {
            mode: 0o600,
          });
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );
  assert.notEqual(replacementDirectory, undefined);
  assert.notEqual(movedStaging, undefined);
  assert.equal(
    await readFile(path.join(third.root, replacementDirectory!, "synthetic-foreign"), "utf8"),
    "synthetic\n",
  );
  assert.equal((await readdir(movedStaging!)).includes("slot-event.json.pending"), true);
});

test("normalizes hostile thrown proxies before and after publication", async (t) => {
  const marker = "SYNTHETIC_PRIVATE_THROWN_PROXY";
  const thrown = new Proxy(new Error(marker), {
    getPrototypeOf() {
      throw new Error(marker);
    },
  });
  const first = await publishedRun(t);
  const preError = await captureRejection(
    appendSuiteSlotEvent(
      first.published.runDirectory,
      appendInput(runningEvent(first.published.manifest)),
      {
        checkpoint: (point) => {
          if (point === "before-publish") throw thrown;
        },
      },
    ),
  );
  assert.equal(isLedgerError(preError, "suite_slot_event_write_failed"), true);
  assert.equal(String(preError).includes(marker), false);

  const second = await publishedRun(t);
  const postError = await captureRejection(
    appendSuiteSlotEvent(
      second.published.runDirectory,
      appendInput(runningEvent(second.published.manifest)),
      {
        checkpoint: (point) => {
          if (point === "record-published") throw thrown;
        },
      },
    ),
  );
  assert.equal(isLedgerError(postError, "suite_slot_event_publication_uncertain"), true);
  assert.equal(String(postError).includes(marker), false);
});

test("fails closed on mode drift and hostile hook objects", async (t) => {
  const first = await publishedRun(t);
  await assert.rejects(
    appendSuiteSlotEvent(
      first.published.runDirectory,
      appendInput(runningEvent(first.published.manifest)),
      {
        checkpoint: async (point) => {
          if (point === "before-publish") await chmod(first.published.slotLedgerDirectory, 0o755);
        },
      },
    ),
    ledgerError("suite_slot_event_write_failed"),
  );

  const second = await publishedRun(t);
  let accessorCalled = false;
  const hostile = Object.defineProperty({}, "checkpoint", {
    enumerable: true,
    get() {
      accessorCalled = true;
      return undefined;
    },
  });
  await assert.rejects(
    appendSuiteSlotEvent(
      second.published.runDirectory,
      appendInput(runningEvent(second.published.manifest)),
      hostile,
    ),
    ledgerError("suite_slot_event_invalid"),
  );
  assert.equal(accessorCalled, false);
});

function appendInput(event: SuiteSlotEvent) {
  return {
    expectedNextSequence: event.sequence,
    expectedPreviousEventId: event.previousEventId,
    event,
  } as const;
}

function runningEvent(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
  overrides: Partial<CreateSuiteSlotEventInput> = {},
): SuiteSlotEvent {
  const slot = manifest.slots[0]!;
  return createSuiteSlotEvent({
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
  });
}

function outcomeEvent(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
  previous: SuiteSlotEvent,
): SuiteSlotEvent {
  const slot = manifest.slots[0]!;
  return createSuiteSlotEvent({
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
  });
}

async function publishedRun(t: test.TestContext) {
  const root = await mkdtemp(path.join(tmpdir(), "svbench-synthetic-slot-ledger-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const published = await publishSuiteRunDirectory(root, syntheticSuiteRunManifest());
  return { root, published };
}

async function runCrashChild(
  runDirectory: string,
  point: SuiteSlotEventAppendCheckpoint,
): Promise<number | null> {
  const childPath = path.join(process.cwd(), ".tmp/build/test/support/suite-slot-ledger-child.js");
  return await spawnExit(childPath, ["crash", runDirectory, point]);
}

function spawnExit(file: string, arguments_: readonly string[]): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file, ...arguments_], { stdio: "ignore" });
    child.once("error", reject);
    child.once("exit", resolve);
  });
}

async function waitForFiles(files: readonly string[]): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const ready = await Promise.all(
      files.map(async (file) => {
        try {
          await access(file);
          return true;
        } catch {
          return false;
        }
      }),
    );
    if (ready.every(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("synthetic child readiness timed out");
}

function isLedgerError(error: unknown, code: SuiteSlotLedgerError["code"]): boolean {
  return error instanceof SuiteSlotLedgerError && error.code === code;
}

function ledgerError(code: SuiteSlotLedgerError["code"]): (error: unknown) => boolean {
  return (error) => isLedgerError(error, code);
}

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected rejection");
}
