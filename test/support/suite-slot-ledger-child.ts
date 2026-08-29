import { access, writeFile } from "node:fs/promises";

import {
  SuiteSlotLedgerError,
  appendSuiteSlotEvent,
  type SuiteSlotEventAppendCheckpoint,
} from "../../src/suite/slot-ledger.js";
import { readSuiteRunDirectory } from "../../src/suite/run-directory.js";
import { createSuiteSlotEvent } from "../../src/suite/slot-event.js";

const [mode, runDirectory, value, readyFile, gateFile] = process.argv.slice(2);
if (mode === undefined || runDirectory === undefined || value === undefined) process.exit(64);

const reopened = await readSuiteRunDirectory(runDirectory);
const slot = reopened.manifest.slots[0]!;
const event = createSuiteSlotEvent({
  suiteRunId: reopened.manifest.suiteRunId,
  sequence: 0,
  previousEventId: null,
  recordedAt:
    mode === "contend" && value === "synthetic-b"
      ? "2026-01-02T03:04:05.007Z"
      : "2026-01-02T03:04:05.006Z",
  caseIndex: slot.caseIndex,
  repeatIndex: slot.repeatIndex,
  attemptKey: slot.attemptKey,
  runId: slot.runId,
  attemptId: slot.attemptId,
  previousStatus: "pending",
  status: "running",
  failureCode: null,
});

if (mode === "crash") {
  await appendSuiteSlotEvent(
    runDirectory,
    { expectedNextSequence: 0, expectedPreviousEventId: null, event },
    {
      checkpoint: (point) => {
        if (point === (value as SuiteSlotEventAppendCheckpoint)) process.exit(77);
      },
    },
  );
  process.exit(0);
}

if (mode !== "contend" || readyFile === undefined || gateFile === undefined) process.exit(64);
await writeFile(readyFile, "synthetic-ready\n", { flag: "wx", mode: 0o600 });
for (let attempt = 0; attempt < 500; attempt += 1) {
  try {
    await access(gateFile);
    break;
  } catch {
    if (attempt === 499) process.exit(65);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

try {
  await appendSuiteSlotEvent(runDirectory, {
    expectedNextSequence: 0,
    expectedPreviousEventId: null,
    event,
  });
  process.exit(0);
} catch (error) {
  if (error instanceof SuiteSlotLedgerError && error.code === "suite_slot_event_conflict") {
    process.exit(42);
  }
  process.exit(1);
}
