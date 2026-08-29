import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

import { parseJson, type JsonValue } from "../src/bundle/json.js";
import {
  validateJsonSchema,
  validateJsonSchemaDefinition,
} from "../src/bundle/schema-validator.js";
import {
  MAX_SUITE_SLOT_EVENT_BYTES,
  SuiteSlotEventError,
  computeSuiteSlotOutcomeIdentityDigest,
  computeSuiteSlotEventId,
  createSuiteSlotEvent,
  encodeSuiteSlotEvent,
  readSuiteSlotEvent,
  reduceSuiteSlotEvents,
  type CreateSuiteSlotEventInput,
  type SuiteSlotEvent,
  type SuiteSlotOutcomeIdentityInput,
} from "../src/suite/slot-event.js";
import {
  syntheticSanitizedSuiteRunManifest,
  syntheticSuiteRunManifest,
} from "./support/synthetic-suite-run.js";

const OUTCOME_B = "e".repeat(64);

test("creates deterministic canonical event bytes and validates the schema", async () => {
  const manifest = syntheticSuiteRunManifest();
  const event = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const second = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });

  assert.deepEqual(second, event);
  assert.deepEqual(encodeSuiteSlotEvent(second), encodeSuiteSlotEvent(event));
  assert.equal(event.eventId, computeSuiteSlotEventId(event));
  assert.equal(event.eventId, "dfbdc421bed4fffcad0dca1bd09df4b1f9f68fb7e816f99b6087a6c9ccc57373");
  assert.deepEqual(readSuiteSlotEvent(encodeSuiteSlotEvent(event)), event);
  assert.equal(Object.isFrozen(event), true);
  assert.equal(
    encodeSuiteSlotEvent(event).toString("utf8"),
    `${JSON.stringify({
      suiteSlotEventVersion: 1,
      suiteSlotEventIdentityVersion: 1,
      suiteRunId: event.suiteRunId,
      sequence: 0,
      previousEventId: null,
      eventId: "dfbdc421bed4fffcad0dca1bd09df4b1f9f68fb7e816f99b6087a6c9ccc57373",
      recordedAt: "2026-01-02T03:04:05.006Z",
      caseIndex: 0,
      repeatIndex: 0,
      attemptKey: event.attemptKey,
      runId: event.runId,
      attemptId: event.attemptId,
      previousStatus: "pending",
      status: "running",
      failureCode: null,
      outcomeIdentityDigest: null,
    })}\n`,
  );

  const schema = parseJson(
    await readFile("schemas/suite-slot-event-v1.schema.json", "utf8"),
    "suite slot event schema",
  );
  assert.deepEqual(validateJsonSchemaDefinition(schema), []);
  assert.deepEqual(validateJsonSchema(schema, event as unknown as JsonValue), []);

  const source = encodeSuiteSlotEvent(event).toString("utf8");
  for (const marker of [
    "synthetic-private-case",
    "synthetic-private-kind",
    "SYNTHETIC_PRIVATE_BUNDLE",
    "/synthetic/private/path",
  ]) {
    assert.equal(source.includes(marker), false);
  }
});

test("machine-readable schema fixes sequence and status field matrices", async () => {
  const schema = parseJson(
    await readFile("schemas/suite-slot-event-v1.schema.json", "utf8"),
    "suite slot event schema",
  );
  const manifest = syntheticSuiteRunManifest();
  const running = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const digest = "f".repeat(64);
  for (const fields of [
    { status: "running", failureCode: null, outcomeIdentityDigest: null },
    { status: "succeeded", failureCode: null, outcomeIdentityDigest: digest },
    { status: "failed", failureCode: "provider_failed", outcomeIdentityDigest: digest },
    { status: "cancelled", failureCode: "execution_cancelled", outcomeIdentityDigest: digest },
    {
      status: "interrupted",
      failureCode: "execution_interrupted",
      outcomeIdentityDigest: digest,
    },
  ]) {
    assert.deepEqual(
      validateJsonSchema(schema, { ...running, ...fields } as unknown as JsonValue),
      [],
    );
  }
  for (const fields of [
    { status: "running", failureCode: "provider_failed", outcomeIdentityDigest: digest },
    { status: "succeeded", failureCode: "provider_failed", outcomeIdentityDigest: digest },
    { status: "failed", failureCode: "execution_cancelled", outcomeIdentityDigest: digest },
    { status: "cancelled", failureCode: "provider_failed", outcomeIdentityDigest: digest },
    { status: "interrupted", failureCode: "approval_denied", outcomeIdentityDigest: digest },
  ]) {
    assert.notDeepEqual(
      validateJsonSchema(schema, { ...running, ...fields } as unknown as JsonValue),
      [],
    );
  }
  assert.notDeepEqual(
    validateJsonSchema(
      schema,
      { ...running, sequence: 1, previousEventId: null } as unknown as JsonValue,
    ),
    [],
  );
});

test("reduces success and preserves interrupted history across resume", () => {
  const manifest = syntheticSuiteRunManifest();
  const running = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const interrupted = createEvent(manifest, running, {
    recordedAt: "2026-01-02T03:04:06.000Z",
    previousStatus: "running",
    status: "interrupted",
    failureCode: "execution_interrupted",
  });
  const resumed = createEvent(manifest, interrupted, {
    recordedAt: "2026-01-02T03:04:07.000Z",
    previousStatus: "interrupted",
    status: "running",
  });
  const succeeded = createEvent(manifest, resumed, {
    recordedAt: "2026-01-02T03:04:08.000Z",
    previousStatus: "running",
    status: "succeeded",
  });

  assert.equal(
    succeeded.outcomeIdentityDigest,
    computeSuiteSlotOutcomeIdentityDigest(outcomeIdentity(succeeded)),
  );
  assert.equal(
    succeeded.outcomeIdentityDigest,
    "f7d5c8d04ad86845532c07f1c424d3605c5bf1c6319d7a457d89c59f3dd2088e",
  );
  const outcomeTamper = JSON.parse(
    encodeSuiteSlotEvent(succeeded).toString("utf8"),
  ) as Record<string, unknown>;
  outcomeTamper.outcomeIdentityDigest = "f".repeat(64);
  assert.throws(
    () => readSuiteSlotEvent(Buffer.from(JSON.stringify(outcomeTamper))),
    isEventError("suite_slot_event_identity_mismatch"),
  );

  const reduced = reduceSuiteSlotEvents(manifest, [running, interrupted, resumed, succeeded]);
  assert.equal(reduced.lastEventId, succeeded.eventId);
  assert.equal(reduced.slots[0]!.status, "succeeded");
  assert.deepEqual(
    reduced.slots[0]!.history.map(({ status }) => status),
    ["running", "interrupted", "running", "succeeded"],
  );
  assert.equal(Object.isFrozen(reduced), true);
  assert.equal(Object.isFrozen(reduced.events), true);
  assert.equal(Object.isFrozen(reduced.slots), true);
  assert.equal(Object.isFrozen(reduced.slots[0]!.history), true);
});

test("treats an empty chain as all manifest slots pending", () => {
  const manifest = syntheticSuiteRunManifest();
  const reduced = reduceSuiteSlotEvents(manifest, []);
  assert.equal(reduced.lastEventId, null);
  assert.equal(reduced.slots[0]!.status, "pending");
  assert.deepEqual(reduced.slots[0]!.history, []);
});

test("accepts a pre-epoch first event and still rejects timestamp rollback", () => {
  const manifest = syntheticSuiteRunManifest();
  const running = createEvent(manifest, null, {
    recordedAt: "1969-12-31T23:59:59.000Z",
    previousStatus: "pending",
    status: "running",
  });
  const reopened = readSuiteSlotEvent(encodeSuiteSlotEvent(running));

  assert.deepEqual(reopened, running);
  assert.equal(reduceSuiteSlotEvents(manifest, [reopened]).slots[0]!.status, "running");

  const rollback = createEvent(manifest, reopened, {
    recordedAt: "1969-12-31T23:59:58.999Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "provider_failed",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [reopened, rollback]),
    isEventError("suite_slot_event_chain_invalid"),
  );
});

test("rejects gaps, forks, foreign slots, timestamp rollback, and illegal transitions", () => {
  const manifest = syntheticSuiteRunManifest();
  const running = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const failed = createEvent(manifest, running, {
    recordedAt: "2026-01-02T03:04:06.000Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "provider_failed",
  });

  const gap = createEvent(manifest, failed, {
    sequence: 5,
    recordedAt: "2026-01-02T03:04:07.000Z",
    previousStatus: "failed",
    status: "running",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [running, failed, gap]),
    isEventError("suite_slot_event_chain_invalid"),
  );

  const fork = createEvent(manifest, running, {
    previousEventId: OUTCOME_B,
    recordedAt: "2026-01-02T03:04:06.000Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "provider_failed",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [running, fork]),
    isEventError("suite_slot_event_chain_invalid"),
  );

  const foreign = createEvent(manifest, null, {
    caseIndex: 1,
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [foreign]),
    isEventError("suite_slot_event_chain_invalid"),
  );

  const rollback = createEvent(manifest, running, {
    recordedAt: "2026-01-02T03:04:05.005Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "provider_failed",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [running, rollback]),
    isEventError("suite_slot_event_chain_invalid"),
  );

  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [running, failed, gapWithPrevious(failed)]),
    isEventError("suite_slot_transition_invalid"),
  );
});

test("rejects a failure code not fixed by the contract or suite manifest", () => {
  const manifest = syntheticSuiteRunManifest();
  const running = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const failed = createEvent(manifest, running, {
    recordedAt: "2026-01-02T03:04:06.000Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "unapproved_synthetic_code",
  });
  assert.throws(
    () => reduceSuiteSlotEvents(manifest, [running, failed]),
    isEventError("suite_slot_transition_invalid"),
  );
});

test("accepts the existing manifest safe-label alphabet for preflighted sanitizer codes", () => {
  const manifest = syntheticSanitizedSuiteRunManifest("Synthetic.Failure-Code");
  const running = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const failed = createEvent(manifest, running, {
    recordedAt: "2026-01-02T03:04:06.000Z",
    previousStatus: "running",
    status: "failed",
    failureCode: "Synthetic.Failure-Code",
  });
  assert.equal(reduceSuiteSlotEvents(manifest, [running, failed]).slots[0]!.status, "failed");
});

test("requires the dedicated cancellation and interruption failure codes", () => {
  const manifest = syntheticSuiteRunManifest();
  for (const [status, failureCode] of [
    ["cancelled", "provider_failed"],
    ["interrupted", "approval_denied"],
    ["failed", "execution_cancelled"],
    ["failed", "execution_interrupted"],
  ] as const) {
    assert.throws(
      () =>
        createSuiteSlotEvent({
          ...baseInput(manifest),
          previousStatus: "running",
          status,
          failureCode,
        }),
      isEventError("suite_slot_event_invalid"),
    );
  }
});

test("rejects identity tamper, duplicate members, unknown members, and partial JSON", () => {
  const manifest = syntheticSuiteRunManifest();
  const event = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const source = encodeSuiteSlotEvent(event).toString("utf8");
  const tampered = source.replace('"sequence":0', '"sequence":1');
  assert.throws(
    () => readSuiteSlotEvent(Buffer.from(tampered)),
    isEventError("suite_slot_event_invalid"),
  );
  assert.throws(
    () =>
      readSuiteSlotEvent(
        Buffer.from(source.replace("2026-01-02T03:04:05.006Z", "2026-01-02T03:04:05.007Z")),
      ),
    isEventError("suite_slot_event_identity_mismatch"),
  );
  assert.throws(
    () => readSuiteSlotEvent(Buffer.from(source.replace('"sequence":0', '"sequence":0,"sequence":0'))),
    isEventError("suite_slot_event_invalid"),
  );
  assert.throws(
    () => readSuiteSlotEvent(Buffer.from(source.replace('"sequence":0', '"unknown":0,"sequence":0'))),
    isEventError("suite_slot_event_invalid"),
  );
  assert.throws(
    () => readSuiteSlotEvent(Buffer.from(source.slice(0, -3))),
    isEventError("suite_slot_event_invalid"),
  );
  assert.throws(
    () => readSuiteSlotEvent(Buffer.alloc(MAX_SUITE_SLOT_EVENT_BYTES + 1)),
    isEventError("suite_slot_event_invalid"),
  );
});

test("bounds typed-array input before copying and rejects unsupported byte sources", () => {
  const manifest = syntheticSuiteRunManifest();
  const event = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const bytes = encodeSuiteSlotEvent(event);
  const canonicalBytes = new Uint8Array(bytes);
  const actualLength = bytes.length;
  Object.defineProperty(bytes, "byteLength", { value: Number.MAX_SAFE_INTEGER });
  Object.defineProperty(bytes, "length", { value: Number.MAX_SAFE_INTEGER });
  assert.deepEqual(readSuiteSlotEvent(bytes), event);
  assert.throws(
    () => readSuiteSlotEvent(new Uint8Array(MAX_SUITE_SLOT_EVENT_BYTES + 1)),
    isEventError("suite_slot_event_invalid"),
  );
  const sharedBytes = new Uint8Array(new SharedArrayBuffer(actualLength));
  sharedBytes.set(canonicalBytes);
  assert.throws(() => readSuiteSlotEvent(sharedBytes), isEventError("suite_slot_event_invalid"));
  const proxied = new Proxy(bytes, {});
  assert.throws(() => readSuiteSlotEvent(proxied), isEventError("suite_slot_event_invalid"));
  const foreign = runInNewContext("new Uint8Array(values)", {
    values: [...canonicalBytes],
  }) as Uint8Array;
  assert.throws(() => readSuiteSlotEvent(foreign), isEventError("suite_slot_event_invalid"));
});

test("normalizes hostile reflection failures at every public object boundary", () => {
  const manifest = syntheticSuiteRunManifest();
  const event = createEvent(manifest, null, {
    recordedAt: "2026-01-02T03:04:05.006Z",
    previousStatus: "pending",
    status: "running",
  });
  const marker = "/SYNTHETIC_PRIVATE_MARKER";
  const forged = new SuiteSlotEventError("suite_slot_event_chain_invalid", marker);
  const hostile = new Proxy(
    {},
    {
      getPrototypeOf: () => {
        throw forged;
      },
    },
  );
  const hostileBytes = new Proxy(new Uint8Array([123, 125]), {
    getPrototypeOf: () => {
      throw forged;
    },
  });
  const operations = [
    () => createSuiteSlotEvent(hostile as CreateSuiteSlotEventInput),
    () => computeSuiteSlotEventId(hostile as SuiteSlotEvent),
    () => encodeSuiteSlotEvent(hostile as SuiteSlotEvent),
    () => computeSuiteSlotOutcomeIdentityDigest(hostile as never),
    () => readSuiteSlotEvent(hostileBytes),
    () => reduceSuiteSlotEvents(hostile as never, [event]),
    () => reduceSuiteSlotEvents(manifest, [hostile as SuiteSlotEvent]),
  ];
  for (const operation of operations) {
    const error = captureError(operation);
    assert.equal(error instanceof SuiteSlotEventError, true);
    assert.equal((error as SuiteSlotEventError).code, "suite_slot_event_invalid");
    assert.equal((error as Error).message.includes(marker), false);
  }

  const exposed = captureError(() =>
    readSuiteSlotEvent(
      Buffer.from(
        encodeSuiteSlotEvent(event)
          .toString("utf8")
          .replace("2026-01-02T03:04:05.006Z", "2026-01-02T03:04:05.007Z"),
      ),
    ),
  ) as SuiteSlotEventError;
  exposed.message = marker;
  const replay = new Proxy(
    {},
    {
      getPrototypeOf: () => {
        throw exposed;
      },
    },
  );
  const replayed = captureError(() =>
    createSuiteSlotEvent(replay as CreateSuiteSlotEventInput),
  ) as SuiteSlotEventError;
  assert.equal(replayed.code, "suite_slot_event_invalid");
  assert.equal(replayed.message.includes(marker), false);
});

test("rejects runtime accessors and status-dependent field mismatches", () => {
  const manifest = syntheticSuiteRunManifest();
  const input = baseInput(manifest);
  Object.defineProperty(input, "recordedAt", {
    enumerable: true,
    get: () => "2026-01-02T03:04:05.006Z",
  });
  assert.throws(() => createSuiteSlotEvent(input), isEventError("suite_slot_event_invalid"));

  assert.throws(
    () =>
      createSuiteSlotEvent({
        ...baseInput(manifest),
        status: "succeeded",
        failureCode: "provider_failed",
      }),
    isEventError("suite_slot_event_invalid"),
  );
  assert.throws(
    () =>
      createSuiteSlotEvent({
        ...baseInput(manifest),
        recordedAt: "2026-01-02T03:04:05Z",
      }),
    isEventError("suite_slot_event_invalid"),
  );
  for (const field of ["sequence", "caseIndex", "repeatIndex"] as const) {
    assert.throws(
      () => createSuiteSlotEvent({ ...baseInput(manifest), [field]: -0 }),
      isEventError("suite_slot_event_invalid"),
    );
  }
});

function createEvent(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
  previous: SuiteSlotEvent | null,
  overrides: Partial<CreateSuiteSlotEventInput>,
): SuiteSlotEvent {
  const slot = manifest.slots[0]!;
  return createSuiteSlotEvent({
    suiteRunId: manifest.suiteRunId,
    sequence: previous === null ? 0 : previous.sequence + 1,
    previousEventId: previous?.eventId ?? null,
    recordedAt: "2026-01-02T03:04:05.006Z",
    caseIndex: slot.caseIndex,
    repeatIndex: slot.repeatIndex,
    attemptKey: slot.attemptKey,
    runId: slot.runId,
    attemptId: slot.attemptId,
    previousStatus: previous?.status ?? "pending",
    status: "running",
    failureCode: null,
    ...overrides,
  });
}

function baseInput(
  manifest: ReturnType<typeof syntheticSuiteRunManifest>,
): CreateSuiteSlotEventInput {
  const slot = manifest.slots[0]!;
  return {
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
  };
}

function gapWithPrevious(previous: SuiteSlotEvent): SuiteSlotEvent {
  return createSuiteSlotEvent({
    suiteRunId: previous.suiteRunId,
    sequence: previous.sequence + 1,
    previousEventId: previous.eventId,
    recordedAt: previous.recordedAt,
    caseIndex: previous.caseIndex,
    repeatIndex: previous.repeatIndex,
    attemptKey: previous.attemptKey,
    runId: previous.runId,
    attemptId: previous.attemptId,
    previousStatus: "failed",
    status: "running",
    failureCode: null,
  });
}

function isEventError(code: SuiteSlotEventError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof SuiteSlotEventError && error.code === code;
}

function outcomeIdentity(event: SuiteSlotEvent): SuiteSlotOutcomeIdentityInput {
  if (event.status === "running") throw new Error("expected a non-running synthetic event");
  return {
    suiteRunId: event.suiteRunId,
    recordedAt: event.recordedAt,
    caseIndex: event.caseIndex,
    repeatIndex: event.repeatIndex,
    attemptKey: event.attemptKey,
    runId: event.runId,
    attemptId: event.attemptId,
    status: event.status,
    failureCode: event.failureCode,
  };
}

function captureError(operation: () => unknown): unknown {
  try {
    operation();
  } catch (error) {
    return error;
  }
  throw new Error("expected operation to throw");
}
