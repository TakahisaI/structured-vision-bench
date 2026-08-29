import { createHash } from "node:crypto";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../bundle/json.js";
import {
  encodeSuiteRunManifest,
  readSuiteRunManifest,
  type SuiteRunManifest,
  type SuiteRunSlotIdentity,
} from "./run-manifest.js";

export const SUITE_SLOT_EVENT_VERSION = 1 as const;
export const SUITE_SLOT_EVENT_IDENTITY_VERSION = 1 as const;
export const MAX_SUITE_SLOT_EVENT_BYTES = 8 * 1024;
export const MAX_SUITE_SLOT_EVENTS = 100_000;

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_CODE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const AUTHENTIC_ERRORS = new WeakSet<object>();

export const SUITE_SLOT_FAILURE_CODES = Object.freeze([
  "approval_configuration_invalid",
  "approval_denied",
  "approval_required",
  "approval_response_invalid",
  "approval_timeout",
  "attempt_document_digest_mismatch",
  "attempt_exists",
  "attempt_identity_mismatch",
  "attempt_invalid",
  "attempt_write_failed",
  "execution_cancelled",
  "execution_interrupted",
  "internal_error",
  "provider_document_schema_invalid",
  "provider_document_too_large",
  "provider_failed",
  "provider_invalid",
  "provider_response_invalid",
  "provider_timeout",
  "run_configuration_invalid",
  "runner_bundle_changed_after_approval",
  "runner_input_unreadable",
  "sanitizer_configuration_invalid",
  "sanitizer_failed",
  "sanitizer_policy_binding_mismatch",
  "sanitizer_policy_identity_mismatch",
  "sanitizer_policy_invalid",
  "sanitizer_policy_missing",
  "sanitizer_policy_target_mismatch",
  "sanitizer_required",
  "sanitizer_requirement_invalid",
  "sanitizer_response_invalid",
  "sanitizer_timeout",
] as const);

export type SuiteSlotStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "interrupted";

export type SuiteSlotEventErrorCode =
  | "suite_slot_event_invalid"
  | "suite_slot_event_identity_mismatch"
  | "suite_slot_event_chain_invalid"
  | "suite_slot_transition_invalid";

export class SuiteSlotEventError extends Error {
  readonly code: SuiteSlotEventErrorCode;

  constructor(code: SuiteSlotEventErrorCode, message: string) {
    super(message);
    this.name = "SuiteSlotEventError";
    this.code = code;
  }
}

export type SuiteSlotEventIdentity = Readonly<{
  suiteSlotEventVersion: 1;
  suiteSlotEventIdentityVersion: 1;
  suiteRunId: string;
  sequence: number;
  previousEventId: string | null;
  recordedAt: string;
  caseIndex: number;
  repeatIndex: number;
  attemptKey: string;
  runId: string;
  attemptId: string;
  previousStatus: SuiteSlotStatus;
  status: Exclude<SuiteSlotStatus, "pending">;
  failureCode: string | null;
  outcomeIdentityDigest: string | null;
}>;

export type SuiteSlotEvent = SuiteSlotEventIdentity & Readonly<{ eventId: string }>;

export type CreateSuiteSlotEventInput = Omit<
  SuiteSlotEventIdentity,
  "suiteSlotEventVersion" | "suiteSlotEventIdentityVersion" | "outcomeIdentityDigest"
>;

export type SuiteSlotOutcomeIdentityInput = Omit<
  Pick<
    SuiteSlotEventIdentity,
    | "suiteRunId"
    | "recordedAt"
    | "caseIndex"
    | "repeatIndex"
    | "attemptKey"
    | "runId"
    | "attemptId"
    | "status"
    | "failureCode"
  >,
  "status"
> &
  Readonly<{ status: "succeeded" | "failed" | "cancelled" | "interrupted" }>;

export type ReducedSuiteSlot = Readonly<{
  caseIndex: number;
  repeatIndex: number;
  attemptKey: string;
  runId: string;
  attemptId: string;
  status: SuiteSlotStatus;
  history: readonly SuiteSlotEvent[];
}>;

export type SuiteSlotEventReduction = Readonly<{
  suiteRunId: string;
  lastEventId: string | null;
  slots: readonly ReducedSuiteSlot[];
  events: readonly SuiteSlotEvent[];
}>;

/** Creates one deterministic value-free slot transition record. */
export function createSuiteSlotEvent(input: CreateSuiteSlotEventInput): SuiteSlotEvent {
  try {
    const snapshot = snapshotCreateInput(input);
    return freezeEvent({ ...snapshot, eventId: computeIdentityDigest(snapshot) });
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Recomputes the event identity from every record member except eventId. */
export function computeSuiteSlotEventId(event: SuiteSlotEvent): string {
  try {
    return computeIdentityDigest(toIdentity(snapshotEvent(event)));
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Derives the chain-independent identity of one non-running slot outcome. */
export function computeSuiteSlotOutcomeIdentityDigest(
  input: SuiteSlotOutcomeIdentityInput,
): string {
  try {
    return computeOutcomeIdentityDigest(snapshotOutcomeIdentity(input));
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Emits compact canonical JSON followed by one newline. */
export function encodeSuiteSlotEvent(event: SuiteSlotEvent): Buffer {
  try {
    const snapshot = snapshotEvent(event);
    if (computeIdentityDigest(toIdentity(snapshot)) !== snapshot.eventId) {
      throw identityMismatch();
    }
    const bytes = Buffer.from(`${JSON.stringify(snapshot)}\n`, "utf8");
    if (bytes.length > MAX_SUITE_SLOT_EVENT_BYTES) throw invalidEvent();
    return bytes;
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Strictly reads one bounded event record without opening files. */
export function readSuiteSlotEvent(bytes: Uint8Array): SuiteSlotEvent {
  try {
    const byteSnapshot = snapshotBytes(bytes);
    if (byteSnapshot.byteLength === 0 || byteSnapshot.byteLength > MAX_SUITE_SLOT_EVENT_BYTES) {
      throw invalidEvent();
    }
    const parsed = parseJson(decodeUtf8Strict(byteSnapshot, "suite slot event"), "suite slot event");
    if (!isJsonObject(parsed)) throw invalidEvent();
    const event = snapshotEvent(parsed);
    if (computeIdentityDigest(toIdentity(event)) !== event.eventId) throw identityMismatch();
    return event;
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Reduces a complete ordered chain against the immutable suite-run slot identities. */
export function reduceSuiteSlotEvents(
  manifest: SuiteRunManifest,
  sourceEvents: readonly SuiteSlotEvent[],
): SuiteSlotEventReduction {
  try {
    const manifestSnapshot = readSuiteRunManifest(encodeSuiteRunManifest(manifest));
    const events = snapshotEventList(sourceEvents);
    const slots = manifestSnapshot.slots.map(createMutableSlot);
    const byPosition = new Map(slots.map((slot) => [slotKey(slot.caseIndex, slot.repeatIndex), slot]));
    const allowedFailureCodes = new Set<string>([
      ...SUITE_SLOT_FAILURE_CODES,
      ...(manifestSnapshot.sanitizer?.failureCodes ?? []),
    ]);
    let previousEventId: string | null = null;
    let previousTime = Number.NEGATIVE_INFINITY;

    for (let sequence = 0; sequence < events.length; sequence += 1) {
      const event = events[sequence]!;
      if (
        event.suiteRunId !== manifestSnapshot.suiteRunId ||
        event.sequence !== sequence ||
        event.previousEventId !== previousEventId
      ) {
        throw chainInvalid();
      }
      const slot = byPosition.get(slotKey(event.caseIndex, event.repeatIndex));
      if (slot === undefined || !matchesSlot(event, slot)) throw chainInvalid();
      const recordedTime = Date.parse(event.recordedAt);
      if (recordedTime < previousTime) throw chainInvalid();
      if (event.previousStatus !== slot.status || !isAllowedTransition(slot.status, event.status)) {
        throw transitionInvalid();
      }
      if (event.failureCode !== null && !allowedFailureCodes.has(event.failureCode)) {
        throw transitionInvalid();
      }
      slot.status = event.status;
      slot.history.push(event);
      previousEventId = event.eventId;
      previousTime = recordedTime;
    }

    const frozenSlots = Object.freeze(
      slots.map((slot) =>
        Object.freeze({
          caseIndex: slot.caseIndex,
          repeatIndex: slot.repeatIndex,
          attemptKey: slot.attemptKey,
          runId: slot.runId,
          attemptId: slot.attemptId,
          status: slot.status,
          history: Object.freeze([...slot.history]),
        }),
      ),
    );
    return Object.freeze({
      suiteRunId: manifestSnapshot.suiteRunId,
      lastEventId: previousEventId,
      slots: frozenSlots,
      events: Object.freeze(events),
    });
  } catch (error) {
    throw normalizeError(error);
  }
}

function snapshotEventList(source: readonly SuiteSlotEvent[]): SuiteSlotEvent[] {
  if (!Array.isArray(source)) throw invalidEvent();
  const length = Object.getOwnPropertyDescriptor(source, "length")?.value;
  if (
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > MAX_SUITE_SLOT_EVENTS ||
    Object.getOwnPropertySymbols(source).length !== 0
  ) {
    throw invalidEvent();
  }
  const names = Object.getOwnPropertyNames(source);
  if (names.length !== length + 1 || !names.includes("length")) throw invalidEvent();
  const events: SuiteSlotEvent[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(source, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw invalidEvent();
    }
    events.push(readSuiteSlotEvent(encodeSuiteSlotEvent(descriptor.value as SuiteSlotEvent)));
  }
  return events;
}

type MutableReducedSlot = {
  caseIndex: number;
  repeatIndex: number;
  attemptKey: string;
  runId: string;
  attemptId: string;
  status: SuiteSlotStatus;
  history: SuiteSlotEvent[];
};

function createMutableSlot(slot: SuiteRunSlotIdentity): MutableReducedSlot {
  return {
    caseIndex: slot.caseIndex,
    repeatIndex: slot.repeatIndex,
    attemptKey: slot.attemptKey,
    runId: slot.runId,
    attemptId: slot.attemptId,
    status: "pending",
    history: [],
  };
}

function matchesSlot(event: SuiteSlotEvent, slot: MutableReducedSlot): boolean {
  return (
    event.attemptKey === slot.attemptKey &&
    event.runId === slot.runId &&
    event.attemptId === slot.attemptId
  );
}

function isAllowedTransition(
  previous: SuiteSlotStatus,
  next: Exclude<SuiteSlotStatus, "pending">,
): boolean {
  if (previous === "pending") return next === "running";
  if (previous === "running") {
    return ["succeeded", "failed", "cancelled", "interrupted"].includes(next);
  }
  return previous === "interrupted" && next === "running";
}

function snapshotCreateInput(input: CreateSuiteSlotEventInput): SuiteSlotEventIdentity {
  const source = snapshotPlainObject(input, [
    "suiteRunId",
    "sequence",
    "previousEventId",
    "recordedAt",
    "caseIndex",
    "repeatIndex",
    "attemptKey",
    "runId",
    "attemptId",
    "previousStatus",
    "status",
    "failureCode",
  ]);
  const outcomeIdentityDigest =
    source.status === "running"
      ? null
      : computeOutcomeIdentityDigest(outcomeIdentityFromSource(source));
  return validateIdentity({
    suiteSlotEventVersion: SUITE_SLOT_EVENT_VERSION,
    suiteSlotEventIdentityVersion: SUITE_SLOT_EVENT_IDENTITY_VERSION,
    ...source,
    outcomeIdentityDigest,
  });
}

function snapshotEvent(value: unknown): SuiteSlotEvent {
  const source = snapshotPlainObject(value, [
    "suiteSlotEventVersion",
    "suiteSlotEventIdentityVersion",
    "suiteRunId",
    "sequence",
    "previousEventId",
    "eventId",
    "recordedAt",
    "caseIndex",
    "repeatIndex",
    "attemptKey",
    "runId",
    "attemptId",
    "previousStatus",
    "status",
    "failureCode",
    "outcomeIdentityDigest",
  ]);
  const identity = validateIdentity(source);
  if (!isDigest(source.eventId)) throw invalidEvent();
  return freezeEvent({ ...identity, eventId: source.eventId });
}

function validateIdentity(source: Record<string, unknown>): SuiteSlotEventIdentity {
  if (
    source.suiteSlotEventVersion !== SUITE_SLOT_EVENT_VERSION ||
    source.suiteSlotEventIdentityVersion !== SUITE_SLOT_EVENT_IDENTITY_VERSION ||
    !isDigest(source.suiteRunId) ||
    !isBoundedInteger(source.sequence, 0, MAX_SUITE_SLOT_EVENTS - 1) ||
    !(source.previousEventId === null || isDigest(source.previousEventId)) ||
    !isCanonicalTimestamp(source.recordedAt) ||
    !isBoundedInteger(source.caseIndex, 0, 999) ||
    !isBoundedInteger(source.repeatIndex, 0, 999) ||
    !isAttemptKey(source.attemptKey) ||
    !isDigest(source.runId) ||
    !isDigest(source.attemptId) ||
    !isStatus(source.previousStatus) ||
    !isEventStatus(source.status) ||
    !(source.failureCode === null || isSafeCode(source.failureCode)) ||
    !(source.outcomeIdentityDigest === null || isDigest(source.outcomeIdentityDigest))
  ) {
    throw invalidEvent();
  }
  if ((source.sequence === 0) !== (source.previousEventId === null)) throw invalidEvent();
  if (source.status === "running") {
    if (source.failureCode !== null || source.outcomeIdentityDigest !== null) throw invalidEvent();
  } else {
    if (source.status === "succeeded" && source.failureCode !== null) throw invalidEvent();
    if (source.status === "cancelled" && source.failureCode !== "execution_cancelled") {
      throw invalidEvent();
    }
    if (source.status === "interrupted" && source.failureCode !== "execution_interrupted") {
      throw invalidEvent();
    }
    if (
      source.status === "failed" &&
      (source.failureCode === null ||
        source.failureCode === "execution_cancelled" ||
        source.failureCode === "execution_interrupted")
    ) {
      throw invalidEvent();
    }
    const expectedOutcomeIdentityDigest = computeOutcomeIdentityDigest(
      outcomeIdentityFromSource(source),
    );
    if (source.outcomeIdentityDigest !== expectedOutcomeIdentityDigest) throw identityMismatch();
  }
  return Object.freeze({
    suiteSlotEventVersion: 1,
    suiteSlotEventIdentityVersion: 1,
    suiteRunId: source.suiteRunId,
    sequence: source.sequence,
    previousEventId: source.previousEventId,
    recordedAt: source.recordedAt,
    caseIndex: source.caseIndex,
    repeatIndex: source.repeatIndex,
    attemptKey: source.attemptKey,
    runId: source.runId,
    attemptId: source.attemptId,
    previousStatus: source.previousStatus,
    status: source.status,
    failureCode: source.failureCode,
    outcomeIdentityDigest: source.outcomeIdentityDigest,
  });
}

function snapshotPlainObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw invalidEvent();
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== keys.length || !keys.every((key) => names.includes(key))) {
    throw invalidEvent();
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw invalidEvent();
    }
    result[key] = descriptor.value;
  }
  return result;
}

function snapshotOutcomeIdentity(value: unknown): SuiteSlotOutcomeIdentityInput {
  const source = snapshotPlainObject(value, [
    "suiteRunId",
    "recordedAt",
    "caseIndex",
    "repeatIndex",
    "attemptKey",
    "runId",
    "attemptId",
    "status",
    "failureCode",
  ]);
  return outcomeIdentityFromSource(source);
}

function outcomeIdentityFromSource(
  source: Record<string, unknown>,
): SuiteSlotOutcomeIdentityInput {
  if (
    !isDigest(source.suiteRunId) ||
    !isCanonicalTimestamp(source.recordedAt) ||
    !isBoundedInteger(source.caseIndex, 0, 999) ||
    !isBoundedInteger(source.repeatIndex, 0, 999) ||
    !isAttemptKey(source.attemptKey) ||
    !isDigest(source.runId) ||
    !isDigest(source.attemptId) ||
    !isEventStatus(source.status) ||
    source.status === "running" ||
    !(source.failureCode === null || isSafeCode(source.failureCode))
  ) {
    throw invalidEvent();
  }
  if (source.status === "succeeded" && source.failureCode !== null) throw invalidEvent();
  if (source.status === "cancelled" && source.failureCode !== "execution_cancelled") {
    throw invalidEvent();
  }
  if (source.status === "interrupted" && source.failureCode !== "execution_interrupted") {
    throw invalidEvent();
  }
  if (
    source.status === "failed" &&
    (source.failureCode === null ||
      source.failureCode === "execution_cancelled" ||
      source.failureCode === "execution_interrupted")
  ) {
    throw invalidEvent();
  }
  return Object.freeze({
    suiteRunId: source.suiteRunId,
    recordedAt: source.recordedAt,
    caseIndex: source.caseIndex,
    repeatIndex: source.repeatIndex,
    attemptKey: source.attemptKey,
    runId: source.runId,
    attemptId: source.attemptId,
    status: source.status,
    failureCode: source.failureCode,
  });
}

function freezeEvent(event: SuiteSlotEventIdentity & { eventId: string }): SuiteSlotEvent {
  return Object.freeze({
    suiteSlotEventVersion: event.suiteSlotEventVersion,
    suiteSlotEventIdentityVersion: event.suiteSlotEventIdentityVersion,
    suiteRunId: event.suiteRunId,
    sequence: event.sequence,
    previousEventId: event.previousEventId,
    eventId: event.eventId,
    recordedAt: event.recordedAt,
    caseIndex: event.caseIndex,
    repeatIndex: event.repeatIndex,
    attemptKey: event.attemptKey,
    runId: event.runId,
    attemptId: event.attemptId,
    previousStatus: event.previousStatus,
    status: event.status,
    failureCode: event.failureCode,
    outcomeIdentityDigest: event.outcomeIdentityDigest,
  });
}

function toIdentity(event: SuiteSlotEvent): SuiteSlotEventIdentity {
  const { eventId: _eventId, ...identity } = event;
  return identity;
}

function computeIdentityDigest(identity: SuiteSlotEventIdentity): string {
  const bytes = Buffer.from(JSON.stringify(identity), "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return createHash("sha256")
    .update(Buffer.from("svbench-suite-slot-event-v1", "ascii"))
    .update(length)
    .update(bytes)
    .digest("hex");
}

function computeOutcomeIdentityDigest(identity: SuiteSlotOutcomeIdentityInput): string {
  const bytes = Buffer.from(JSON.stringify(identity), "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return createHash("sha256")
    .update(Buffer.from("svbench-suite-slot-outcome-v1", "ascii"))
    .update(length)
    .update(bytes)
    .digest("hex");
}

function snapshotBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) throw invalidEvent();
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
  const byteLengthGetter = Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    "byteLength",
  )?.get;
  const byteOffsetGetter = Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    "byteOffset",
  )?.get;
  const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")?.get;
  const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(
    ArrayBuffer.prototype,
    "byteLength",
  )?.get;
  if (
    byteLengthGetter === undefined ||
    byteOffsetGetter === undefined ||
    bufferGetter === undefined ||
    arrayBufferByteLengthGetter === undefined
  ) {
    throw invalidEvent();
  }
  const byteLength = Reflect.apply(byteLengthGetter, value, []) as number;
  if (byteLength === 0 || byteLength > MAX_SUITE_SLOT_EVENT_BYTES) throw invalidEvent();
  const byteOffset = Reflect.apply(byteOffsetGetter, value, []) as number;
  const buffer = Reflect.apply(bufferGetter, value, []) as ArrayBufferLike;
  Reflect.apply(arrayBufferByteLengthGetter, buffer, []);
  const source = new Uint8Array(buffer as ArrayBuffer, byteOffset, byteLength);
  const snapshot = new Uint8Array(byteLength);
  Uint8Array.prototype.set.call(snapshot, source);
  return snapshot;
}

function slotKey(caseIndex: number, repeatIndex: number): string {
  return `${caseIndex}:${repeatIndex}`;
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function isSafeCode(value: unknown): value is string {
  return typeof value === "string" && SAFE_CODE_PATTERN.test(value);
}

function isAttemptKey(value: unknown): value is string {
  return typeof value === "string" && /^c[0-9a-z]+-r[0-9a-z]+$/u.test(value) && value.length <= 64;
}

function isCanonicalTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    TIMESTAMP_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return (
    Number.isSafeInteger(value) &&
    !Object.is(value, -0) &&
    (value as number) >= minimum &&
    (value as number) <= maximum
  );
}

function isStatus(value: unknown): value is SuiteSlotStatus {
  return ["pending", "running", "succeeded", "failed", "cancelled", "interrupted"].includes(
    value as SuiteSlotStatus,
  );
}

function isEventStatus(value: unknown): value is Exclude<SuiteSlotStatus, "pending"> {
  return isStatus(value) && value !== "pending";
}

function invalidEvent(): SuiteSlotEventError {
  return authenticError("suite_slot_event_invalid", "suite slot event is invalid");
}

function identityMismatch(): SuiteSlotEventError {
  return authenticError(
    "suite_slot_event_identity_mismatch",
    "suite slot event identity is invalid",
  );
}

function chainInvalid(): SuiteSlotEventError {
  return authenticError("suite_slot_event_chain_invalid", "suite slot event chain is invalid");
}

function transitionInvalid(): SuiteSlotEventError {
  return authenticError(
    "suite_slot_transition_invalid",
    "suite slot transition is invalid",
  );
}

function authenticError(code: SuiteSlotEventErrorCode, message: string): SuiteSlotEventError {
  const error = new SuiteSlotEventError(code, message);
  AUTHENTIC_ERRORS.add(error);
  return error;
}

function normalizeError(error: unknown): SuiteSlotEventError {
  if (typeof error === "object" && error !== null && AUTHENTIC_ERRORS.has(error)) {
    AUTHENTIC_ERRORS.delete(error);
    const code = (error as SuiteSlotEventError).code;
    return new SuiteSlotEventError(code, messageForCode(code));
  }
  return new SuiteSlotEventError("suite_slot_event_invalid", messageForCode("suite_slot_event_invalid"));
}

function messageForCode(code: SuiteSlotEventErrorCode): string {
  switch (code) {
    case "suite_slot_event_invalid":
      return "suite slot event is invalid";
    case "suite_slot_event_identity_mismatch":
      return "suite slot event identity is invalid";
    case "suite_slot_event_chain_invalid":
      return "suite slot event chain is invalid";
    case "suite_slot_transition_invalid":
      return "suite slot transition is invalid";
  }
}
