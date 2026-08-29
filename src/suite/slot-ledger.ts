import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, opendir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";

import {
  MAX_SUITE_SLOT_LEDGER_BYTES,
  SUITE_SLOT_EVENT_FILENAME_WIDTH,
  SUITE_SLOT_LEDGER_DIRECTORY_NAME,
  readSuiteRunDirectory,
  type SuiteRunDirectoryResult,
} from "./run-directory.js";
import {
  MAX_SUITE_RUN_MANIFEST_BYTES,
  encodeSuiteRunManifest,
} from "./run-manifest.js";
import {
  MAX_SUITE_SLOT_EVENT_BYTES,
  MAX_SUITE_SLOT_EVENTS,
  encodeSuiteSlotEvent,
  readSuiteSlotEvent,
  reduceSuiteSlotEvents,
  type SuiteSlotEvent,
} from "./slot-event.js";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const MANIFEST_NAME = "suite-run.json";
const STAGING_PREFIX = ".suite-slot-event-claim-";
const PENDING_EVENT_NAME = "slot-event.json.pending";
const FORMAL_LEDGER_CONFIRMATION_ATTEMPTS = 8;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;
const DIRECTORY = constants.O_DIRECTORY ?? 0;
const DIRECTORY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK | DIRECTORY;
const READ_ONLY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK;
const WRITE_EXCLUSIVE_NOFOLLOW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW;

export type SuiteSlotLedgerErrorCode =
  | "suite_slot_event_invalid"
  | "suite_slot_event_conflict"
  | "suite_slot_event_write_failed"
  | "suite_slot_event_publication_uncertain";

export class SuiteSlotLedgerError extends Error {
  readonly code: SuiteSlotLedgerErrorCode;

  constructor(code: SuiteSlotLedgerErrorCode, message: string) {
    super(message);
    this.name = "SuiteSlotLedgerError";
    this.code = code;
  }
}

export type SuiteSlotEventAppendInput = Readonly<{
  expectedNextSequence: number;
  expectedPreviousEventId: string | null;
  event: SuiteSlotEvent;
}>;

export type SuiteSlotEventAppendCheckpoint =
  | "head-verified"
  | "staging-created"
  | "record-written"
  | "record-synced"
  | "record-verified"
  | "root-synced-before-publish"
  | "before-publish"
  | "link-ready"
  | "record-published"
  | "record-synced-after-publish"
  | "ledger-synced"
  | "run-synced"
  | "root-synced-after-publish"
  | "record-verified-after-publish"
  | "staging-file-removed"
  | "staging-directory-removed"
  | "cleanup-root-synced";

export type SuiteSlotEventAppendHooks = Readonly<{
  checkpoint?: (point: SuiteSlotEventAppendCheckpoint) => void | Promise<void>;
}>;

export type SuiteSlotEventAppendResult = Readonly<{
  event: SuiteSlotEvent;
}>;

type FileIdentity = Readonly<{
  dev: number;
  ino: number;
  uid: number;
}>;

type DirectoryHandle = Awaited<ReturnType<typeof open>>;

type AppendState = {
  readonly rootDirectory: string;
  readonly runDirectory: string;
  readonly manifestPath: string;
  readonly ledgerDirectory: string;
  readonly stagingDirectory: string;
  readonly pendingEventPath: string;
  readonly finalEventPath: string;
  rootHandle: DirectoryHandle | undefined;
  runHandle: DirectoryHandle | undefined;
  ledgerHandle: DirectoryHandle | undefined;
  stagingHandle: DirectoryHandle | undefined;
  rootIdentity: FileIdentity | undefined;
  runIdentity: FileIdentity | undefined;
  ledgerIdentity: FileIdentity | undefined;
  stagingIdentity: FileIdentity | undefined;
  manifestIdentity: FileIdentity | undefined;
  pendingIdentity: FileIdentity | undefined;
  stagingPresent: boolean;
  pendingPresent: boolean;
  linked: boolean;
};

const INTERNAL_CONFLICT = Symbol("suite-slot-ledger-conflict");
const INTERNAL_INVALID_EVENT = Symbol("suite-slot-ledger-invalid-event");

/** Atomically appends one canonical event to a private suite-slot ledger. */
export async function appendSuiteSlotEvent(
  runDirectoryInput: string,
  inputValue: SuiteSlotEventAppendInput,
  hooks: SuiteSlotEventAppendHooks = {},
): Promise<SuiteSlotEventAppendResult> {
  let runDirectory: string;
  let input: SuiteSlotEventAppendInput;
  let eventBytes: Buffer;
  let checkpoint: SuiteSlotEventAppendHooks["checkpoint"];
  let state: AppendState;
  try {
    runDirectory = resolveDirectoryArgument(runDirectoryInput);
    input = snapshotAppendInput(inputValue);
    eventBytes = encodeSuiteSlotEvent(input.event);
    const event = readSuiteSlotEvent(eventBytes);
    if (
      event.sequence !== input.expectedNextSequence ||
      event.previousEventId !== input.expectedPreviousEventId
    ) {
      throw new Error();
    }
    input = Object.freeze({
      expectedNextSequence: input.expectedNextSequence,
      expectedPreviousEventId: input.expectedPreviousEventId,
      event,
    });
    checkpoint = snapshotCheckpoint(hooks);
    state = createAppendState(runDirectory, event.sequence);
  } catch {
    throw appendError("suite_slot_event_invalid");
  }

  try {
    requireSupportedFilesystem();
    const initial = await readFormalRunWithRetry(state.runDirectory);
    validateExpectedHead(initial, input);
    validateCandidate(initial, input.event, eventBytes.byteLength);

    const rootOpened = await openPrivateDirectory(state.rootDirectory);
    state.rootHandle = rootOpened.handle;
    state.rootIdentity = rootOpened.identity;
    const runOpened = await openPrivateDirectory(state.runDirectory, rootOpened.identity.dev);
    state.runHandle = runOpened.handle;
    state.runIdentity = runOpened.identity;
    const ledgerOpened = await openPrivateDirectory(
      state.ledgerDirectory,
      runOpened.identity.dev,
    );
    state.ledgerHandle = ledgerOpened.handle;
    state.ledgerIdentity = ledgerOpened.identity;
    const manifestBytes = encodeSuiteRunManifest(initial.manifest);
    const manifestRead = await readPrivateFile(
      state.manifestPath,
      MAX_SUITE_RUN_MANIFEST_BYTES,
      undefined,
      runOpened.identity.dev,
    );
    if (!manifestRead.bytes.equals(manifestBytes)) throw new Error();
    state.manifestIdentity = manifestRead.identity;
    await assertOpenLayoutStable(state, manifestBytes);
    await checkpoint?.("head-verified");

    await mkdir(state.stagingDirectory, { recursive: false, mode: 0o700 });
    state.stagingPresent = true;
    const stagingOpened = await openPrivateDirectory(
      state.stagingDirectory,
      rootOpened.identity.dev,
    );
    state.stagingHandle = stagingOpened.handle;
    state.stagingIdentity = stagingOpened.identity;
    await state.rootHandle.sync();
    await checkpoint?.("staging-created");
    await assertStagingEmpty(state);

    state.pendingIdentity = await writePrivateFile(
      state.pendingEventPath,
      eventBytes,
      stagingOpened.identity.dev,
    );
    state.pendingPresent = true;
    await checkpoint?.("record-written");
    await syncPrivateFile(state.pendingEventPath, state.pendingIdentity);
    await state.stagingHandle.sync();
    await checkpoint?.("record-synced");
    await verifyPendingEvent(state, eventBytes);
    await checkpoint?.("record-verified");
    await state.rootHandle.sync();
    await checkpoint?.("root-synced-before-publish");

    await checkpoint?.("before-publish");
    const refreshed = await readFormalRunWithRetry(state.runDirectory);
    validateExpectedHead(refreshed, input);
    validateCandidate(refreshed, input.event, eventBytes.byteLength);
    await assertOpenLayoutStable(state, manifestBytes);
    await verifyPendingEvent(state, eventBytes);
    await checkpoint?.("link-ready");

    try {
      await link(state.pendingEventPath, state.finalEventPath);
      state.linked = true;
    } catch (error) {
      if (isErrorCode(error, "EEXIST")) {
        if (await hasValidCompetingRecord(state.runDirectory, input.expectedNextSequence)) {
          throw INTERNAL_CONFLICT;
        }
        throw new Error();
      }
      throw error;
    }

    await checkpoint?.("record-published");
    await verifyPublishedEvent(state, eventBytes);
    await syncPrivateFile(state.finalEventPath, state.pendingIdentity!);
    await checkpoint?.("record-synced-after-publish");
    await state.ledgerHandle.sync();
    await checkpoint?.("ledger-synced");
    await state.runHandle.sync();
    await checkpoint?.("run-synced");
    await state.rootHandle.sync();
    await checkpoint?.("root-synced-after-publish");
    await assertOpenLayoutStable(state, manifestBytes, false);
    await confirmFormalLedger(
      state.runDirectory,
      input.expectedNextSequence,
      eventBytes,
    );
    await verifyPublishedEvent(state, eventBytes);
    await checkpoint?.("record-verified-after-publish");
    const result = Object.freeze({ event: input.event });
    await cleanupOwnedStaging(state, checkpoint, true);
    return result;
  } catch (error) {
    await cleanupOwnedStaging(state, checkpoint, false);
    if (error === INTERNAL_INVALID_EVENT) {
      throw appendError("suite_slot_event_invalid");
    }
    if (error === INTERNAL_CONFLICT) {
      throw appendError("suite_slot_event_conflict");
    }
    if (state.linked) {
      throw appendError("suite_slot_event_publication_uncertain");
    }
    throw appendError("suite_slot_event_write_failed");
  } finally {
    await closeHandles(state);
  }
}

function createAppendState(runDirectory: string, sequence: number): AppendState {
  const rootDirectory = path.dirname(runDirectory);
  const ledgerDirectory = path.join(runDirectory, SUITE_SLOT_LEDGER_DIRECTORY_NAME);
  const stagingDirectory = path.join(rootDirectory, `${STAGING_PREFIX}${randomUUID()}`);
  return {
    rootDirectory,
    runDirectory,
    manifestPath: path.join(runDirectory, MANIFEST_NAME),
    ledgerDirectory,
    stagingDirectory,
    pendingEventPath: path.join(stagingDirectory, PENDING_EVENT_NAME),
    finalEventPath: path.join(ledgerDirectory, slotEventFileName(sequence)),
    rootHandle: undefined,
    runHandle: undefined,
    ledgerHandle: undefined,
    stagingHandle: undefined,
    rootIdentity: undefined,
    runIdentity: undefined,
    ledgerIdentity: undefined,
    stagingIdentity: undefined,
    manifestIdentity: undefined,
    pendingIdentity: undefined,
    stagingPresent: false,
    pendingPresent: false,
    linked: false,
  };
}

function snapshotAppendInput(value: SuiteSlotEventAppendInput): SuiteSlotEventAppendInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const expectedKeys = ["expectedNextSequence", "expectedPreviousEventId", "event"];
  if (keys.length !== expectedKeys.length || keys.some((key) => !expectedKeys.includes(String(key)))) {
    throw new Error();
  }
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error();
    }
  }
  const expectedNextSequence = descriptors.expectedNextSequence!.value as unknown;
  const expectedPreviousEventId = descriptors.expectedPreviousEventId!.value as unknown;
  const event = descriptors.event!.value as unknown;
  if (
    !Number.isSafeInteger(expectedNextSequence) ||
    Object.is(expectedNextSequence, -0) ||
    (expectedNextSequence as number) < 0 ||
    (expectedNextSequence as number) >= MAX_SUITE_SLOT_EVENTS ||
    !(
      expectedPreviousEventId === null ||
      (typeof expectedPreviousEventId === "string" && DIGEST_PATTERN.test(expectedPreviousEventId))
    )
  ) {
    throw new Error();
  }
  return Object.freeze({
    expectedNextSequence: expectedNextSequence as number,
    expectedPreviousEventId,
    event: event as SuiteSlotEvent,
  });
}

function snapshotCheckpoint(
  hooks: SuiteSlotEventAppendHooks,
): SuiteSlotEventAppendHooks["checkpoint"] {
  if (typeof hooks !== "object" || hooks === null || Array.isArray(hooks)) throw new Error();
  const prototype = Object.getPrototypeOf(hooks);
  if (prototype !== Object.prototype && prototype !== null) throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(hooks);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => key !== "checkpoint")) throw new Error();
  const descriptor = descriptors.checkpoint;
  if (descriptor === undefined) return undefined;
  if (
    !("value" in descriptor) ||
    !descriptor.enumerable ||
    (descriptor.value !== undefined && typeof descriptor.value !== "function")
  ) {
    throw new Error();
  }
  return descriptor.value as SuiteSlotEventAppendHooks["checkpoint"];
}

function validateExpectedHead(
  current: SuiteRunDirectoryResult,
  input: SuiteSlotEventAppendInput,
): void {
  if (
    current.slotState.events.length !== input.expectedNextSequence ||
    current.slotState.lastEventId !== input.expectedPreviousEventId
  ) {
    throw INTERNAL_CONFLICT;
  }
}

function validateCandidate(
  current: SuiteRunDirectoryResult,
  event: SuiteSlotEvent,
  eventByteLength: number,
): void {
  try {
    let storedBytes = 0;
    for (const stored of current.slotState.events) {
      const length = encodeSuiteSlotEvent(stored).byteLength;
      if (length > MAX_SUITE_SLOT_LEDGER_BYTES - storedBytes) throw new Error();
      storedBytes += length;
    }
    if (eventByteLength > MAX_SUITE_SLOT_LEDGER_BYTES - storedBytes) throw new Error();
    reduceSuiteSlotEvents(current.manifest, [...current.slotState.events, event]);
  } catch {
    throw INTERNAL_INVALID_EVENT;
  }
}

async function hasValidCompetingRecord(
  runDirectory: string,
  sequence: number,
): Promise<boolean> {
  try {
    const current = await readFormalRunWithRetry(runDirectory);
    return current.slotState.events[sequence] !== undefined;
  } catch {
    return false;
  }
}

async function confirmFormalLedger(
  runDirectory: string,
  sequence: number,
  expectedBytes: Buffer,
): Promise<void> {
  for (let attempt = 0; attempt < FORMAL_LEDGER_CONFIRMATION_ATTEMPTS; attempt += 1) {
    try {
      const current = await readFormalRunWithRetry(runDirectory, 1);
      const stored = current.slotState.events[sequence];
      if (stored === undefined || !encodeSuiteSlotEvent(stored).equals(expectedBytes)) {
        throw new Error();
      }
      return;
    } catch {
      if (attempt === FORMAL_LEDGER_CONFIRMATION_ATTEMPTS - 1) throw new Error();
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
}

async function readFormalRunWithRetry(
  runDirectory: string,
  attempts = FORMAL_LEDGER_CONFIRMATION_ATTEMPTS,
): Promise<SuiteRunDirectoryResult> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await readSuiteRunDirectory(runDirectory);
    } catch {
      if (attempt === attempts - 1) throw new Error();
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
  throw new Error();
}

async function assertOpenLayoutStable(
  state: AppendState,
  manifestBytes: Buffer,
  verifyPending = true,
): Promise<void> {
  if (
    state.rootHandle === undefined ||
    state.runHandle === undefined ||
    state.ledgerHandle === undefined ||
    state.rootIdentity === undefined ||
    state.runIdentity === undefined ||
    state.ledgerIdentity === undefined ||
    state.manifestIdentity === undefined
  ) {
    throw new Error();
  }
  await assertDirectoryStable(state.rootDirectory, state.rootHandle, state.rootIdentity);
  await assertDirectoryStable(state.runDirectory, state.runHandle, state.runIdentity);
  await assertDirectoryStable(state.ledgerDirectory, state.ledgerHandle, state.ledgerIdentity);
  await assertExactEntries(
    state.runDirectory,
    [MANIFEST_NAME],
    [SUITE_SLOT_LEDGER_DIRECTORY_NAME],
  );
  const manifest = await readPrivateFile(
    state.manifestPath,
    MAX_SUITE_RUN_MANIFEST_BYTES,
    state.manifestIdentity,
    state.runIdentity.dev,
  );
  if (!manifest.bytes.equals(manifestBytes)) throw new Error();
  if (verifyPending && state.pendingPresent) await verifyPendingEvent(state, undefined);
}

async function assertStagingEmpty(state: AppendState): Promise<void> {
  if (
    state.stagingHandle === undefined ||
    state.stagingIdentity === undefined ||
    state.rootIdentity === undefined
  ) {
    throw new Error();
  }
  await assertDirectoryStable(
    state.stagingDirectory,
    state.stagingHandle,
    state.stagingIdentity,
  );
  if (state.stagingIdentity.dev !== state.rootIdentity.dev) throw new Error();
  await assertExactEntries(state.stagingDirectory, [], []);
}

async function verifyPendingEvent(state: AppendState, expectedBytes: Buffer | undefined): Promise<void> {
  if (
    state.pendingIdentity === undefined ||
    state.stagingIdentity === undefined ||
    state.stagingHandle === undefined
  ) {
    throw new Error();
  }
  await assertDirectoryStable(
    state.stagingDirectory,
    state.stagingHandle,
    state.stagingIdentity,
  );
  await assertExactEntries(state.stagingDirectory, [PENDING_EVENT_NAME], []);
  const pending = await readPrivateFile(
    state.pendingEventPath,
    MAX_SUITE_SLOT_EVENT_BYTES,
    state.pendingIdentity,
    state.stagingIdentity.dev,
  );
  const canonical = encodeSuiteSlotEvent(readSuiteSlotEvent(pending.bytes));
  if (!pending.bytes.equals(canonical) || (expectedBytes !== undefined && !pending.bytes.equals(expectedBytes))) {
    throw new Error();
  }
}

async function verifyPublishedEvent(state: AppendState, expectedBytes: Buffer): Promise<void> {
  if (state.pendingIdentity === undefined || state.ledgerIdentity === undefined) throw new Error();
  const published = await readPrivateFile(
    state.finalEventPath,
    MAX_SUITE_SLOT_EVENT_BYTES,
    state.pendingIdentity,
    state.ledgerIdentity.dev,
  );
  if (!published.bytes.equals(expectedBytes)) throw new Error();
}

async function cleanupOwnedStaging(
  state: AppendState,
  checkpoint: SuiteSlotEventAppendHooks["checkpoint"],
  confirmed: boolean,
): Promise<void> {
  try {
    if (
      state.rootIdentity === undefined ||
      !(await directoryMatches(state.rootDirectory, state.rootIdentity))
    ) {
      return;
    }
    if (
      state.stagingPresent &&
      (state.stagingIdentity === undefined ||
        !(await directoryMatches(state.stagingDirectory, state.stagingIdentity)))
    ) {
      return;
    }
    if (state.pendingPresent && state.pendingIdentity !== undefined) {
      if (await unlinkOwnedFile(state.pendingEventPath, state.pendingIdentity)) {
        state.pendingPresent = false;
        if (confirmed) await safeCheckpoint(checkpoint, "staging-file-removed");
      }
    }
    await state.stagingHandle?.sync().catch(() => undefined);
    await state.stagingHandle?.close().catch(() => undefined);
    state.stagingHandle = undefined;
    if (
      state.stagingPresent &&
      state.stagingIdentity !== undefined &&
      (await removeOwnedEmptyDirectory(state.stagingDirectory, state.stagingIdentity))
    ) {
      state.stagingPresent = false;
      if (confirmed) await safeCheckpoint(checkpoint, "staging-directory-removed");
    }
    if (
      state.rootHandle !== undefined &&
      (await directoryMatches(state.rootDirectory, state.rootIdentity))
    ) {
      await state.rootHandle.sync();
      if (confirmed) await safeCheckpoint(checkpoint, "cleanup-root-synced");
    }
  } catch {
    // Cleanup never removes the published record and never touches an unowned staging entry.
  }
}

async function safeCheckpoint(
  checkpoint: SuiteSlotEventAppendHooks["checkpoint"],
  point: SuiteSlotEventAppendCheckpoint,
): Promise<void> {
  try {
    await checkpoint?.(point);
  } catch {
    // The append is already confirmed durable; cleanup hooks cannot reverse success.
  }
}

function requireSupportedFilesystem(): void {
  if (
    process.platform === "win32" ||
    NOFOLLOW === 0 ||
    DIRECTORY === 0 ||
    typeof process.geteuid !== "function"
  ) {
    throw new Error();
  }
}

async function openPrivateDirectory(
  directory: string,
  expectedDevice?: number,
): Promise<{ handle: DirectoryHandle; identity: FileIdentity }> {
  const before = await lstat(directory);
  if (!isPrivateDirectory(before) || (expectedDevice !== undefined && before.dev !== expectedDevice)) {
    throw new Error();
  }
  const handle = await open(directory, DIRECTORY_NOFOLLOW);
  try {
    const info = await handle.stat();
    const after = await lstat(directory);
    if (
      !isPrivateDirectory(info) ||
      !isPrivateDirectory(after) ||
      !sameFile(info, before) ||
      !sameFile(info, after) ||
      (expectedDevice !== undefined && info.dev !== expectedDevice)
    ) {
      throw new Error();
    }
    return { handle, identity: toIdentity(info) };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function writePrivateFile(
  file: string,
  bytes: Uint8Array,
  expectedDevice: number,
): Promise<FileIdentity> {
  const handle = await open(file, WRITE_EXCLUSIVE_NOFOLLOW, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    const info = await handle.stat();
    const pathInfo = await lstat(file);
    if (
      !isPrivateFile(info) ||
      !isPrivateFile(pathInfo) ||
      info.dev !== expectedDevice ||
      !sameFile(info, pathInfo)
    ) {
      throw new Error();
    }
    return toIdentity(info);
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function syncPrivateFile(file: string, identity: FileIdentity): Promise<void> {
  const handle = await open(file, constants.O_RDWR | NOFOLLOW | NONBLOCK);
  try {
    const info = await handle.stat();
    const pathInfo = await lstat(file);
    if (
      !isPrivateFile(info) ||
      !isPrivateFile(pathInfo) ||
      !sameFile(info, identity) ||
      !sameFile(info, pathInfo)
    ) {
      throw new Error();
    }
    await handle.sync();
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function readPrivateFile(
  file: string,
  maxBytes: number,
  expectedIdentity: FileIdentity | undefined,
  expectedDevice: number,
): Promise<{ bytes: Buffer; identity: FileIdentity }> {
  const handle = await open(file, READ_ONLY_NOFOLLOW);
  try {
    const info = await handle.stat();
    const before = await lstat(file);
    if (
      !isPrivateFile(info) ||
      !isPrivateFile(before) ||
      !sameFile(info, before) ||
      info.dev !== expectedDevice ||
      (expectedIdentity !== undefined && !sameFile(info, expectedIdentity))
    ) {
      throw new Error();
    }
    const bytes = await readBounded(handle, maxBytes);
    const finalInfo = await handle.stat();
    const after = await lstat(file);
    if (
      !isPrivateFile(finalInfo) ||
      !isPrivateFile(after) ||
      !sameFile(info, finalInfo) ||
      !sameFile(info, after)
    ) {
      throw new Error();
    }
    return { bytes, identity: toIdentity(info) };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function readBounded(handle: DirectoryHandle, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const remaining = maxBytes + 1 - total;
    if (remaining <= 0) throw new Error();
    const chunk = Buffer.alloc(Math.min(64 * 1024, remaining));
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    total += bytesRead;
    if (total > maxBytes) throw new Error();
  }
  return Buffer.concat(chunks, total);
}

async function assertDirectoryStable(
  directory: string,
  handle: DirectoryHandle,
  identity: FileIdentity,
): Promise<void> {
  const info = await handle.stat();
  const pathInfo = await lstat(directory);
  if (
    !isPrivateDirectory(info) ||
    !isPrivateDirectory(pathInfo) ||
    !sameFile(info, identity) ||
    !sameFile(info, pathInfo)
  ) {
    throw new Error();
  }
}

async function assertExactEntries(
  directory: string,
  expectedFiles: readonly string[],
  expectedDirectories: readonly string[],
): Promise<void> {
  const expected = new Map<string, "file" | "directory">();
  for (const name of expectedFiles) expected.set(name, "file");
  for (const name of expectedDirectories) expected.set(name, "directory");
  const seen = new Set<string>();
  const stream = await opendir(directory);
  try {
    for await (const entry of stream) {
      if (seen.size >= expected.size || seen.has(entry.name)) throw new Error();
      const kind = expected.get(entry.name);
      if (
        kind === undefined ||
        (kind === "file" && !entry.isFile()) ||
        (kind === "directory" && !entry.isDirectory())
      ) {
        throw new Error();
      }
      seen.add(entry.name);
    }
  } finally {
    await stream.close().catch(() => undefined);
  }
  if (seen.size !== expected.size) throw new Error();
}

async function unlinkOwnedFile(file: string, identity: FileIdentity): Promise<boolean> {
  try {
    const info = await lstat(file);
    if (!isPrivateFile(info) || !sameFile(info, identity)) return false;
    await unlink(file);
    return true;
  } catch (error) {
    return isErrorCode(error, "ENOENT");
  }
}

async function removeOwnedEmptyDirectory(
  directory: string,
  identity: FileIdentity,
): Promise<boolean> {
  try {
    if (!(await directoryMatches(directory, identity))) return false;
    if (!(await isDirectoryEmpty(directory))) return false;
    if (!(await directoryMatches(directory, identity))) return false;
    await rmdir(directory);
    return true;
  } catch (error) {
    return isErrorCode(error, "ENOENT");
  }
}

async function isDirectoryEmpty(directory: string): Promise<boolean> {
  const stream = await opendir(directory);
  try {
    for await (const _entry of stream) return false;
    return true;
  } finally {
    await stream.close().catch(() => undefined);
  }
}

async function directoryMatches(directory: string, identity: FileIdentity): Promise<boolean> {
  try {
    const info = await lstat(directory);
    return isPrivateDirectory(info) && sameFile(info, identity);
  } catch {
    return false;
  }
}

async function closeHandles(state: AppendState): Promise<void> {
  await state.stagingHandle?.close().catch(() => undefined);
  await state.ledgerHandle?.close().catch(() => undefined);
  await state.runHandle?.close().catch(() => undefined);
  await state.rootHandle?.close().catch(() => undefined);
  state.stagingHandle = undefined;
  state.ledgerHandle = undefined;
  state.runHandle = undefined;
  state.rootHandle = undefined;
}

function slotEventFileName(sequence: number): string {
  return `${sequence.toString(10).padStart(SUITE_SLOT_EVENT_FILENAME_WIDTH, "0")}.json`;
}

function isPrivateDirectory(info: Awaited<ReturnType<typeof lstat>>): boolean {
  return info.isDirectory() && !info.isSymbolicLink() && exactMode(info.mode, 0o700) && ownedByProcess(info.uid);
}

function isPrivateFile(info: Awaited<ReturnType<typeof lstat>>): boolean {
  return info.isFile() && !info.isSymbolicLink() && exactMode(info.mode, 0o600) && ownedByProcess(info.uid);
}

function exactMode(mode: number | bigint, expected: number): boolean {
  return typeof mode === "bigint"
    ? (mode & 0o7777n) === BigInt(expected)
    : (mode & 0o7777) === expected;
}

function ownedByProcess(uid: number | bigint): boolean {
  return typeof process.geteuid === "function" &&
    (uid === BigInt(process.geteuid()) || uid === process.geteuid());
}

function resolveDirectoryArgument(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error();
  return path.resolve(value);
}

function sameFile(
  first: Pick<FileIdentity, "dev" | "ino" | "uid">,
  second: Pick<FileIdentity, "dev" | "ino" | "uid">,
): boolean {
  return first.dev === second.dev && first.ino === second.ino && first.uid === second.uid;
}

function toIdentity(info: Pick<FileIdentity, "dev" | "ino" | "uid">): FileIdentity {
  if (![info.dev, info.ino, info.uid].every(Number.isSafeInteger)) throw new Error();
  return Object.freeze({ dev: info.dev, ino: info.ino, uid: info.uid });
}

function isErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

function appendError(code: SuiteSlotLedgerErrorCode): SuiteSlotLedgerError {
  switch (code) {
    case "suite_slot_event_invalid":
      return new SuiteSlotLedgerError(code, "the suite slot event append request is invalid");
    case "suite_slot_event_conflict":
      return new SuiteSlotLedgerError(code, "the suite slot ledger changed before the event was appended");
    case "suite_slot_event_publication_uncertain":
      return new SuiteSlotLedgerError(code, "the suite slot event publication outcome is uncertain");
    case "suite_slot_event_write_failed":
      return new SuiteSlotLedgerError(code, "the suite slot event could not be appended");
  }
}
