import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";

import {
  MAX_SUITE_RUN_MANIFEST_BYTES,
  encodeSuiteRunManifest,
  readSuiteRunManifest,
  type SuiteRunManifest,
} from "./run-manifest.js";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const OWNER_MARKER_NAME = ".suite-run-owner.pending";
const MANIFEST_NAME = "suite-run.json";
const PENDING_MANIFEST_NAME = "suite-run.json.pending";
const STAGING_PREFIX = ".suite-run-claim-";
const OWNER_MARKER_MAX_BYTES = 128;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;
const DIRECTORY = constants.O_DIRECTORY ?? 0;
const DIRECTORY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK | DIRECTORY;
const READ_ONLY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK;
const WRITE_EXCLUSIVE_NOFOLLOW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW;

export type SuiteRunDirectoryErrorCode =
  | "suite_run_exists"
  | "suite_run_write_failed"
  | "suite_run_publication_uncertain"
  | "suite_run_directory_invalid";

export class SuiteRunDirectoryError extends Error {
  readonly code: SuiteRunDirectoryErrorCode;

  constructor(code: SuiteRunDirectoryErrorCode, message: string) {
    super(message);
    this.name = "SuiteRunDirectoryError";
    this.code = code;
  }
}

class InternalPublicationError extends Error {
  readonly code: "suite_run_exists";

  constructor(code: "suite_run_exists") {
    super(code);
    this.code = code;
  }
}

export type SuiteRunPublicationCheckpoint =
  | "directory-claimed"
  | "owner-marker-written"
  | "staging-created"
  | "manifest-written"
  | "manifest-synced"
  | "manifest-verified"
  | "owner-marker-removed"
  | "before-publish"
  | "manifest-published"
  | "run-directory-synced"
  | "root-directory-synced"
  | "staging-file-removed"
  | "staging-directory-removed";

export type SuiteRunPublicationHooks = Readonly<{
  checkpoint?: (point: SuiteRunPublicationCheckpoint) => void | Promise<void>;
}>;

export type SuiteRunDirectoryResult = Readonly<{
  runDirectory: string;
  manifestPath: string;
  manifest: SuiteRunManifest;
}>;

type FileIdentity = Readonly<{
  dev: number;
  ino: number;
  uid: number;
}>;

type PublicationState = {
  readonly rootDirectory: string;
  readonly runDirectory: string;
  readonly stagingDirectory: string;
  readonly ownerMarkerPath: string;
  readonly pendingManifestPath: string;
  readonly finalManifestPath: string;
  readonly ownerMarkerBytes: Buffer;
  rootHandle: Awaited<ReturnType<typeof open>> | undefined;
  runHandle: Awaited<ReturnType<typeof open>> | undefined;
  stagingHandle: Awaited<ReturnType<typeof open>> | undefined;
  rootIdentity: FileIdentity | undefined;
  runIdentity: FileIdentity | undefined;
  stagingIdentity: FileIdentity | undefined;
  markerIdentity: FileIdentity | undefined;
  pendingIdentity: FileIdentity | undefined;
  markerPresent: boolean;
  markerRemoved: boolean;
  pendingPresent: boolean;
  stagingPresent: boolean;
  runPresent: boolean;
  linked: boolean;
  publicationComplete: boolean;
};

/** Publishes one canonical manifest under `<root>/<suiteRunId>/suite-run.json`. */
export async function publishSuiteRunDirectory(
  rootDirectory: string,
  manifestInput: SuiteRunManifest,
  hooks: SuiteRunPublicationHooks = {},
): Promise<SuiteRunDirectoryResult> {
  let root: string;
  let checkpoint: SuiteRunPublicationHooks["checkpoint"];
  let manifestBytes: Buffer;
  let manifest: SuiteRunManifest;
  let state: PublicationState;
  try {
    root = resolveDirectoryArgument(rootDirectory);
    checkpoint = snapshotCheckpoint(hooks);
    manifestBytes = encodeSuiteRunManifest(manifestInput);
    manifest = readSuiteRunManifest(manifestBytes);
    state = createPublicationState(root, manifest.suiteRunId);
  } catch {
    throw publicationInputError();
  }
  try {
    requireSupportedFilesystem();
    const rootOpened = await openPrivateDirectory(root);
    state.rootHandle = rootOpened.handle;
    state.rootIdentity = rootOpened.identity;
    try {
      await mkdir(state.runDirectory, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (isErrorCode(error, "EEXIST")) {
        throw new InternalPublicationError("suite_run_exists");
      }
      throw error;
    }
    state.runPresent = true;
    const runOpened = await openPrivateDirectory(state.runDirectory, state.rootIdentity.dev);
    state.runHandle = runOpened.handle;
    state.runIdentity = runOpened.identity;
    await state.rootHandle.sync();
    await checkpoint?.("directory-claimed");

    state.markerIdentity = await writePrivateFile(
      state.ownerMarkerPath,
      state.ownerMarkerBytes,
      state.runIdentity.dev,
    );
    state.markerPresent = true;
    await state.runHandle.sync();
    await checkpoint?.("owner-marker-written");

    await assertRootAndRunStable(state);
    await mkdir(state.stagingDirectory, { recursive: false, mode: 0o700 });
    state.stagingPresent = true;
    const stagingOpened = await openPrivateDirectory(
      state.stagingDirectory,
      state.rootIdentity.dev,
    );
    state.stagingHandle = stagingOpened.handle;
    state.stagingIdentity = stagingOpened.identity;
    await checkpoint?.("staging-created");
    await assertStagingReadyForWrite(state);

    state.pendingIdentity = await writePrivateFile(
      state.pendingManifestPath,
      manifestBytes,
      state.stagingIdentity.dev,
      false,
    );
    state.pendingPresent = true;
    await checkpoint?.("manifest-written");
    await syncPrivateFile(state.pendingManifestPath, state.pendingIdentity);
    await state.stagingHandle.sync();
    await checkpoint?.("manifest-synced");

    const pendingRead = await readPrivateFile(
      state.pendingManifestPath,
      MAX_SUITE_RUN_MANIFEST_BYTES,
      state.pendingIdentity,
      state.stagingIdentity.dev,
    );
    if (!pendingRead.bytes.equals(manifestBytes)) throw new Error();
    readSuiteRunManifest(pendingRead.bytes, { expectedSuiteRunId: manifest.suiteRunId });
    await checkpoint?.("manifest-verified");

    await assertPublicationInputsStable(state);
    if (!(await unlinkOwnedFile(state.ownerMarkerPath, state.markerIdentity))) throw new Error();
    state.markerPresent = false;
    state.markerRemoved = true;
    await checkpoint?.("owner-marker-removed");
    await assertPublicationInputsStable(state);
    await assertExactEntries(state.runDirectory, []);
    await checkpoint?.("before-publish");
    await assertPublicationInputsStable(state);
    await assertExactEntries(state.runDirectory, []);
    await verifyManifestFile(
      state.pendingManifestPath,
      state.pendingIdentity,
      state.stagingIdentity.dev,
      manifestBytes,
      manifest.suiteRunId,
    );

    try {
      await link(state.pendingManifestPath, state.finalManifestPath);
    } catch (error) {
      if (isErrorCode(error, "EEXIST")) {
        throw new InternalPublicationError("suite_run_exists");
      }
      throw error;
    }
    state.linked = true;
    await postPublishCheckpoint(checkpoint, "manifest-published");
    await verifyPublishedLink(state, manifestBytes, manifest.suiteRunId);
    await state.runHandle.sync();
    await postPublishCheckpoint(checkpoint, "run-directory-synced");
    await assertRootAndRunStable(state);
    await verifyPublishedLink(state, manifestBytes, manifest.suiteRunId);
    await state.rootHandle.sync();
    await postPublishCheckpoint(checkpoint, "root-directory-synced");
    await syncPrivateFile(state.finalManifestPath, state.pendingIdentity);
    await state.runHandle.sync();
    await state.rootHandle.sync();
    await assertRootAndRunStable(state);
    await verifyPublishedLink(state, manifestBytes, manifest.suiteRunId);

    await cleanupStagingAfterPublication(state, checkpoint);
    await syncPrivateFile(state.finalManifestPath, state.pendingIdentity);
    await state.runHandle.sync();
    await state.rootHandle.sync();
    await assertRootAndRunStable(state);
    await verifyPublishedLink(state, manifestBytes, manifest.suiteRunId);
    state.publicationComplete = true;
    return freezeResult(state, manifest);
  } catch (error) {
    if (state.publicationComplete) {
      await cleanupStagingAfterPublication(state, checkpoint);
      return freezeResult(state, manifest);
    }
    if (state.linked) {
      throw new SuiteRunDirectoryError(
        "suite_run_publication_uncertain",
        "the suite run publication outcome is uncertain",
      );
    }
    await cleanupUnpublished(state);
    if (isInternalPublicationError(error)) {
      throw new SuiteRunDirectoryError(
        "suite_run_exists",
        "the suite run identity is already claimed",
      );
    }
    throw new SuiteRunDirectoryError(
      "suite_run_write_failed",
      "the suite run directory could not be published",
    );
  } finally {
    await closeHandles(state);
  }
}

function createPublicationState(root: string, suiteRunId: string): PublicationState {
  const nonce = randomUUID();
  const runDirectory = path.join(root, suiteRunId);
  const stagingDirectory = path.join(root, `${STAGING_PREFIX}${nonce}`);
  return {
    rootDirectory: root,
    runDirectory,
    stagingDirectory,
    ownerMarkerPath: path.join(runDirectory, OWNER_MARKER_NAME),
    pendingManifestPath: path.join(stagingDirectory, PENDING_MANIFEST_NAME),
    finalManifestPath: path.join(runDirectory, MANIFEST_NAME),
    ownerMarkerBytes: Buffer.from(`${nonce}\n`, "utf8"),
    rootHandle: undefined,
    runHandle: undefined,
    stagingHandle: undefined,
    rootIdentity: undefined,
    runIdentity: undefined,
    stagingIdentity: undefined,
    markerIdentity: undefined,
    pendingIdentity: undefined,
    markerPresent: false,
    markerRemoved: false,
    pendingPresent: false,
    stagingPresent: false,
    runPresent: false,
    linked: false,
    publicationComplete: false,
  };
}

/** Reopens one complete suite-run directory and revalidates its immutable identity. */
export async function readSuiteRunDirectory(
  runDirectory: string,
): Promise<SuiteRunDirectoryResult> {
  let directoryHandle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const absoluteDirectory = resolveDirectoryArgument(runDirectory);
    const expectedSuiteRunId = path.basename(absoluteDirectory);
    requireSupportedFilesystem();
    if (!DIGEST_PATTERN.test(expectedSuiteRunId)) throw new Error();
    const opened = await openPrivateDirectory(absoluteDirectory);
    directoryHandle = opened.handle;
    await assertExactEntries(absoluteDirectory, [MANIFEST_NAME]);
    const manifestPath = path.join(absoluteDirectory, MANIFEST_NAME);
    const manifestRead = await readPrivateFile(
      manifestPath,
      MAX_SUITE_RUN_MANIFEST_BYTES,
      undefined,
      opened.identity.dev,
    );
    const manifestBytes = manifestRead.bytes;
    const manifest = readSuiteRunManifest(manifestBytes, { expectedSuiteRunId });
    if (!manifestBytes.equals(encodeSuiteRunManifest(manifest))) throw new Error();
    await assertDirectoryStable(absoluteDirectory, directoryHandle, opened.identity);
    await assertExactEntries(absoluteDirectory, [MANIFEST_NAME]);
    await assertPrivateFileStable(manifestPath, manifestRead.identity);
    return Object.freeze({
      runDirectory: absoluteDirectory,
      manifestPath,
      manifest,
    });
  } catch {
    throw new SuiteRunDirectoryError(
      "suite_run_directory_invalid",
      "the suite run directory is invalid",
    );
  } finally {
    await directoryHandle?.close().catch(() => undefined);
  }
}

function freezeResult(
  state: PublicationState,
  manifest: SuiteRunManifest,
): SuiteRunDirectoryResult {
  return Object.freeze({
    runDirectory: state.runDirectory,
    manifestPath: state.finalManifestPath,
    manifest,
  });
}

async function postPublishCheckpoint(
  checkpoint: SuiteRunPublicationHooks["checkpoint"],
  point: SuiteRunPublicationCheckpoint,
): Promise<void> {
  try {
    await checkpoint?.(point);
  } catch {
    // The hard link is the commit point. Hook or cleanup failure cannot roll it back.
  }
}

function requireSupportedFilesystem(): void {
  if (process.platform === "win32" || NOFOLLOW === 0 || DIRECTORY === 0) throw new Error();
}

async function openPrivateDirectory(
  directory: string,
  expectedDevice?: number,
): Promise<{ handle: Awaited<ReturnType<typeof open>>; identity: FileIdentity }> {
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
  sync = true,
): Promise<FileIdentity> {
  const handle = await open(file, WRITE_EXCLUSIVE_NOFOLLOW, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    if (sync) await handle.sync();
    const info = await handle.stat();
    if (!isPrivateFile(info) || info.dev !== expectedDevice) throw new Error();
    const pathInfo = await lstat(file);
    if (!isPrivateFile(pathInfo) || !sameFile(info, pathInfo)) throw new Error();
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

async function readBounded(
  handle: Awaited<ReturnType<typeof open>>,
  maxBytes: number,
): Promise<Buffer> {
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

async function assertPublicationInputsStable(state: PublicationState): Promise<void> {
  await assertRootAndRunStable(state);
  if (
    state.stagingHandle === undefined ||
    state.stagingIdentity === undefined ||
    state.pendingIdentity === undefined
  ) {
    throw new Error();
  }
  await assertDirectoryStable(state.stagingDirectory, state.stagingHandle, state.stagingIdentity);
  await assertPrivateFileStable(state.pendingManifestPath, state.pendingIdentity);
  await assertExactEntries(state.stagingDirectory, [PENDING_MANIFEST_NAME]);
  if (state.markerPresent) {
    if (state.markerIdentity === undefined) throw new Error();
    await assertPrivateFileStable(state.ownerMarkerPath, state.markerIdentity);
    const marker = await readPrivateFile(
      state.ownerMarkerPath,
      OWNER_MARKER_MAX_BYTES,
      state.markerIdentity,
      state.runIdentity!.dev,
    );
    if (!marker.bytes.equals(state.ownerMarkerBytes)) throw new Error();
    await assertExactEntries(state.runDirectory, [OWNER_MARKER_NAME]);
  }
}

async function assertStagingReadyForWrite(state: PublicationState): Promise<void> {
  await assertRootAndRunStable(state);
  if (state.stagingHandle === undefined || state.stagingIdentity === undefined) throw new Error();
  await assertDirectoryStable(state.stagingDirectory, state.stagingHandle, state.stagingIdentity);
  await assertExactEntries(state.stagingDirectory, []);
  if (state.markerIdentity === undefined || state.runIdentity === undefined) throw new Error();
  const marker = await readPrivateFile(
    state.ownerMarkerPath,
    OWNER_MARKER_MAX_BYTES,
    state.markerIdentity,
    state.runIdentity.dev,
  );
  if (!marker.bytes.equals(state.ownerMarkerBytes)) throw new Error();
  await assertExactEntries(state.runDirectory, [OWNER_MARKER_NAME]);
}

async function assertRootAndRunStable(state: PublicationState): Promise<void> {
  if (
    state.rootHandle === undefined ||
    state.rootIdentity === undefined ||
    state.runHandle === undefined ||
    state.runIdentity === undefined
  ) {
    throw new Error();
  }
  await assertDirectoryStable(state.rootDirectory, state.rootHandle, state.rootIdentity);
  await assertDirectoryStable(state.runDirectory, state.runHandle, state.runIdentity);
}

async function assertDirectoryStable(
  directory: string,
  handle: Awaited<ReturnType<typeof open>>,
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

async function assertPrivateFileStable(file: string, identity: FileIdentity): Promise<void> {
  const info = await lstat(file);
  if (!isPrivateFile(info) || !sameFile(info, identity)) throw new Error();
}

async function verifyPublishedLink(
  state: PublicationState,
  expectedBytes: Buffer,
  expectedSuiteRunId: string,
): Promise<void> {
  if (state.pendingIdentity === undefined || state.runIdentity === undefined) throw new Error();
  const finalInfo = await lstat(state.finalManifestPath);
  if (
    !isPrivateFile(finalInfo) ||
    !sameFile(finalInfo, state.pendingIdentity) ||
    finalInfo.dev !== state.runIdentity.dev
  ) {
    throw new Error();
  }
  await assertExactEntries(state.runDirectory, [MANIFEST_NAME]);
  await verifyManifestFile(
    state.finalManifestPath,
    state.pendingIdentity,
    state.runIdentity.dev,
    expectedBytes,
    expectedSuiteRunId,
  );
}

async function verifyManifestFile(
  file: string,
  identity: FileIdentity,
  expectedDevice: number,
  expectedBytes: Buffer,
  expectedSuiteRunId: string,
): Promise<void> {
  const result = await readPrivateFile(
    file,
    MAX_SUITE_RUN_MANIFEST_BYTES,
    identity,
    expectedDevice,
  );
  if (!result.bytes.equals(expectedBytes)) throw new Error();
  readSuiteRunManifest(result.bytes, { expectedSuiteRunId });
  await assertPrivateFileStable(file, result.identity);
}

async function assertExactEntries(directory: string, expected: readonly string[]): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.some((entry) => !entry.isFile())) throw new Error();
  const names = entries.map((entry) => entry.name).sort();
  const expectedNames = [...expected].sort();
  if (names.length !== expectedNames.length || names.some((name, index) => name !== expectedNames[index])) {
    throw new Error();
  }
}

async function cleanupStagingAfterPublication(
  state: PublicationState,
  checkpoint: SuiteRunPublicationHooks["checkpoint"],
): Promise<void> {
  try {
    if (state.pendingPresent && state.pendingIdentity !== undefined) {
      if (await unlinkOwnedFile(state.pendingManifestPath, state.pendingIdentity)) {
        state.pendingPresent = false;
        await postPublishCheckpoint(checkpoint, "staging-file-removed");
      }
    }
    await state.stagingHandle?.close().catch(() => undefined);
    state.stagingHandle = undefined;
    if (
      state.stagingPresent &&
      state.stagingIdentity !== undefined &&
      (await removeOwnedEmptyDirectory(state.stagingDirectory, state.stagingIdentity))
    ) {
      state.stagingPresent = false;
      await postPublishCheckpoint(checkpoint, "staging-directory-removed");
    }
  } catch {
    // Publication is already visible; staging cleanup is identity-guarded best effort.
  }
}

async function cleanupUnpublished(state: PublicationState): Promise<void> {
  try {
    if (state.rootIdentity === undefined || !(await directoryMatches(state.rootDirectory, state.rootIdentity))) {
      return;
    }
    if (state.pendingPresent && state.pendingIdentity !== undefined) {
      state.pendingPresent = !(await unlinkOwnedFile(state.pendingManifestPath, state.pendingIdentity));
    }
    await state.stagingHandle?.close().catch(() => undefined);
    state.stagingHandle = undefined;
    if (state.stagingPresent && state.stagingIdentity !== undefined) {
      state.stagingPresent = !(await removeOwnedEmptyDirectory(
        state.stagingDirectory,
        state.stagingIdentity,
      ));
    }
    if (
      state.markerPresent &&
      state.markerIdentity !== undefined &&
      state.runIdentity !== undefined &&
      (await directoryMatches(state.runDirectory, state.runIdentity))
    ) {
      state.markerPresent = !(await unlinkOwnedFile(state.ownerMarkerPath, state.markerIdentity));
    }
    await state.runHandle?.close().catch(() => undefined);
    state.runHandle = undefined;
    if (
      state.runPresent &&
      state.runIdentity !== undefined &&
      (state.markerRemoved || !state.markerPresent)
    ) {
      state.runPresent = !(await removeOwnedEmptyDirectory(state.runDirectory, state.runIdentity));
    }
  } catch {
    // Never remove an entry whose ownership and identity cannot be proven.
  }
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
    const entries = await readdir(directory);
    if (entries.length !== 0) return false;
    await rmdir(directory);
    return true;
  } catch (error) {
    return isErrorCode(error, "ENOENT");
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

async function closeHandles(state: PublicationState): Promise<void> {
  await state.stagingHandle?.close().catch(() => undefined);
  await state.runHandle?.close().catch(() => undefined);
  await state.rootHandle?.close().catch(() => undefined);
  state.stagingHandle = undefined;
  state.runHandle = undefined;
  state.rootHandle = undefined;
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
  return typeof process.geteuid !== "function" || uid === BigInt(process.geteuid()) || uid === process.geteuid();
}

function resolveDirectoryArgument(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error();
  return path.resolve(value);
}

function snapshotCheckpoint(
  hooks: SuiteRunPublicationHooks,
): SuiteRunPublicationHooks["checkpoint"] {
  try {
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
    return descriptor.value as SuiteRunPublicationHooks["checkpoint"];
  } catch {
    throw publicationInputError();
  }
}

function publicationInputError(): SuiteRunDirectoryError {
  return new SuiteRunDirectoryError(
    "suite_run_write_failed",
    "the suite run directory could not be published",
  );
}

function isInternalPublicationError(error: unknown): error is InternalPublicationError {
  try {
    return error instanceof InternalPublicationError && error.code === "suite_run_exists";
  } catch {
    return false;
  }
}

function sameFile(
  first: Pick<FileIdentity, "dev" | "ino" | "uid">,
  second: Pick<FileIdentity, "dev" | "ino" | "uid">,
): boolean {
  return first.dev === second.dev && first.ino === second.ino && first.uid === second.uid;
}

function toIdentity(info: Pick<FileIdentity, "dev" | "ino" | "uid">): FileIdentity {
  return Object.freeze({ dev: info.dev, ino: info.ino, uid: info.uid });
}

function isErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}
