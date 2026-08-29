import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";

import {
  decodeUtf8Strict,
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import {
  ARTIFACT_IDENTITY_VERSION,
  ATTEMPT_IDENTITY_VERSION,
  computeArtifactIdentity,
  computeCaseInputIdentity,
  computeAttemptIdentity,
  computePolicyBindingDigest,
  computeRunIdentity,
  computeSanitizerExecutionBindingDigest,
  computeSanitizerFindingPathAllowlistDigest,
  computeSanitizerRequirementDigest,
  type ArtifactIdentityInput,
  type CaseInputIdentity,
  type SanitizerRequirementCoreV1,
  type SanitizerRequirementDecisionV1,
  type SanitizerRequirementVerifier,
} from "./identity.js";
import { RunnerError } from "./errors.js";
import {
  isSanitizerFindingPath,
  sanitizerFindingPathMatchesPatterns,
  snapshotSanitizerFindingPathPatterns,
} from "./sanitizer-finding-path.js";
import type {
  ProviderUsage,
  RequestedExecutionSettings,
  SanitizerFinding,
  SanitizerPolicyBindingIdentity,
} from "./types.js";

export const ATTEMPT_VERSION = 1 as const;
export const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const MAX_ATTEMPT_MANIFEST_BYTES = 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;
const DIRECTORY = constants.O_DIRECTORY ?? 0;
const READ_ONLY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK;
const DIRECTORY_NOFOLLOW = READ_ONLY_NOFOLLOW | DIRECTORY;
const WRITABLE_EXCLUSIVE_NOFOLLOW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW;
const OWNER_MARKER_NAME = ".attempt-owner.pending";
const PENDING_MANIFEST_NAME = "attempt.json.pending";
const CLAIM_MARKER_MAX_BYTES = 128;
const CASE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;

export type AttemptClaim = {
  readonly attemptDirectory: string;
};

export type AttemptClaimHooks = {
  beforeDirectoryOpen?: () => void | Promise<void>;
  beforeOwnerMarkerWrite?: () => void | Promise<void>;
};

type FileIdentity = {
  readonly dev: number;
  readonly ino: number;
};

type AttemptClaimState = {
  readonly ownerNonce: string;
  readonly ownerMarkerPath: string;
  directoryHandle: Awaited<ReturnType<typeof open>> | undefined;
  directoryIdentity: FileIdentity | undefined;
  markerIdentity: FileIdentity | undefined;
  markerPresent: boolean;
  markerRemovedByOwner: boolean;
  published: boolean;
  closed: boolean;
  ownedFiles: Set<string>;
  ownedFileIdentities: Map<string, FileIdentity>;
  artifactDirectoryPath: string | undefined;
  artifactDirectoryIdentity: FileIdentity | undefined;
  artifactDirectoryHandle: Awaited<ReturnType<typeof open>> | undefined;
  ownedArtifactFiles: Set<string>;
  ownedArtifactFileIdentities: Map<string, FileIdentity>;
  stagingDirectoryPath: string | undefined;
  stagingDirectoryIdentity: FileIdentity | undefined;
  ownedStagingFiles: Set<string>;
  ownedStagingFileIdentities: Map<string, FileIdentity>;
};

const ATTEMPT_CLAIMS = new WeakMap<AttemptClaim, AttemptClaimState>();

export type AttemptInputManifest = {
  image: { sha256: string; mediaType: string };
  schema: { sha256: string; mediaType: string };
  system: { sha256: string; mediaType: string };
  instruction: { sha256: string; mediaType: string };
};

export type AttemptStage = {
  status: "passed";
  errorCode: null;
};

export type AttemptManifest = {
  attemptVersion: 1;
  attemptIdentityVersion: typeof ATTEMPT_IDENTITY_VERSION;
  artifactIdentityVersion: typeof ARTIFACT_IDENTITY_VERSION;
  artifactId: string;
  attemptKey: string;
  attemptId: string;
  runId: string;
  bundleVersion: 1;
  caseId: string;
  documentKind: string;
  bundleManifestDigest: string;
  inputs: AttemptInputManifest;
  caseInputIdentity: CaseInputIdentity;
  provenance: {
    harnessVersion: string;
    harnessCommit: string | null;
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  run: {
    phase: string;
    providerId: string;
    route: string;
    implementationVersion: string | null;
    protocolVersion: string | null;
    requested: RequestedExecutionSettings;
    responded: {
      model: string | null;
      effort: string | null;
      usage: ProviderUsage;
      stopReason: string | null;
    };
  };
  approval: {
    required: boolean;
    applied: boolean;
    gateId: string | null;
    protocolVersion: 1 | null;
    snapshotDigest: string | null;
    runtimeBindingDigest: string | null;
    runtimeBindingIdentity: string | null;
    approvedScopeDigest: string | null;
    approvedScopeIdentity: string | null;
    phase: string | null;
    requirementVerifierId: string | null;
    requirementVerifierVersion: string | null;
    consumerSourceCommit: string | null;
    requirementDecisionDigest: string | null;
    sanitizerRequirementVersion: 1 | null;
    sanitizerRequired: boolean | null;
    policyRequired: boolean | null;
    sanitizerRequirementReason: string | null;
    checkedAt: string | null;
    expiresAt: string | null;
    reasonCode: string | null;
  };
  sanitizerRequirement: SanitizerRequirementDecisionV1;
  sanitizer?: {
    required: boolean;
    applied: boolean;
    id: string | null;
    protocolVersion: 1 | null;
    policyVersion: number | null;
    policyDigest: string | null;
    policyTargetIdentityDigest: string | null;
    policyBindingIdentity: SanitizerPolicyBindingIdentity | null;
    policyBindingDigest: string | null;
    findingPathAllowlistVersion: 1;
    findingPathAllowlistDigest: string;
    allowedFindingPathPatterns: string[];
    findings: SanitizerFinding[];
  };
  stages: {
    approval: AttemptStage;
    provider: AttemptStage;
    parse: AttemptStage;
    schemaValidation: AttemptStage;
    policyTargetPreflight?: AttemptStage;
    sanitizer?: AttemptStage;
    targetBinding?: AttemptStage;
  };
  document: {
    path: "document.json";
    sha256: string;
  };
  timing: {
    startedAt: string;
    finishedAt: string;
    durationMs: number;
  };
};

export type AttemptManifestBase = Omit<
  AttemptManifest,
  "artifactIdentityVersion" | "artifactId" | "document"
>;

export type AttemptReadResult = {
  manifest: AttemptManifest;
  document: JsonValue;
  artifactDirectory: string;
};

export type ReadAttemptOptions = {
  requirementVerifier?: SanitizerRequirementVerifier;
};

type AttemptWriteHooks = {
  removePendingManifest?: (pendingPath: string) => Promise<void>;
};

export async function claimAttemptDirectory(
  attemptDirectory: string,
  hooks: AttemptClaimHooks = {},
): Promise<AttemptClaim> {
  const absoluteDirectory = path.resolve(attemptDirectory);
  const ownerNonce = randomUUID();
  let created = false;
  let initializationState: AttemptClaimState | undefined;
  try {
    await mkdir(absoluteDirectory, { recursive: false, mode: 0o700 });
    created = true;
    const ownerMarkerPath = path.join(absoluteDirectory, OWNER_MARKER_NAME);
    const state: AttemptClaimState = {
      ownerNonce,
      ownerMarkerPath,
      directoryHandle: undefined,
      directoryIdentity: undefined,
      markerIdentity: undefined,
      markerPresent: false,
      markerRemovedByOwner: false,
      published: false,
      closed: false,
      ownedFiles: new Set(),
      ownedFileIdentities: new Map(),
      artifactDirectoryPath: undefined,
      artifactDirectoryIdentity: undefined,
      artifactDirectoryHandle: undefined,
      ownedArtifactFiles: new Set(),
      ownedArtifactFileIdentities: new Map(),
      stagingDirectoryPath: undefined,
      stagingDirectoryIdentity: undefined,
      ownedStagingFiles: new Set(),
      ownedStagingFileIdentities: new Map(),
    };
    initializationState = state;
    const pathInfo = await lstat(absoluteDirectory);
    if (
      pathInfo.isSymbolicLink() ||
      !pathInfo.isDirectory() ||
      (process.platform !== "win32" && (pathInfo.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
    state.directoryIdentity = toFileIdentity(pathInfo);
    await hooks.beforeDirectoryOpen?.();
    state.directoryHandle = await open(absoluteDirectory, DIRECTORY_NOFOLLOW);
    const handleInfo = await state.directoryHandle.stat();
    const openedPathInfo = await lstat(absoluteDirectory);
    if (
      !handleInfo.isDirectory() ||
      openedPathInfo.isSymbolicLink() ||
      !openedPathInfo.isDirectory() ||
      !sameFile(handleInfo, openedPathInfo) ||
      !sameFile(handleInfo, state.directoryIdentity) ||
      (process.platform !== "win32" && (handleInfo.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
    await state.directoryHandle.chmod(0o700);
    await writeOwnedFile(
      ownerMarkerPath,
      Buffer.from(`${ownerNonce}\n`, "utf8"),
      (identity) => {
        state.markerIdentity = identity;
        registerOwnedFile(state, OWNER_MARKER_NAME, identity);
      },
      hooks.beforeOwnerMarkerWrite,
      () => {
        state.markerPresent = true;
        state.ownedFiles.add(OWNER_MARKER_NAME);
      },
    );
    const claim = Object.freeze({ attemptDirectory: absoluteDirectory });
    ATTEMPT_CLAIMS.set(claim, state);
    initializationState = undefined;
    return claim;
  } catch (error) {
    if (created && initializationState !== undefined) {
      await initializationState.directoryHandle?.close().catch(() => undefined);
      initializationState.directoryHandle = undefined;
      await cleanupClaimInitialization(absoluteDirectory, initializationState);
    }
    if (!created && isErrorCode(error, "EEXIST")) {
      throw new RunnerError("attempt_exists", "an attempt already exists for this attempt identity");
    }
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("attempt_write_failed", "attempt directory could not be claimed");
  }
}

async function cleanupClaimInitialization(
  directory: string,
  state: AttemptClaimState,
): Promise<void> {
  try {
    const pathInfo = await lstat(directory);
    if (
      pathInfo.isSymbolicLink() ||
      !pathInfo.isDirectory() ||
      state.directoryIdentity === undefined ||
      !sameFile(state.directoryIdentity, pathInfo) ||
      (process.platform !== "win32" && (pathInfo.mode & 0o077) !== 0)
    ) {
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true });
    if (entries.some((entry) => !entry.isFile() || !state.ownedFiles.has(entry.name))) return;
    for (const fileName of state.ownedFiles) {
      const identity = state.ownedFileIdentities.get(fileName);
      if (identity === undefined || !(await unlinkOwnedFile(path.join(directory, fileName), identity))) {
        return;
      }
    }
    await rmdir(directory);
  } catch {
    // Never remove a directory whose identity or emptiness cannot be proven.
  }
}

export async function cleanupAttemptClaim(
  claim: AttemptClaim,
  canCleanup: () => Promise<boolean>,
): Promise<void> {
  const state = ATTEMPT_CLAIMS.get(claim);
  if (state === undefined) return;
  try {
    const allowed = await canCleanup().catch(() => false);
    const ownerProven =
      !state.published &&
      !state.closed &&
      allowed &&
      (state.markerPresent || state.markerRemovedByOwner) &&
      (await ownsAttemptClaim(claim, state));
    if (ownerProven) {
      await closeArtifactDirectoryHandle(state);
      await cleanupOwnedArtifactDirectory(state);
      await closeClaimDirectoryHandle(state);
      await cleanupOwnedFiles(claim.attemptDirectory, state);
    }
    if (allowed) {
      await cleanupClaimStaging(state);
    }
  } catch {
    // Cleanup must never replace the primary runner error.
  } finally {
    await closeArtifactDirectoryHandle(state);
    await closeClaimDirectoryHandle(state);
    state.closed = true;
    ATTEMPT_CLAIMS.delete(claim);
  }
}

async function cleanupOwnedArtifactDirectory(state: AttemptClaimState): Promise<void> {
  const directory = state.artifactDirectoryPath;
  const directoryIdentity = state.artifactDirectoryIdentity;
  if (directory === undefined || directoryIdentity === undefined) return;
  let current;
  try {
    current = await lstat(directory);
  } catch (error) {
    if (isErrorCode(error, "ENOENT")) return;
    throw error;
  }
  if (!isPrivateDirectory(current) || !sameFile(current, directoryIdentity)) return;
  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.some((entry) => !entry.isFile() || !state.ownedArtifactFiles.has(entry.name))) return;
  for (const fileName of [...state.ownedArtifactFiles]) {
    const identity = state.ownedArtifactFileIdentities.get(fileName);
    if (identity === undefined || !(await unlinkOwnedFile(path.join(directory, fileName), identity))) {
      return;
    }
    state.ownedArtifactFiles.delete(fileName);
    state.ownedArtifactFileIdentities.delete(fileName);
  }
  if ((await readdir(directory)).length === 0) await rmdir(directory);
}

async function cleanupOwnedFiles(directory: string, state: AttemptClaimState): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.some((entry) => !entry.isFile() || !state.ownedFiles.has(entry.name))) return;
  for (const fileName of [...state.ownedFiles]) {
    const identity = state.ownedFileIdentities.get(fileName);
    if (identity === undefined || !(await unlinkOwnedFile(path.join(directory, fileName), identity))) {
      return;
    }
    state.ownedFiles.delete(fileName);
    state.ownedFileIdentities.delete(fileName);
  }
  if ((await readdir(directory)).length === 0) await rmdir(directory);
}

async function cleanupClaimStaging(state: AttemptClaimState): Promise<void> {
  const stagingDirectory = state.stagingDirectoryPath;
  const stagingIdentity = state.stagingDirectoryIdentity;
  if (stagingDirectory === undefined || stagingIdentity === undefined) return;
  for (const fileName of [...state.ownedStagingFiles]) {
    const identity = state.ownedStagingFileIdentities.get(fileName);
    if (
      identity === undefined ||
      !(await unlinkOwnedFile(path.join(stagingDirectory, fileName), identity))
    ) {
      return;
    }
    state.ownedStagingFiles.delete(fileName);
    state.ownedStagingFileIdentities.delete(fileName);
  }
  const currentStaging = await lstat(stagingDirectory);
  if (!currentStaging.isDirectory() || !sameFile(stagingIdentity, currentStaging)) return;
  if ((await readdir(stagingDirectory)).length !== 0) return;
  await rmdir(stagingDirectory);
}

async function closeClaimDirectoryHandle(state: AttemptClaimState): Promise<void> {
  const handle = state.directoryHandle;
  state.directoryHandle = undefined;
  await handle?.close().catch(() => undefined);
}

async function closeArtifactDirectoryHandle(state: AttemptClaimState): Promise<void> {
  const handle = state.artifactDirectoryHandle;
  state.artifactDirectoryHandle = undefined;
  await handle?.close().catch(() => undefined);
}

async function writeOwnedFile(
  file: string,
  bytes: Buffer,
  register: (identity: FileIdentity) => void,
  beforeWrite?: () => void | Promise<void>,
  onCreate?: () => void,
): Promise<void> {
  let handle;
  try {
    handle = await open(file, WRITABLE_EXCLUSIVE_NOFOLLOW, 0o600);
    onCreate?.();
    const info = await handle.stat();
    if (!info.isFile() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) {
      throw new Error();
    }
    register(toFileIdentity(info));
    await beforeWrite?.();
    await handle.writeFile(bytes);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function registerOwnedFile(state: AttemptClaimState, fileName: string, identity: FileIdentity): void {
  state.ownedFiles.add(fileName);
  state.ownedFileIdentities.set(fileName, identity);
}

function registerOwnedArtifactFile(
  state: AttemptClaimState,
  fileName: string,
  identity: FileIdentity,
): void {
  state.ownedArtifactFiles.add(fileName);
  state.ownedArtifactFileIdentities.set(fileName, identity);
}

async function createArtifactDirectory(
  claim: AttemptClaim,
  state: AttemptClaimState,
  artifactId: string,
): Promise<string> {
  const artifactDirectory = path.join(claim.attemptDirectory, artifactId);
  await mkdir(artifactDirectory, { recursive: false, mode: 0o700 });
  const pathInfo = await lstat(artifactDirectory);
  if (!isPrivateDirectory(pathInfo)) throw new Error();
  state.artifactDirectoryPath = artifactDirectory;
  state.artifactDirectoryIdentity = toFileIdentity(pathInfo);
  const handle = await open(artifactDirectory, DIRECTORY_NOFOLLOW);
  const handleInfo = await handle.stat();
  if (!handleInfo.isDirectory() || !sameFile(handleInfo, pathInfo)) {
    await handle.close().catch(() => undefined);
    throw new Error();
  }
  state.artifactDirectoryIdentity = toFileIdentity(handleInfo);
  state.artifactDirectoryHandle = handle;
  return artifactDirectory;
}

async function assertArtifactDirectoryStable(state: AttemptClaimState): Promise<void> {
  const directory = state.artifactDirectoryPath;
  const identity = state.artifactDirectoryIdentity;
  const handle = state.artifactDirectoryHandle;
  if (directory === undefined || identity === undefined || handle === undefined) throw new Error();
  const handleInfo = await handle.stat();
  const pathInfo = await lstat(directory);
  if (
    !handleInfo.isDirectory() ||
    pathInfo.isSymbolicLink() ||
    !pathInfo.isDirectory() ||
    !sameFile(handleInfo, pathInfo) ||
    !sameFile(handleInfo, identity) ||
    (process.platform !== "win32" && (handleInfo.mode & 0o077) !== 0)
  ) {
    throw new Error();
  }
}

function registerOwnedStagingFile(
  state: AttemptClaimState,
  fileName: string,
  identity: FileIdentity,
): void {
  state.ownedStagingFiles.add(fileName);
  state.ownedStagingFileIdentities.set(fileName, identity);
}

async function unlinkOwnedFile(file: string, identity: FileIdentity): Promise<boolean> {
  try {
    const info = await lstat(file);
    if (
      info.isSymbolicLink() ||
      !info.isFile() ||
      (process.platform !== "win32" && (info.mode & 0o077) !== 0) ||
      !sameFile(identity, info)
    ) {
      return false;
    }
    await unlink(file);
    return true;
  } catch (error) {
    return isErrorCode(error, "ENOENT");
  }
}

async function prepareManifestStaging(
  state: AttemptClaimState,
  attemptDirectory: string,
): Promise<string> {
  const stagingDirectory = path.join(
    path.dirname(attemptDirectory),
    `.claim-${state.ownerNonce}`,
  );
  await mkdir(stagingDirectory, { recursive: false, mode: 0o700 });
  state.stagingDirectoryPath = stagingDirectory;
  const stagingInfo = await lstat(stagingDirectory);
  if (!isPrivateDirectory(stagingInfo)) throw new Error();
  state.stagingDirectoryIdentity = toFileIdentity(stagingInfo);
  return path.join(stagingDirectory, PENDING_MANIFEST_NAME);
}

async function readPendingAttemptFiles(
  artifactDirectory: string,
  manifestPath: string,
): Promise<void> {
  await assertClaimDirectoryEntries(artifactDirectory, ["document.json"]);
  const manifestFile = await readAttemptJson(manifestPath);
  const manifest = parseAttemptManifest(manifestFile.value, undefined);
  assertAttemptDirectoryIdentity(path.dirname(artifactDirectory), manifest.attemptId);
  assertArtifactDirectoryIdentity(artifactDirectory, manifest);
  const documentFile = await readAttemptJson(path.join(artifactDirectory, manifest.document.path), true);
  if (createHash("sha256").update(documentFile.bytes).digest("hex") !== manifest.document.sha256) {
    throw new RunnerError(
      "attempt_document_digest_mismatch",
      "attempt document digest does not match its manifest",
    );
  }
}

async function assertClaimDirectoryEntries(
  directory: string,
  expected: string[],
  expectedDirectories: readonly string[] = [],
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  const directoryNames = new Set(expectedDirectories);
  if (
    entries.some((entry) =>
      directoryNames.has(entry.name) ? !entry.isDirectory() : !entry.isFile(),
    )
  ) {
    throw new Error();
  }
  const names = entries.map((entry) => entry.name).sort();
  const expectedNames = [...expected].sort();
  if (names.length !== expectedNames.length || names.some((name, index) => name !== expectedNames[index])) {
    throw new Error();
  }
}

async function assertClaimStagingStable(state: AttemptClaimState): Promise<void> {
  const stagingDirectory = state.stagingDirectoryPath;
  const stagingIdentity = state.stagingDirectoryIdentity;
  if (stagingDirectory === undefined || stagingIdentity === undefined) {
    throw new Error();
  }
  const currentStaging = await lstat(stagingDirectory);
  if (
    !isPrivateDirectory(currentStaging) ||
    !sameFile(stagingIdentity, currentStaging)
  ) {
    throw new Error();
  }
}

async function assertOwnedStagingFileStable(
  state: AttemptClaimState,
  fileName: string,
): Promise<void> {
  const stagingDirectory = state.stagingDirectoryPath;
  const identity = state.ownedStagingFileIdentities.get(fileName);
  if (stagingDirectory === undefined || identity === undefined) throw new Error();
  const info = await lstat(path.join(stagingDirectory, fileName));
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    (process.platform !== "win32" && (info.mode & 0o077) !== 0) ||
    !sameFile(identity, info)
  ) {
    throw new Error();
  }
}

export function encodeAttemptDocument(document: JsonValue): {
  bytes: Buffer;
  sha256: string;
} {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(normalizeJsonValue(document, "provider document", MAX_DOCUMENT_BYTES), null, 2);
  } catch {
    throw new RunnerError("provider_response_invalid", "provider document could not be serialized");
  }
  if (serialized === undefined) {
    throw new RunnerError("provider_response_invalid", "provider document could not be serialized");
  }
  const bytes = Buffer.from(`${serialized}\n`, "utf8");
  if (bytes.length > MAX_DOCUMENT_BYTES) {
    throw new RunnerError("provider_document_too_large", "provider document exceeds the size limit");
  }
  return {
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

export async function writeAttemptFiles(
  claim: AttemptClaim,
  manifest: AttemptManifestBase,
  document: JsonValue,
  canCleanup: () => Promise<boolean>,
  beforePublish: (() => Promise<void>) | undefined = undefined,
  hooks: AttemptWriteHooks = {},
): Promise<{ artifactDirectory: string; artifactId: string; documentSha256: string }> {
  const state = ATTEMPT_CLAIMS.get(claim);
  if (state === undefined || state.closed) {
    throw new RunnerError("attempt_write_failed", "attempt claim is unavailable");
  }
  const attemptDirectory = claim.attemptDirectory;
  try {
    const encoded = encodeAttemptDocument(document);
    const artifactIdentity = computeArtifactIdentity({
      attemptId: manifest.attemptId,
      documentSha256: encoded.sha256,
      sanitizer: toArtifactIdentitySanitizer(manifest.sanitizer),
    });
    const artifactDirectory = await createArtifactDirectory(
      claim,
      state,
      artifactIdentity.artifactId,
    );
    const documentPath = path.join(artifactDirectory, "document.json");
    const documentPart = path.join(artifactDirectory, "document.json.part");
    const manifestPath = path.join(artifactDirectory, "attempt.json");
    const completeManifest: AttemptManifest = {
      ...manifest,
      ...artifactIdentity,
      document: { path: "document.json", sha256: encoded.sha256 },
    };
    await assertClaimOwnership(claim, state);
    await assertArtifactDirectoryStable(state);
    await writeOwnedFile(documentPart, encoded.bytes, (identity) => {
      registerOwnedArtifactFile(state, "document.json.part", identity);
    }, undefined, () => {
      state.ownedArtifactFiles.add("document.json.part");
    });
    const documentPartIdentity = state.ownedArtifactFileIdentities.get("document.json.part");
    if (documentPartIdentity === undefined) throw new Error();
    await linkNoReplace(documentPart, documentPath, "attempt_write_failed");
    registerOwnedArtifactFile(state, "document.json", documentPartIdentity);
    if (!(await unlinkOwnedFile(documentPart, documentPartIdentity))) throw new Error();
    state.ownedArtifactFiles.delete("document.json.part");
    state.ownedArtifactFileIdentities.delete("document.json.part");
    const manifestValue = normalizeJsonValue(
      completeManifest as unknown as JsonValue,
      "attempt manifest",
      MAX_ATTEMPT_MANIFEST_BYTES,
    );
    const manifestBytes = Buffer.from(`${JSON.stringify(manifestValue, null, 2)}\n`, "utf8");
    if (manifestBytes.length > MAX_ATTEMPT_MANIFEST_BYTES) {
      throw new RunnerError("attempt_write_failed", "attempt manifest exceeds the size limit");
    }
    const manifestPending = await prepareManifestStaging(state, attemptDirectory);
    await writeOwnedFile(manifestPending, manifestBytes, (identity) => {
      registerOwnedStagingFile(state, PENDING_MANIFEST_NAME, identity);
    }, undefined, () => {
      state.ownedStagingFiles.add(PENDING_MANIFEST_NAME);
    });
    await readPendingAttemptFiles(artifactDirectory, manifestPending);
    await assertClaimOwnership(claim, state);
    const markerIdentity = state.markerIdentity;
    if (markerIdentity === undefined || !(await unlinkOwnedFile(state.ownerMarkerPath, markerIdentity))) {
      throw new Error();
    }
    state.markerPresent = false;
    state.markerRemovedByOwner = true;
    state.ownedFiles.delete(OWNER_MARKER_NAME);
    state.ownedFileIdentities.delete(OWNER_MARKER_NAME);
    await beforePublish?.();
    await assertClaimDirectoryStable(claim, state);
    await assertArtifactDirectoryStable(state);
    await assertClaimDirectoryEntries(
      attemptDirectory,
      [artifactIdentity.artifactId],
      [artifactIdentity.artifactId],
    );
    await assertClaimDirectoryEntries(artifactDirectory, ["document.json"]);
    await assertClaimStagingStable(state);
    await assertOwnedStagingFileStable(state, PENDING_MANIFEST_NAME);
    const manifestIdentity = state.ownedStagingFileIdentities.get(PENDING_MANIFEST_NAME);
    if (manifestIdentity === undefined) throw new Error();
    await linkNoReplace(manifestPending, manifestPath, "attempt_exists");
    registerOwnedArtifactFile(state, "attempt.json", manifestIdentity);
    state.published = true;
    try {
      await (hooks.removePendingManifest === undefined
        ? unlink(manifestPending)
        : hooks.removePendingManifest(manifestPending));
    } catch {
      // The final link already made the exact attempt shape visible. Source
      // cleanup is best effort and must not turn publication into a failure.
    }
    if (!(await pathExists(manifestPending))) {
      state.ownedStagingFiles.delete(PENDING_MANIFEST_NAME);
      state.ownedStagingFileIdentities.delete(PENDING_MANIFEST_NAME);
    }
    return {
      artifactDirectory,
      artifactId: artifactIdentity.artifactId,
      documentSha256: encoded.sha256,
    };
  } catch (error) {
    await cleanupAttemptClaim(claim, canCleanup);
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("attempt_write_failed", "attempt files could not be written");
  }
}

export async function readAttempt(
  attemptDirectory: string,
  options: ReadAttemptOptions = {},
): Promise<AttemptReadResult> {
  const result = await readAttemptFiles(path.resolve(attemptDirectory), options.requirementVerifier);
  return {
    manifest: result.manifest,
    document: result.documentFile.value,
    artifactDirectory: result.artifactDirectory,
  };
}

async function readAttemptFiles(
  attemptDirectory: string,
  requirementVerifier: SanitizerRequirementVerifier | undefined,
): Promise<{
  manifest: AttemptManifest;
  documentFile: { value: JsonValue; bytes: Buffer };
  artifactDirectory: string;
}> {
  const absoluteDirectory = path.resolve(attemptDirectory);
  const artifactDirectory = await resolveArtifactDirectory(absoluteDirectory);
  const manifestFile = await readAttemptJson(path.join(artifactDirectory, "attempt.json"));
  const manifest = parseAttemptManifest(manifestFile.value, requirementVerifier);
  assertAttemptDirectoryIdentity(absoluteDirectory, manifest.attemptId);
  assertArtifactDirectoryIdentity(artifactDirectory, manifest);
  const documentFile = await readAttemptJson(path.join(artifactDirectory, manifest.document.path), true);
  if (createHash("sha256").update(documentFile.bytes).digest("hex") !== manifest.document.sha256) {
    throw new RunnerError(
      "attempt_document_digest_mismatch",
      "attempt document digest does not match its manifest",
    );
  }
  await assertFormalArtifactDirectory(artifactDirectory);
  await assertAttemptContainer(absoluteDirectory, manifest.artifactId);
  return { manifest, documentFile, artifactDirectory };
}

function assertAttemptDirectoryIdentity(directory: string, attemptId: string): void {
  if (path.basename(directory) !== attemptId) {
    throw new RunnerError("attempt_identity_mismatch", "attempt directory identity is invalid");
  }
}

function assertArtifactDirectoryIdentity(directory: string, manifest: AttemptManifest): void {
  try {
    const computed = computeArtifactIdentity({
      attemptId: manifest.attemptId,
      documentSha256: manifest.document.sha256,
      sanitizer: toArtifactIdentitySanitizer(manifest.sanitizer),
    });
    if (
      manifest.artifactIdentityVersion === computed.artifactIdentityVersion &&
      manifest.artifactId === computed.artifactId &&
      path.basename(directory) === computed.artifactId
    ) {
      return;
    }
  } catch {
    // Normalize all malformed or mismatched artifact identity inputs below.
  }
  throw new RunnerError("attempt_identity_mismatch", "attempt artifact identity is invalid");
}

function toArtifactIdentitySanitizer(
  sanitizer: AttemptManifest["sanitizer"],
): ArtifactIdentityInput["sanitizer"] {
  if (sanitizer === undefined) return null;
  if (
    sanitizer.id === null ||
    sanitizer.protocolVersion !== 1 ||
    sanitizer.policyBindingDigest === null
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt artifact identity is invalid");
  }
  return {
    id: sanitizer.id,
    protocolVersion: sanitizer.protocolVersion,
    bindingDigest: computeSanitizerExecutionBindingDigest({
      policyBindingDigest: sanitizer.policyBindingDigest,
      findingPathAllowlistDigest: sanitizer.findingPathAllowlistDigest,
    }),
    findings: sanitizer.findings.map((finding) => ({
      code: finding.code,
      severity: finding.severity,
      classification: finding.classification,
      hardGate: finding.hardGate,
      path: finding.path ?? null,
    })),
  };
}

async function resolveArtifactDirectory(attemptDirectory: string): Promise<string> {
  try {
    await assertPrivateDirectory(attemptDirectory);
    const entries = await readdir(attemptDirectory, { withFileTypes: true });
    if (
      entries.length !== 1 ||
      !entries[0]?.isDirectory() ||
      !SHA256_PATTERN.test(entries[0].name)
    ) {
      throw new Error();
    }
    const artifactDirectory = path.join(attemptDirectory, entries[0].name);
    await assertFormalArtifactDirectory(artifactDirectory);
    return artifactDirectory;
  } catch {
    throw new RunnerError("attempt_invalid", "attempt directory is invalid");
  }
}

async function assertAttemptContainer(directory: string, artifactId: string): Promise<void> {
  try {
    await assertPrivateDirectory(directory);
    const entries = await readdir(directory, { withFileTypes: true });
    if (entries.length !== 1 || !entries[0]?.isDirectory() || entries[0].name !== artifactId) {
      throw new Error();
    }
  } catch {
    throw new RunnerError("attempt_invalid", "attempt directory is invalid");
  }
}

async function assertFormalArtifactDirectory(directory: string): Promise<void> {
  try {
    await assertPrivateDirectory(directory);
    const entries = await readdir(directory, { withFileTypes: true });
    const names = entries.map((entry) => entry.name).sort();
    const expectedNames = ["attempt.json", "document.json"];
    if (
      entries.some((entry) => !entry.isFile()) ||
      names.length !== expectedNames.length ||
      names.some((name, index) => name !== expectedNames[index])
    ) {
      throw new Error();
    }
  } catch {
    throw new RunnerError("attempt_invalid", "attempt directory is invalid");
  }
}

async function assertPrivateDirectory(directory: string): Promise<void> {
  let handle;
  try {
    const absolute = path.resolve(directory);
    const pathInfo = await lstat(absolute);
    if (pathInfo.isSymbolicLink() || !pathInfo.isDirectory()) throw new Error();
    handle = await open(absolute, DIRECTORY_NOFOLLOW);
    const info = await handle.stat();
    if (
      !info.isDirectory() ||
      !sameFile(info, pathInfo) ||
      (process.platform !== "win32" && (info.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
    const finalPathInfo = await lstat(absolute);
    if (finalPathInfo.isSymbolicLink() || !sameFile(info, finalPathInfo)) throw new Error();
  } catch {
    throw new RunnerError("attempt_invalid", "attempt directory is invalid");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readAttemptJson(
  file: string,
  document = false,
): Promise<{ value: JsonValue; bytes: Buffer }> {
  const maxBytes = document ? MAX_DOCUMENT_BYTES : MAX_ATTEMPT_MANIFEST_BYTES;
  let handle;
  try {
    const absolute = path.resolve(file);
    handle = await open(absolute, READ_ONLY_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) throw new Error();
    const pathInfo = await lstat(absolute);
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile() || !sameFile(info, pathInfo)) throw new Error();
    const bytes = await readBounded(handle, maxBytes);
    const finalPathInfo = await lstat(absolute);
    if (finalPathInfo.isSymbolicLink() || !sameFile(info, finalPathInfo)) throw new Error();
    try {
      return { value: parseJson(decodeUtf8Strict(bytes, "attempt file"), "attempt file"), bytes };
    } catch {
      throw new RunnerError("attempt_invalid", "attempt file is invalid");
    }
  } catch {
    throw new RunnerError("attempt_invalid", "attempt file is invalid");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readBounded(handle: Awaited<ReturnType<typeof open>>, maxBytes: number): Promise<Buffer> {
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

async function assertClaimOwnership(claim: AttemptClaim, state: AttemptClaimState): Promise<void> {
  await assertClaimDirectoryStable(claim, state);
  if (state.markerPresent && !(await ownerMarkerMatches(state.ownerMarkerPath, state.ownerNonce))) {
    throw new RunnerError("attempt_write_failed", "attempt claim is not owned");
  }
}

async function linkNoReplace(
  source: string,
  destination: string,
  existingCode: "attempt_exists" | "attempt_write_failed",
): Promise<void> {
  try {
    await link(source, destination);
  } catch (error) {
    if (isErrorCode(error, "EEXIST")) {
      if (existingCode === "attempt_exists") {
        throw new RunnerError("attempt_exists", "an attempt already exists for this attempt identity");
      }
      throw new RunnerError("attempt_write_failed", "attempt file already exists");
    }
    throw error;
  }
}

async function assertClaimDirectoryStable(
  claim: AttemptClaim,
  state: AttemptClaimState,
): Promise<void> {
  try {
    if (state.directoryHandle === undefined || state.directoryIdentity === undefined) throw new Error();
    const handleInfo = await state.directoryHandle.stat();
    const pathInfo = await lstat(claim.attemptDirectory);
    if (
      !handleInfo.isDirectory() ||
      !pathInfo.isDirectory() ||
      pathInfo.isSymbolicLink() ||
      !sameFile(handleInfo, pathInfo) ||
      !sameFile(handleInfo, state.directoryIdentity) ||
      (process.platform !== "win32" && (handleInfo.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
  } catch {
    throw new RunnerError("attempt_write_failed", "attempt claim changed");
  }
}

async function ownsAttemptClaim(claim: AttemptClaim, state: AttemptClaimState): Promise<boolean> {
  try {
    await assertClaimDirectoryStable(claim, state);
    if (state.markerPresent) return await ownerMarkerMatches(state.ownerMarkerPath, state.ownerNonce);
    return state.markerRemovedByOwner;
  } catch {
    return false;
  }
}

async function ownerMarkerMatches(file: string, ownerNonce: string): Promise<boolean> {
  let handle;
  try {
    const absolute = path.resolve(file);
    handle = await open(absolute, READ_ONLY_NOFOLLOW);
    const info = await handle.stat();
    const pathInfo = await lstat(absolute);
    if (
      !info.isFile() ||
      pathInfo.isSymbolicLink() ||
      !pathInfo.isFile() ||
      !sameFile(info, pathInfo) ||
      (process.platform !== "win32" && (info.mode & 0o077) !== 0)
    ) {
      return false;
    }
    const value = decodeUtf8Strict(await readBounded(handle, CLAIM_MARKER_MAX_BYTES), "attempt claim marker");
    return value === `${ownerNonce}\n`;
  } catch {
    return false;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function pathExists(file: string): Promise<boolean> {
  try {
    await lstat(file);
    return true;
  } catch (error) {
    return !isErrorCode(error, "ENOENT");
  }
}

function parseAttemptManifest(
  value: JsonValue,
  requirementVerifier: SanitizerRequirementVerifier | undefined,
): AttemptManifest {
  const manifest = requiredObject(value);
  assertKeys(manifest, [
    "attemptVersion",
    "attemptIdentityVersion",
    "artifactIdentityVersion",
    "artifactId",
    "attemptKey",
    "attemptId",
    "runId",
    "bundleVersion",
    "caseId",
    "documentKind",
    "bundleManifestDigest",
    "inputs",
    "caseInputIdentity",
    "provenance",
    "run",
    "approval",
    "sanitizerRequirement",
    "sanitizer",
    "stages",
    "document",
    "timing",
  ]);
  if (
    manifest.attemptVersion !== ATTEMPT_VERSION ||
    manifest.attemptIdentityVersion !== ATTEMPT_IDENTITY_VERSION ||
    manifest.artifactIdentityVersion !== ARTIFACT_IDENTITY_VERSION ||
    manifest.bundleVersion !== 1
  ) invalid();
  const attemptKey = requiredSafeLabel(manifest.attemptKey);
  const attemptId = requiredDigest(manifest.attemptId);
  requiredDigest(manifest.artifactId);
  const runId = requiredDigest(manifest.runId);
  if (computeAttemptIdentity({ runId, attemptKey }).attemptId !== attemptId) {
    throw new RunnerError("attempt_identity_mismatch", "attempt instance identity is invalid");
  }
  const caseId = requiredCaseId(manifest.caseId);
  const documentKind = requiredSafeLabel(manifest.documentKind);
  const bundleManifestDigest = requiredDigest(manifest.bundleManifestDigest);
  const sanitizerRequirement = parseSanitizerRequirement(
    manifest.sanitizerRequirement,
    documentKind,
    requirementVerifier,
  );
  const inputs = parseInputs(manifest.inputs);
  const identity = parseIdentity(manifest.caseInputIdentity);
  let recomputedIdentity: CaseInputIdentity;
  try {
    recomputedIdentity = computeCaseInputIdentity({
      caseId: identity.caseId,
      documentKind: identity.documentKind,
      preparedImage: identity.preparedImage,
    });
  } catch {
    throw new RunnerError("attempt_identity_mismatch", "attempt case identity is invalid");
  }
  if (
    identity.caseId !== caseId ||
    identity.documentKind !== documentKind ||
    identity.digest !== recomputedIdentity.digest ||
    identity.preparedImage.sha256 !== inputs.image.sha256 ||
    identity.preparedImage.mediaType !== inputs.image.mediaType
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt case identity is invalid");
  }
  const document = requiredObject(manifest.document);
  assertKeys(document, ["path", "sha256"]);
  if (document.path !== "document.json") invalid();
  requiredDigest(document.sha256);
  const timing = requiredObject(manifest.timing);
  assertKeys(timing, ["startedAt", "finishedAt", "durationMs"]);
  if (
    typeof timing.startedAt !== "string" ||
    typeof timing.finishedAt !== "string" ||
    !isDateTime(timing.startedAt) ||
    !isDateTime(timing.finishedAt) ||
    typeof timing.durationMs !== "number" ||
    !Number.isSafeInteger(timing.durationMs) ||
    timing.durationMs < 0
  ) {
    invalid();
  }
  parseProvenance(manifest.provenance);
  let sanitizer: AttemptManifest["sanitizer"];
  if (sanitizerRequirement.sanitizerRequired) {
    const sanitizerRecord = requiredObject(manifest.sanitizer);
    assertKeys(sanitizerRecord, [
      "required",
      "applied",
      "id",
      "protocolVersion",
      "policyVersion",
      "policyDigest",
      "policyTargetIdentityDigest",
      "policyBindingIdentity",
      "policyBindingDigest",
      "findingPathAllowlistVersion",
      "findingPathAllowlistDigest",
      "allowedFindingPathPatterns",
      "findings",
    ]);
    const findingPathPatterns = parseSanitizerFindingPathAllowlist(sanitizerRecord);
    parseSanitizerFindings(sanitizerRecord.findings, findingPathPatterns);
    validateSanitizerBinding(sanitizerRecord, identity.digest);
    if (sanitizerRecord.required !== true || sanitizerRecord.applied !== true) invalid();
    sanitizer = sanitizerRecord as unknown as NonNullable<AttemptManifest["sanitizer"]>;
  } else if (Object.hasOwn(manifest, "sanitizer")) {
    invalid();
  }
  const run = requiredObject(manifest.run);
  assertKeys(run, [
    "phase",
    "providerId",
    "route",
    "implementationVersion",
    "protocolVersion",
    "requested",
    "responded",
  ]);
  parseResponded(run.responded);
  const phase = requiredString(run.phase);
  const providerId = requiredString(run.providerId);
  const route = requiredString(run.route);
  if (!isSafeLabel(phase) || !isSafeLabel(providerId) || !isSafeLabel(route)) invalid();
  const providerImplementationVersion = nullableSafeLabel(run.implementationVersion);
  const providerProtocolVersion = nullableSafeLabel(run.protocolVersion);
  const requested = parseRequested(run.requested);
  const approval = requiredObject(manifest.approval);
  assertKeys(approval, [
    "required",
    "applied",
    "gateId",
    "protocolVersion",
    "snapshotDigest",
    "runtimeBindingDigest",
    "runtimeBindingIdentity",
    "approvedScopeDigest",
    "approvedScopeIdentity",
    "phase",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "consumerSourceCommit",
    "requirementDecisionDigest",
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
    "checkedAt",
    "expiresAt",
    "reasonCode",
  ]);
  const approvalMetadata = parseApprovalMetadata(approval, sanitizerRequirement);
  if (approvalMetadata.applied && approvalMetadata.phase !== phase) {
    throw new RunnerError(
      "attempt_identity_mismatch",
      "attempt approval phase is invalid",
    );
  }
  const sanitizerBindingDigest =
    sanitizer === undefined
      ? null
      : computeSanitizerExecutionBindingDigest({
          policyBindingDigest: requiredDigest(sanitizer.policyBindingDigest),
          findingPathAllowlistDigest: requiredDigest(
            sanitizer.findingPathAllowlistDigest,
          ),
        });
  parseStages(manifest.stages, sanitizerRequirement.sanitizerRequired);
  if (
    computeRunIdentity({
      caseInputIdentityDigest: identity.digest,
      bundleManifestDigest,
      phase,
      providerId,
      providerRoute: route,
      providerImplementationVersion,
      providerProtocolVersion,
      requestedModel: requested.model,
      requestedEffort: requested.effort,
      maxTokens: requested.maxTokens,
      approvalBindingDigest: approvalMetadata.runtimeBindingDigest,
      approvalBindingIdentity: approvalMetadata.runtimeBindingIdentity,
      approvalGateId: approvalMetadata.gateId,
      approvalProtocolVersion: approvalMetadata.protocolVersion,
      approvalSnapshotDigest: approvalMetadata.snapshotDigest,
      approvalPhase: approvalMetadata.phase,
      approvalScopeDigest: approvalMetadata.approvedScopeDigest,
      approvalScopeIdentity: approvalMetadata.approvedScopeIdentity,
      approvalRequired: approvalMetadata.required,
      sanitizerBindingDigest,
      sanitizerId: sanitizer === undefined ? null : nullableSafeLabel(sanitizer.id),
      sanitizerProtocolVersion: sanitizer === undefined ? null : nullableProtocolVersion(sanitizer.protocolVersion),
      sanitizerRequired: sanitizer !== undefined,
      policyRequired: sanitizer !== undefined,
      sanitizerRequirementVersion: sanitizerRequirement.sanitizerRequirementVersion,
      sanitizerRequirementReason: sanitizerRequirement.sanitizerRequirementReason,
      requirementVerifierId: sanitizerRequirement.requirementVerifierId,
      requirementVerifierVersion: sanitizerRequirement.requirementVerifierVersion,
      consumerSourceCommit: sanitizerRequirement.consumerSourceCommit,
      requirementDecisionDigest: sanitizerRequirement.requirementDecisionDigest,
    }) !== runId
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt run identity is invalid");
  }
  // The writer creates this shape from typed values. Re-check the identity and
  // binding invariants here, then return the parsed value for normal consumers.
  return manifest as unknown as AttemptManifest;
}

function parseSanitizerRequirement(
  value: JsonValue | undefined,
  documentKind: string,
  verifier: SanitizerRequirementVerifier | undefined,
): SanitizerRequirementDecisionV1 {
  const requirement = requiredObject(value);
  assertKeys(requirement, [
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "consumerSourceCommit",
    "requirementDecisionDigest",
  ]);
  if (requirement.sanitizerRequirementVersion !== 1) invalid();
  if (typeof requirement.sanitizerRequired !== "boolean" || typeof requirement.policyRequired !== "boolean") {
    invalid();
  }
  if (requirement.sanitizerRequired !== requirement.policyRequired) invalid();
  const core: SanitizerRequirementCoreV1 = {
    sanitizerRequired: requirement.sanitizerRequired,
    policyRequired: requirement.policyRequired,
    sanitizerRequirementReason: requiredSafeLabel(requirement.sanitizerRequirementReason),
    consumerSourceCommit: nullableSafeLabel(requirement.consumerSourceCommit),
  };
  const requirementVerifierId = requiredSafeLabel(requirement.requirementVerifierId);
  const requirementVerifierVersion = requiredSafeLabel(requirement.requirementVerifierVersion);
  const requirementDecisionDigest = requiredDigest(requirement.requirementDecisionDigest);
  const expected: SanitizerRequirementDecisionV1 = {
    ...core,
    sanitizerRequirementVersion: 1,
    requirementVerifierId,
    requirementVerifierVersion,
    requirementDecisionDigest: computeSanitizerRequirementDigest({
      ...core,
      sanitizerRequirementVersion: 1,
      requirementVerifierId,
      requirementVerifierVersion,
    }),
  };
  if (requirementDecisionDigest !== expected.requirementDecisionDigest) {
    throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer requirement is invalid");
  }
  if (verifier !== undefined) {
    if (!isSafeLabel(verifier.id) || !isSafeLabel(verifier.version)) invalid();
    let derived: SanitizerRequirementCoreV1;
    try {
      derived = verifier.derive(documentKind);
      if (
        derived === null ||
        typeof derived !== "object" ||
        typeof derived.sanitizerRequired !== "boolean" ||
        typeof derived.policyRequired !== "boolean" ||
        typeof derived.sanitizerRequirementReason !== "string" ||
        !isSafeLabel(derived.sanitizerRequirementReason) ||
        (derived.consumerSourceCommit !== null &&
          (typeof derived.consumerSourceCommit !== "string" || !isSafeLabel(derived.consumerSourceCommit))) ||
        derived.sanitizerRequired !== derived.policyRequired
      ) {
        throw new Error();
      }
    } catch {
      throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer requirement is invalid");
    }
    const derivedDigest = computeSanitizerRequirementDigest({
      ...derived,
      sanitizerRequirementVersion: 1,
      requirementVerifierId: verifier.id,
      requirementVerifierVersion: verifier.version,
    });
    if (
      verifier.id !== requirementVerifierId ||
      verifier.version !== requirementVerifierVersion ||
      derivedDigest !== requirementDecisionDigest ||
      derived.sanitizerRequired !== core.sanitizerRequired ||
      derived.policyRequired !== core.policyRequired ||
      derived.sanitizerRequirementReason !== core.sanitizerRequirementReason ||
      derived.consumerSourceCommit !== core.consumerSourceCommit
    ) {
      throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer requirement is invalid");
    }
  }
  return expected;
}

function parseInputs(value: JsonValue | undefined): AttemptInputManifest {
  const inputs = requiredObject(value);
  assertKeys(inputs, ["image", "schema", "system", "instruction"]);
  return {
    image: parseInput(inputs.image),
    schema: parseInput(inputs.schema),
    system: parseInput(inputs.system),
    instruction: parseInput(inputs.instruction),
  };
}

function parseInput(value: JsonValue | undefined): { sha256: string; mediaType: string } {
  const input = requiredObject(value);
  assertKeys(input, ["sha256", "mediaType"]);
  return {
    sha256: requiredDigest(input.sha256),
    mediaType: requiredMediaType(input.mediaType),
  };
}

function parseIdentity(value: JsonValue | undefined): CaseInputIdentity {
  const identity = requiredObject(value);
  assertKeys(identity, ["identityVersion", "caseId", "documentKind", "preparedImage", "digest"]);
  const preparedImage = requiredObject(identity.preparedImage);
  assertKeys(preparedImage, ["mediaType", "sha256"]);
  if (identity.identityVersion !== 1) invalid();
  const result: CaseInputIdentity = {
    identityVersion: 1,
    caseId: requiredCaseId(identity.caseId),
    documentKind: requiredSafeLabel(identity.documentKind),
    preparedImage: {
      mediaType: requiredMediaType(preparedImage.mediaType),
      sha256: requiredDigest(preparedImage.sha256),
    },
    digest: requiredDigest(identity.digest),
  };
  return result;
}

function validateSanitizerBinding(sanitizer: Record<string, JsonValue>, identityDigest: string): void {
  const applied = sanitizer.applied;
  const required = sanitizer.required;
  if (typeof applied !== "boolean" || typeof required !== "boolean") invalid();
  if (required && !applied) {
    throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer binding is incomplete");
  }
  const sanitizerId = nullableString(sanitizer.id);
  const protocolVersion = sanitizer.protocolVersion;
  if (protocolVersion !== null && protocolVersion !== 1) invalid();
  const policyVersion = sanitizer.policyVersion;
  const policyDigest = nullableDigest(sanitizer.policyDigest);
  const targetDigest = nullableDigest(sanitizer.policyTargetIdentityDigest);
  const bindingDigest = nullableDigest(sanitizer.policyBindingDigest);
  const bindingIdentity = parsePolicyBindingIdentity(sanitizer.policyBindingIdentity);
  if (!applied) {
    if (
      sanitizerId !== null ||
      protocolVersion !== null ||
      policyVersion !== null ||
      policyDigest !== null ||
      targetDigest !== null ||
      bindingIdentity !== null ||
      bindingDigest !== null
    ) {
      throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer binding is invalid");
    }
    return;
  }
  if (
    sanitizerId === null ||
    !isSafeLabel(sanitizerId) ||
    protocolVersion !== 1 ||
    typeof policyVersion !== "number" ||
    !Number.isSafeInteger(policyVersion) ||
    policyVersion < 1 ||
    policyDigest === null ||
    targetDigest === null ||
    bindingIdentity === null ||
    bindingIdentity.caseInputIdentityDigest !== identityDigest ||
    bindingIdentity.policyVersion !== policyVersion ||
    bindingIdentity.policyDigest !== policyDigest ||
    targetDigest !== identityDigest ||
    bindingDigest === null ||
    bindingDigest !==
      computePolicyBindingDigest({
        caseInputIdentityDigest: identityDigest,
        policyVersion,
        policyDigest,
      })
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt sanitizer binding is invalid");
  }
}

function parsePolicyBindingIdentity(
  value: JsonValue | undefined,
): SanitizerPolicyBindingIdentity | null {
  if (value === null) return null;
  const identity = requiredObject(value);
  assertKeys(identity, ["caseInputIdentityDigest", "policyVersion", "policyDigest"]);
  const policyVersion = identity.policyVersion;
  if (typeof policyVersion !== "number" || !Number.isSafeInteger(policyVersion) || policyVersion < 1) {
    invalid();
  }
  return {
    caseInputIdentityDigest: requiredDigest(identity.caseInputIdentityDigest),
    policyVersion,
    policyDigest: requiredDigest(identity.policyDigest),
  };
}

function parseRequested(value: JsonValue | undefined): RequestedExecutionSettings {
  const requested = requiredObject(value);
  assertKeys(requested, ["model", "effort", "maxTokens"]);
  const model = nullableSafeLabel(requested.model);
  const effort = nullableSafeLabel(requested.effort);
  const maxTokens = requested.maxTokens;
  if (maxTokens === null) return { model, effort, maxTokens: null };
  if (typeof maxTokens !== "number" || !Number.isSafeInteger(maxTokens) || maxTokens < 1) invalid();
  return { model, effort, maxTokens };
}

function parseProvenance(value: JsonValue | undefined): void {
  const provenance = requiredObject(value);
  assertKeys(provenance, ["harnessVersion", "harnessCommit", "promptVersion", "preprocessVersion", "sourceCommit"]);
  requiredSafeLabel(provenance.harnessVersion);
  nullableSafeLabel(provenance.harnessCommit);
  requiredSafeLabel(provenance.promptVersion);
  requiredSafeLabel(provenance.preprocessVersion);
  nullableSafeLabel(provenance.sourceCommit);
}

function parseResponded(value: JsonValue | undefined): void {
  const responded = requiredObject(value);
  assertKeys(responded, ["model", "effort", "usage", "stopReason"]);
  nullableSafeLabel(responded.model);
  nullableSafeLabel(responded.effort);
  parseUsage(responded.usage);
  nullableSafeLabel(responded.stopReason);
}

function parseUsage(value: JsonValue | undefined): void {
  const usage = requiredObject(value);
  assertKeys(usage, ["available", "inputTokens", "outputTokens", "totalTokens"]);
  if (typeof usage.available !== "boolean") invalid();
  for (const key of ["inputTokens", "outputTokens", "totalTokens"] as const) {
    const tokenValue = usage[key];
    if (tokenValue !== undefined && tokenValue !== null) {
      if (typeof tokenValue !== "number" || !Number.isSafeInteger(tokenValue) || tokenValue < 0) {
        invalid();
      }
    }
  }
}

function parseApprovalMetadata(
  approval: Record<string, JsonValue>,
  requirement: SanitizerRequirementDecisionV1,
): {
  required: boolean;
  applied: boolean;
  gateId: string | null;
  protocolVersion: 1 | null;
  snapshotDigest: string | null;
  runtimeBindingDigest: string | null;
  runtimeBindingIdentity: string | null;
  approvedScopeDigest: string | null;
  approvedScopeIdentity: string | null;
  phase: string | null;
} {
  const required = approval.required;
  const applied = approval.applied;
  if (typeof required !== "boolean" || typeof applied !== "boolean") invalid();
  if (required && !applied) {
    throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is incomplete");
  }
  const gateId = nullableSafeLabel(approval.gateId);
  const protocolVersion = approval.protocolVersion;
  if (protocolVersion !== null && protocolVersion !== 1) invalid();
  const snapshotDigest = nullableDigest(approval.snapshotDigest);
  const runtimeBindingDigest = nullableDigest(approval.runtimeBindingDigest);
  const runtimeBindingIdentity = nullableSafeLabel(approval.runtimeBindingIdentity);
  const approvedScopeDigest = nullableDigest(approval.approvedScopeDigest);
  const approvedScopeIdentity = nullableSafeLabel(approval.approvedScopeIdentity);
  const phase = nullableSafeLabel(approval.phase);
  const requirementVerifierId = nullableSafeLabel(approval.requirementVerifierId);
  const requirementVerifierVersion = nullableSafeLabel(approval.requirementVerifierVersion);
  const consumerSourceCommit = nullableSafeLabel(approval.consumerSourceCommit);
  const requirementDecisionDigest = nullableDigest(approval.requirementDecisionDigest);
  const sanitizerRequirementVersion = approval.sanitizerRequirementVersion;
  const sanitizerRequired = approval.sanitizerRequired;
  const policyRequired = approval.policyRequired;
  const sanitizerRequirementReason = nullableSafeLabel(approval.sanitizerRequirementReason);
  const checkedAt = nullableDateTime(approval.checkedAt);
  const expiresAt = nullableDateTime(approval.expiresAt);
  const reasonCode = nullableSafeLabel(approval.reasonCode);
  if (applied) {
    if (
      gateId === null ||
      protocolVersion !== 1 ||
      snapshotDigest === null ||
      runtimeBindingDigest === null ||
      runtimeBindingIdentity === null ||
      approvedScopeDigest === null ||
      approvedScopeIdentity === null ||
      phase === null ||
      requirementVerifierId !== requirement.requirementVerifierId ||
      requirementVerifierVersion !== requirement.requirementVerifierVersion ||
      consumerSourceCommit !== requirement.consumerSourceCommit ||
      requirementDecisionDigest !== requirement.requirementDecisionDigest ||
      sanitizerRequirementVersion !== requirement.sanitizerRequirementVersion ||
      sanitizerRequired !== requirement.sanitizerRequired ||
      policyRequired !== requirement.policyRequired ||
      sanitizerRequirementReason !== requirement.sanitizerRequirementReason
    ) {
      throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is invalid");
    }
  } else if (
    required ||
    gateId !== null ||
    protocolVersion !== null ||
    snapshotDigest !== null ||
    runtimeBindingDigest !== null ||
    runtimeBindingIdentity !== null ||
    approvedScopeDigest !== null ||
    approvedScopeIdentity !== null ||
    phase !== null ||
    requirementVerifierId !== null ||
    requirementVerifierVersion !== null ||
    consumerSourceCommit !== null ||
    requirementDecisionDigest !== null ||
    sanitizerRequirementVersion !== null ||
    sanitizerRequired !== null ||
    policyRequired !== null ||
    sanitizerRequirementReason !== null ||
    checkedAt !== null ||
    expiresAt !== null ||
    reasonCode !== null
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is invalid");
  }
  return {
    required,
    applied,
    gateId,
    protocolVersion: protocolVersion === 1 ? 1 : null,
    snapshotDigest,
    runtimeBindingDigest,
    runtimeBindingIdentity,
    approvedScopeDigest,
    approvedScopeIdentity,
    phase,
  };
}

function parseSanitizerFindingPathAllowlist(
  sanitizer: Record<string, JsonValue>,
): readonly string[] {
  if (sanitizer.findingPathAllowlistVersion !== 1) invalid();
  const source = sanitizer.allowedFindingPathPatterns;
  let patterns: readonly string[];
  try {
    patterns = snapshotSanitizerFindingPathPatterns(source);
  } catch {
    invalid();
  }
  if (!Array.isArray(source) || source.some((value, index) => value !== patterns[index])) invalid();
  const digest = requiredDigest(sanitizer.findingPathAllowlistDigest);
  if (computeSanitizerFindingPathAllowlistDigest(patterns) !== digest) {
    throw new RunnerError(
      "attempt_identity_mismatch",
      "attempt sanitizer finding path binding is invalid",
    );
  }
  return patterns;
}

function parseSanitizerFindings(
  value: JsonValue | undefined,
  allowedFindingPathPatterns: readonly string[],
): void {
  if (!Array.isArray(value) || value.length > 100) invalid();
  for (const findingValue of value) {
    const finding = requiredObject(findingValue);
    assertKeys(finding, ["code", "severity", "classification", "hardGate", "path"]);
    requiredSafeLabel(finding.code);
    if (
      finding.severity !== "info" &&
      finding.severity !== "warning" &&
      finding.severity !== "error"
    ) {
      invalid();
    }
    requiredSafeLabel(finding.classification);
    if (typeof finding.hardGate !== "boolean") invalid();
    if (
      finding.path !== null &&
      (!isSanitizerFindingPath(finding.path) ||
        !sanitizerFindingPathMatchesPatterns(finding.path, allowedFindingPathPatterns))
    ) {
      invalid();
    }
  }
}

function parseStages(value: JsonValue | undefined, sanitizerRequired: boolean): void {
  const stages = requiredObject(value);
  const requiredNames = [
    "approval",
    "provider",
    "parse",
    "schemaValidation",
  ] as const;
  const conditionalNames = ["policyTargetPreflight", "sanitizer", "targetBinding"] as const;
  assertKeys(stages, sanitizerRequired ? [...requiredNames, ...conditionalNames] : [...requiredNames]);
  for (const name of requiredNames) {
    const stage = requiredObject(stages[name]);
    assertKeys(stage, ["status", "errorCode"]);
    if (stage.status !== "passed" || stage.errorCode !== null) invalid();
  }
  for (const name of conditionalNames) {
    const stageValue = stages[name];
    if (sanitizerRequired) {
      const stage = requiredObject(stageValue);
      assertKeys(stage, ["status", "errorCode"]);
      if (stage.status !== "passed" || stage.errorCode !== null) invalid();
    } else if (stageValue !== undefined) {
      invalid();
    }
  }
}

function assertKeys(value: Record<string, JsonValue>, allowed: string[]): void {
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) invalid();
  }
}

function requiredObject(value: JsonValue | undefined): Record<string, JsonValue> {
  if (!isJsonObject(value)) invalid();
  return value;
}

function requiredString(value: JsonValue | undefined): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 240) invalid();
  return value;
}

function requiredSafeLabel(value: JsonValue | undefined): string {
  const result = requiredString(value);
  if (!isSafeLabel(result)) invalid();
  return result;
}

function requiredCaseId(value: JsonValue | undefined): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 128 ||
    !CASE_ID_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function requiredMediaType(value: JsonValue | undefined): string {
  const result = requiredString(value);
  if (!/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u.test(result)) invalid();
  return result;
}

function requiredDigest(value: JsonValue | undefined): string {
  const result = requiredString(value);
  if (!SHA256_PATTERN.test(result)) invalid();
  return result;
}

function nullableDigest(value: JsonValue | undefined): string | null {
  const result = nullableString(value);
  if (result !== null && !SHA256_PATTERN.test(result)) invalid();
  return result;
}

function nullableString(value: JsonValue | undefined): string | null {
  if (value === null) return null;
  if (typeof value === "string" && value.length <= 240) return value;
  invalid();
}

function nullableSafeLabel(value: JsonValue | undefined): string | null {
  const result = nullableString(value);
  if (result !== null && !isSafeLabel(result)) invalid();
  return result;
}

function nullableProtocolVersion(value: JsonValue | undefined): 1 | null {
  if (value === null) return null;
  if (value === 1) return 1;
  invalid();
}

function nullableDateTime(value: JsonValue | undefined): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !isDateTime(value)) invalid();
  return value;
}

function isDateTime(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/u.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  if (match[7] !== "Z" && (Number(match[8]) > 23 || Number(match[9]) > 59)) return false;
  return true;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function sameFile(left: { dev: number; ino: number }, right: { dev: number; ino: number }): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function toFileIdentity(value: { dev: number; ino: number }): FileIdentity {
  return { dev: value.dev, ino: value.ino };
}

function isPrivateDirectory(value: {
  isDirectory: () => boolean;
  isSymbolicLink: () => boolean;
  mode: number;
}): boolean {
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    (process.platform === "win32" || (value.mode & 0o077) === 0)
  );
}

function isErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

function isSafeLabel(value: string): boolean {
  return value.length > 0 && value.length <= 64 && /^[A-Za-z0-9._-]+$/u.test(value);
}

function invalid(): never {
  throw new RunnerError("attempt_invalid", "attempt manifest is invalid");
}
