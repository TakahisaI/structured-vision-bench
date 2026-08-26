import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../bundle/json.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  computeRunIdentity,
  type CaseInputIdentity,
} from "./identity.js";
import { RunnerError } from "./errors.js";
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
    providerId: string;
    route: string;
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
  };
  sanitizer: {
    required: boolean;
    applied: boolean;
    id: string | null;
    protocolVersion: 1 | null;
    policyVersion: number | null;
    policyDigest: string | null;
    policyTargetIdentityDigest: string | null;
    policyBindingIdentity: SanitizerPolicyBindingIdentity | null;
    policyBindingDigest: string | null;
    findings: SanitizerFinding[];
  };
  stages: {
    policyTargetPreflight: AttemptStage;
    approval: AttemptStage;
    provider: AttemptStage;
    parse: AttemptStage;
    sanitizer: AttemptStage;
    targetBinding: AttemptStage;
    schemaValidation: AttemptStage;
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

export type AttemptManifestBase = Omit<AttemptManifest, "document">;

export type AttemptReadResult = {
  manifest: AttemptManifest;
  document: JsonValue;
};

export function encodeAttemptDocument(document: JsonValue): {
  bytes: Buffer;
  sha256: string;
} {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(document, null, 2);
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
  attemptDirectory: string,
  manifest: AttemptManifestBase,
  document: JsonValue,
): Promise<{ documentSha256: string }> {
  const encoded = encodeAttemptDocument(document);
  const completeManifest: AttemptManifest = {
    ...manifest,
    document: { path: "document.json", sha256: encoded.sha256 },
  };
  const documentPart = path.join(attemptDirectory, "document.json.part");
  const manifestPart = path.join(attemptDirectory, "attempt.json.part");
  let createdDirectory = false;
  try {
    await mkdir(attemptDirectory, { recursive: false });
    createdDirectory = true;
    await writeFile(documentPart, encoded.bytes, { flag: "wx" });
    await rename(documentPart, path.join(attemptDirectory, "document.json"));
    const manifestBytes = Buffer.from(`${JSON.stringify(completeManifest, null, 2)}\n`, "utf8");
    if (manifestBytes.length > MAX_ATTEMPT_MANIFEST_BYTES) {
      throw new RunnerError("attempt_write_failed", "attempt manifest exceeds the size limit");
    }
    await writeFile(manifestPart, manifestBytes, { flag: "wx" });
    await rename(manifestPart, path.join(attemptDirectory, "attempt.json"));
    return { documentSha256: encoded.sha256 };
  } catch (error) {
    await rm(documentPart, { force: true });
    await rm(manifestPart, { force: true });
    if (createdDirectory) await rm(attemptDirectory, { recursive: true, force: true });
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("attempt_write_failed", "attempt files could not be written");
  }
}

export async function readAttempt(attemptDirectory: string): Promise<AttemptReadResult> {
  await assertAttemptDirectory(attemptDirectory);
  const manifestFile = await readAttemptJson(path.join(attemptDirectory, "attempt.json"));
  const manifest = parseAttemptManifest(manifestFile.value);
  const documentFile = await readAttemptJson(path.join(attemptDirectory, manifest.document.path), true);
  if (createHash("sha256").update(documentFile.bytes).digest("hex") !== manifest.document.sha256) {
    throw new RunnerError(
      "attempt_document_digest_mismatch",
      "attempt document digest does not match its manifest",
    );
  }
  return { manifest, document: documentFile.value };
}

async function assertAttemptDirectory(directory: string): Promise<void> {
  try {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error();
  } catch {
    throw new RunnerError("attempt_invalid", "attempt directory is invalid");
  }
}

async function readAttemptJson(
  file: string,
  document = false,
): Promise<{ value: JsonValue; bytes: Buffer }> {
  const maxBytes = document ? MAX_DOCUMENT_BYTES : MAX_ATTEMPT_MANIFEST_BYTES;
  let info;
  try {
    info = await lstat(file);
  } catch {
    throw new RunnerError("attempt_invalid", "attempt file is missing");
  }
  if (info.isSymbolicLink() || !info.isFile() || info.size > maxBytes) {
    throw new RunnerError("attempt_invalid", "attempt file is invalid");
  }
  let bytes: Buffer;
  try {
    bytes = await readFile(file);
  } catch {
    throw new RunnerError("attempt_invalid", "attempt file could not be read");
  }
  try {
    return { value: parseJson(decodeUtf8Strict(bytes, "attempt file"), "attempt file"), bytes };
  } catch {
    throw new RunnerError("attempt_invalid", "attempt file is invalid");
  }
}

function parseAttemptManifest(value: JsonValue): AttemptManifest {
  const manifest = requiredObject(value);
  assertKeys(manifest, [
    "attemptVersion",
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
    "sanitizer",
    "stages",
    "document",
    "timing",
  ]);
  if (manifest.attemptVersion !== ATTEMPT_VERSION || manifest.bundleVersion !== 1) invalid();
  const attemptId = requiredDigest(manifest.attemptId);
  const runId = requiredDigest(manifest.runId);
  if (attemptId !== runId) invalid();
  const caseId = requiredString(manifest.caseId);
  const documentKind = requiredString(manifest.documentKind);
  const bundleManifestDigest = requiredDigest(manifest.bundleManifestDigest);
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
    typeof timing.durationMs !== "number" ||
    !Number.isSafeInteger(timing.durationMs) ||
    timing.durationMs < 0
  ) {
    invalid();
  }
  parseProvenance(manifest.provenance);
  const sanitizer = requiredObject(manifest.sanitizer);
  assertKeys(sanitizer, [
    "required",
    "applied",
    "id",
    "protocolVersion",
    "policyVersion",
    "policyDigest",
    "policyTargetIdentityDigest",
    "policyBindingIdentity",
    "policyBindingDigest",
    "findings",
  ]);
  parseSanitizerFindings(sanitizer.findings);
  validateSanitizerBinding(sanitizer, identity.digest);
  const run = requiredObject(manifest.run);
  assertKeys(run, ["providerId", "route", "requested", "responded"]);
  parseResponded(run.responded);
  const providerId = requiredString(run.providerId);
  const route = requiredString(run.route);
  if (!isSafeLabel(providerId) || !isSafeLabel(route)) invalid();
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
  ]);
  parseApprovalMetadata(approval);
  const approvalBinding = parseAppliedBinding(approval);
  const sanitizerBindingDigest = nullableString(sanitizer.policyBindingDigest);
  parseStages(manifest.stages);
  if (
    computeRunIdentity({
      caseInputIdentityDigest: identity.digest,
      bundleManifestDigest,
      providerId,
      providerRoute: route,
      requestedModel: requested.model,
      requestedEffort: requested.effort,
      maxTokens: requested.maxTokens,
      approvalBindingDigest: approvalBinding.digest,
      approvalBindingIdentity: approvalBinding.identity,
      sanitizerBindingDigest,
    }) !== runId
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt run identity is invalid");
  }
  // The writer creates this shape from typed values. Re-check the identity and
  // binding invariants here, then return the parsed value for normal consumers.
  return manifest as unknown as AttemptManifest;
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
    mediaType: requiredString(input.mediaType),
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
    caseId: requiredString(identity.caseId),
    documentKind: requiredString(identity.documentKind),
    preparedImage: {
      mediaType: requiredString(preparedImage.mediaType),
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
  const model = nullableString(requested.model);
  const effort = nullableString(requested.effort);
  const maxTokens = requested.maxTokens;
  if (maxTokens === null) return { model, effort, maxTokens: null };
  if (typeof maxTokens !== "number" || !Number.isSafeInteger(maxTokens) || maxTokens < 1) invalid();
  return { model, effort, maxTokens };
}

function parseAppliedBinding(approval: Record<string, JsonValue>): {
  digest: string | null;
  identity: string | null;
} {
  const applied = approval.applied;
  if (typeof applied !== "boolean") invalid();
  const binding = nullableString(approval.runtimeBindingDigest);
  const identity = nullableString(approval.runtimeBindingIdentity);
  if (!applied && (binding !== null || identity !== null)) {
    throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is invalid");
  }
  return { digest: binding, identity };
}

function parseProvenance(value: JsonValue | undefined): void {
  const provenance = requiredObject(value);
  assertKeys(provenance, ["harnessVersion", "harnessCommit", "promptVersion", "preprocessVersion", "sourceCommit"]);
  requiredString(provenance.harnessVersion);
  nullableString(provenance.harnessCommit);
  requiredString(provenance.promptVersion);
  requiredString(provenance.preprocessVersion);
  nullableString(provenance.sourceCommit);
}

function parseResponded(value: JsonValue | undefined): void {
  const responded = requiredObject(value);
  assertKeys(responded, ["model", "effort", "usage", "stopReason"]);
  nullableString(responded.model);
  nullableString(responded.effort);
  parseUsage(responded.usage);
  nullableString(responded.stopReason);
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

function parseApprovalMetadata(approval: Record<string, JsonValue>): void {
  const required = approval.required;
  const applied = approval.applied;
  if (typeof required !== "boolean" || typeof applied !== "boolean") invalid();
  if (required && !applied) {
    throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is incomplete");
  }
  const gateId = nullableString(approval.gateId);
  const protocolVersion = approval.protocolVersion;
  if (protocolVersion !== null && protocolVersion !== 1) invalid();
  const snapshotDigest = nullableDigest(approval.snapshotDigest);
  const runtimeBindingDigest = nullableDigest(approval.runtimeBindingDigest);
  const runtimeBindingIdentity = nullableString(approval.runtimeBindingIdentity);
  if (applied) {
    if (
      gateId === null ||
      protocolVersion !== 1 ||
      snapshotDigest === null ||
      runtimeBindingDigest === null
    ) {
      invalid();
    }
  } else if (
    gateId !== null ||
    protocolVersion !== null ||
    snapshotDigest !== null ||
    runtimeBindingDigest !== null ||
    runtimeBindingIdentity !== null
  ) {
    throw new RunnerError("attempt_identity_mismatch", "attempt approval binding is invalid");
  }
}

function parseSanitizerFindings(value: JsonValue | undefined): void {
  if (!Array.isArray(value) || value.length > 100) invalid();
  for (const findingValue of value) {
    const finding = requiredObject(findingValue);
    assertKeys(finding, ["code", "severity", "classification", "hardGate", "path"]);
    requiredString(finding.code);
    if (
      finding.severity !== "info" &&
      finding.severity !== "warning" &&
      finding.severity !== "error"
    ) {
      invalid();
    }
    requiredString(finding.classification);
    if (typeof finding.hardGate !== "boolean") invalid();
    nullableString(finding.path);
  }
}

function parseStages(value: JsonValue | undefined): void {
  const stages = requiredObject(value);
  const names = [
    "policyTargetPreflight",
    "approval",
    "provider",
    "parse",
    "sanitizer",
    "targetBinding",
    "schemaValidation",
  ] as const;
  assertKeys(stages, [...names]);
  for (const name of names) {
    const stage = requiredObject(stages[name]);
    assertKeys(stage, ["status", "errorCode"]);
    if (stage.status !== "passed" || stage.errorCode !== null) invalid();
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
  if (typeof value !== "string" || value.length === 0) invalid();
  return value;
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
  if (typeof value === "string") return value;
  invalid();
}

function isSafeLabel(value: string): boolean {
  return value.length > 0 && value.length <= 64 && /^[A-Za-z0-9._-]+$/u.test(value);
}

function invalid(): never {
  throw new RunnerError("attempt_invalid", "attempt manifest is invalid");
}
