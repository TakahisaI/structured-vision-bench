import { createHash } from "node:crypto";

import {
  decodeUtf8Strict,
  isJsonObject,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import {
  ATTEMPT_IDENTITY_VERSION,
  RUN_IDENTITY_VERSION,
  SANITIZER_FINDING_PATH_ALLOWLIST_VERSION,
  computeAttemptIdentity,
  computePolicyBindingDigest,
  computeRunIdentity,
  computeSanitizerExecutionBindingDigest,
  computeSanitizerFindingPathAllowlistDigest,
  computeSanitizerRequirementDigest,
} from "../runner/identity.js";
import { snapshotSanitizerFindingPathPatterns } from "../runner/sanitizer-finding-path.js";
import {
  computeCasePolicyMapDigest,
  computeSuitePlanDigest,
  deriveSuiteAttemptKey,
  type SuiteCasePlan,
  type SuitePreflightPlan,
} from "./preflight.js";
import { computeCasePolicyMapIdentityDigest } from "./case-policy-map-identity.js";

export const SUITE_RUN_MANIFEST_VERSION = 1 as const;
export const SUITE_RUN_IDENTITY_VERSION = 1 as const;
export const MAX_SUITE_RUN_MANIFEST_BYTES = 4 * 1024 * 1024;

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const MAX_CASES = 1000;
const MAX_REPEATS = 1000;
const MAX_SLOTS = 10_000;

export type SuiteRunManifestErrorCode =
  | "suite_run_manifest_invalid"
  | "suite_run_identity_mismatch";

export class SuiteRunManifestError extends Error {
  readonly code: SuiteRunManifestErrorCode;

  constructor(code: SuiteRunManifestErrorCode, message: string) {
    super(message);
    this.name = "SuiteRunManifestError";
    this.code = code;
  }
}

export type SuiteRunCaseIdentity = Readonly<{
  caseIndex: number;
  bundleManifestDigest: string;
  caseInputIdentityVersion: 1;
  caseInputIdentityDigest: string;
  sanitizerRequirement: Readonly<{
    sanitizerRequirementVersion: 1;
    sanitizerRequired: boolean;
    policyRequired: boolean;
    sanitizerRequirementReason: string;
    requirementVerifierId: string;
    requirementVerifierVersion: string;
    consumerSourceCommit: string | null;
    requirementDecisionDigest: string;
  }>;
  policy: Readonly<{
    policyVersion: number;
    policyDigest: string;
    policyTargetIdentityDigest: string;
    policyBindingDigest: string;
  }> | null;
}>;

export type SuiteRunSlotIdentity = Readonly<{
  caseIndex: number;
  repeatIndex: number;
  attemptKey: string;
  runIdentityVersion: 1;
  runId: string;
  attemptIdentityVersion: 1;
  attemptId: string;
}>;

export type SuiteRunManifestIdentity = Readonly<{
  suiteRunManifestVersion: 1;
  suiteRunIdentityVersion: 1;
  suite: Readonly<{
    suiteVersion: 1;
    suiteId: string;
    suiteDigest: string;
    suitePlanDigest: string;
    casePolicyMapDigest: string;
  }>;
  provider: Readonly<{
    id: string;
    route: string;
    implementationVersion: string | null;
    protocolVersion: string | null;
    requested: Readonly<{
      model: string | null;
      effort: string | null;
      maxTokens: number | null;
    }>;
  }>;
  phase: string;
  repeat: number;
  requirementVerifier: Readonly<{
    id: string;
    version: string;
    consumerSourceCommit: string | null;
  }>;
  approval: Readonly<{
    required: boolean;
    gateId: string;
    protocolVersion: 1;
    snapshotDigest: string;
    runtimeBindingIdentity: string;
    runtimeBindingDigest: string;
    approvedScopeIdentity: string;
    approvedScopeDigest: string;
    phase: string;
  }> | null;
  sanitizer: Readonly<{
    id: string;
    protocolVersion: 1;
    findingPathAllowlistVersion: 1;
    findingPathAllowlistDigest: string;
    allowedFindingPathPatterns: readonly string[];
    failureCodes: readonly string[];
  }> | null;
  cases: readonly SuiteRunCaseIdentity[];
  slots: readonly SuiteRunSlotIdentity[];
}>;

export type SuiteRunManifest = SuiteRunManifestIdentity &
  Readonly<{
    suiteRunId: string;
  }>;

export type ReadSuiteRunManifestOptions = Readonly<{
  expectedSuiteRunId?: string;
}>;

/** Projects a preflighted plan into the value-free immutable suite-run contract. */
export function createSuiteRunManifest(plan: SuitePreflightPlan): SuiteRunManifest {
  try {
    const source = snapshotPlainData(plan);
    if (!isJsonObject(source)) throw new Error();
    const expectedPlanKeys = [
      "suiteVersion",
      "suiteId",
      "suiteDigest",
      "suitePlanDigest",
      "casePolicyMapDigest",
      "provider",
      "phase",
      "repeat",
      "requirementVerifier",
      ...(source.approval === undefined ? [] : ["approval"]),
      ...(source.sanitizer === undefined ? [] : ["sanitizer"]),
      "cases",
      "slots",
    ];
    if (!hasExactKeys(source, expectedPlanKeys)) throw new Error();
    const rawCases = source.cases;
    if (!Array.isArray(rawCases)) throw new Error();
    const expectedMapDigest = computeCasePolicyMapDigest(
      rawCases as unknown as readonly SuiteCasePlan[],
    );
    if (source.casePolicyMapDigest !== expectedMapDigest) throw new Error();

    const identity = snapshotIdentity({
      suiteRunManifestVersion: SUITE_RUN_MANIFEST_VERSION,
      suiteRunIdentityVersion: SUITE_RUN_IDENTITY_VERSION,
      suite: {
        suiteVersion: source.suiteVersion,
        suiteId: source.suiteId,
        suiteDigest: source.suiteDigest,
        suitePlanDigest: source.suitePlanDigest,
        casePolicyMapDigest: source.casePolicyMapDigest,
      },
      provider: source.provider,
      phase: source.phase,
      repeat: source.repeat,
      requirementVerifier: source.requirementVerifier,
      approval: projectApproval(source.approval),
      sanitizer: projectSanitizer(source.sanitizer),
      cases: rawCases.map(projectCase),
      slots: source.slots,
    }, true);
    const suiteRunId = computeIdentityDigest(identity);
    return Object.freeze({
      suiteRunManifestVersion: identity.suiteRunManifestVersion,
      suiteRunIdentityVersion: identity.suiteRunIdentityVersion,
      suiteRunId,
      suite: identity.suite,
      provider: identity.provider,
      phase: identity.phase,
      repeat: identity.repeat,
      requirementVerifier: identity.requirementVerifier,
      approval: identity.approval,
      sanitizer: identity.sanitizer,
      cases: identity.cases,
      slots: identity.slots,
    });
  } catch (error) {
    if (error instanceof SuiteRunManifestError) throw error;
    throw invalidManifest();
  }
}

/** Recomputes the suite-level identity from all immutable manifest fields. */
export function computeSuiteRunIdentity(manifest: SuiteRunManifest): string {
  try {
    const snapshot = snapshotManifest(manifest, false);
    return computeIdentityDigest(toIdentity(snapshot));
  } catch (error) {
    if (error instanceof SuiteRunManifestError) throw error;
    throw invalidManifest();
  }
}

/** Encodes one validated manifest with deterministic member order and one trailing newline. */
export function encodeSuiteRunManifest(manifest: SuiteRunManifest): Buffer {
  try {
    const snapshot = snapshotManifest(manifest, true);
    const bytes = Buffer.from(`${JSON.stringify(snapshot)}\n`, "utf8");
    if (bytes.length > MAX_SUITE_RUN_MANIFEST_BYTES) throw invalidManifest();
    return bytes;
  } catch (error) {
    if (error instanceof SuiteRunManifestError) throw error;
    throw invalidManifest();
  }
}

/** Strictly reads suite-run bytes without opening files or starting external work. */
export function readSuiteRunManifest(
  bytes: Uint8Array,
  options: ReadSuiteRunManifestOptions = {},
): SuiteRunManifest {
  try {
    const byteSnapshot = snapshotBytes(bytes);
    if (
      byteSnapshot.byteLength === 0 ||
      byteSnapshot.byteLength > MAX_SUITE_RUN_MANIFEST_BYTES
    ) {
      throw invalidManifest();
    }
    const expectedSuiteRunId = snapshotExpectedSuiteRunId(options);
    const value = parseJson(
      decodeUtf8Strict(byteSnapshot, "suite run manifest"),
      "suite run manifest",
    );
    const manifest = snapshotManifest(value, true);
    if (
      expectedSuiteRunId !== undefined &&
      manifest.suiteRunId !== expectedSuiteRunId
    ) {
      throw new SuiteRunManifestError(
        "suite_run_identity_mismatch",
        "suite run identity does not match",
      );
    }
    return manifest;
  } catch (error) {
    if (error instanceof SuiteRunManifestError) throw error;
    throw invalidManifest();
  }
}

function snapshotExpectedSuiteRunId(
  options: ReadSuiteRunManifestOptions,
): string | undefined {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    Object.getPrototypeOf(options) !== Object.prototype ||
    Object.getOwnPropertySymbols(options).length > 0
  ) {
    throw invalidManifest();
  }
  const names = Object.getOwnPropertyNames(options);
  if (names.length === 0) return undefined;
  if (names.length !== 1 || names[0] !== "expectedSuiteRunId") throw invalidManifest();
  const descriptor = Object.getOwnPropertyDescriptor(options, "expectedSuiteRunId");
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    !descriptor.enumerable ||
    !isDigest(descriptor.value)
  ) {
    throw invalidManifest();
  }
  return descriptor.value;
}

function snapshotBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) throw invalidManifest();
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
    throw invalidManifest();
  }
  const byteLength = Reflect.apply(byteLengthGetter, value, []) as number;
  if (byteLength === 0 || byteLength > MAX_SUITE_RUN_MANIFEST_BYTES) {
    throw invalidManifest();
  }
  const byteOffset = Reflect.apply(byteOffsetGetter, value, []) as number;
  const buffer = Reflect.apply(bufferGetter, value, []) as ArrayBufferLike;
  Reflect.apply(arrayBufferByteLengthGetter, buffer, []);
  const source = new Uint8Array(buffer as ArrayBuffer, byteOffset, byteLength);
  const snapshot = new Uint8Array(byteLength);
  Uint8Array.prototype.set.call(snapshot, source);
  return snapshot;
}

function snapshotManifest(value: unknown, verifyIdentity: boolean): SuiteRunManifest {
  const source = snapshotPlainData(value);
  if (
    !isJsonObject(source) ||
    !hasExactKeys(source, [
      "suiteRunManifestVersion",
      "suiteRunIdentityVersion",
      "suiteRunId",
      "suite",
      "provider",
      "phase",
      "repeat",
      "requirementVerifier",
      "approval",
      "sanitizer",
      "cases",
      "slots",
    ]) ||
    !isDigest(source.suiteRunId)
  ) {
    throw invalidManifest();
  }
  const identity = snapshotIdentity({
    suiteRunManifestVersion: source.suiteRunManifestVersion,
    suiteRunIdentityVersion: source.suiteRunIdentityVersion,
    suite: source.suite,
    provider: source.provider,
    phase: source.phase,
    repeat: source.repeat,
    requirementVerifier: source.requirementVerifier,
    approval: source.approval,
    sanitizer: source.sanitizer,
    cases: source.cases,
    slots: source.slots,
  });
  const expected = computeIdentityDigest(identity);
  if (verifyIdentity && source.suiteRunId !== expected) {
    throw new SuiteRunManifestError(
      "suite_run_identity_mismatch",
      "suite run identity does not match",
    );
  }
  return Object.freeze({
    suiteRunManifestVersion: identity.suiteRunManifestVersion,
    suiteRunIdentityVersion: identity.suiteRunIdentityVersion,
    suiteRunId: source.suiteRunId,
    suite: identity.suite,
    provider: identity.provider,
    phase: identity.phase,
    repeat: identity.repeat,
    requirementVerifier: identity.requirementVerifier,
    approval: identity.approval,
    sanitizer: identity.sanitizer,
    cases: identity.cases,
    slots: identity.slots,
  });
}

function snapshotIdentity(
  value: unknown,
  allowDerivedSlots = false,
): SuiteRunManifestIdentity {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "suiteRunManifestVersion",
      "suiteRunIdentityVersion",
      "suite",
      "provider",
      "phase",
      "repeat",
      "requirementVerifier",
      "approval",
      "sanitizer",
      "cases",
      "slots",
    ]) ||
    value.suiteRunManifestVersion !== 1 ||
    value.suiteRunIdentityVersion !== 1 ||
    !isSafeLabel(value.phase) ||
    !isBoundedInteger(value.repeat, 1, MAX_REPEATS)
  ) {
    throw invalidManifest();
  }
  const suite = snapshotSuite(requiredJson(value, "suite"));
  const provider = snapshotProvider(requiredJson(value, "provider"));
  const verifier = snapshotRequirementVerifier(requiredJson(value, "requirementVerifier"));
  const approval = value.approval === null
    ? null
    : snapshotApproval(requiredJson(value, "approval"));
  const sanitizer = value.sanitizer === null
    ? null
    : snapshotSanitizer(requiredJson(value, "sanitizer"));
  if (approval !== null && approval.phase !== value.phase) throw invalidManifest();
  const cases = snapshotCases(requiredJson(value, "cases"), verifier, sanitizer !== null);
  if (computeCasePolicyMapIdentityDigest(cases) !== suite.casePolicyMapDigest) {
    throw invalidManifest();
  }
  const slots = snapshotSlots(
    requiredJson(value, "slots"),
    cases.length,
    value.repeat,
    {
      suite,
      provider,
      phase: value.phase,
      approval,
      sanitizer,
      cases,
    },
    allowDerivedSlots,
  );
  return Object.freeze({
    suiteRunManifestVersion: 1,
    suiteRunIdentityVersion: 1,
    suite,
    provider,
    phase: value.phase,
    repeat: value.repeat,
    requirementVerifier: verifier,
    approval,
    sanitizer,
    cases,
    slots,
  });
}

function snapshotSuite(value: JsonValue): SuiteRunManifestIdentity["suite"] {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "suiteVersion",
      "suiteId",
      "suiteDigest",
      "suitePlanDigest",
      "casePolicyMapDigest",
    ]) ||
    value.suiteVersion !== 1 ||
    !isSafeLabel(value.suiteId) ||
    !isDigest(value.suiteDigest) ||
    !isDigest(value.suitePlanDigest) ||
    !isDigest(value.casePolicyMapDigest) ||
    computeSuitePlanDigest(value.suiteDigest, value.casePolicyMapDigest) !==
      value.suitePlanDigest
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    suiteVersion: 1,
    suiteId: value.suiteId,
    suiteDigest: value.suiteDigest,
    suitePlanDigest: value.suitePlanDigest,
    casePolicyMapDigest: value.casePolicyMapDigest,
  });
}

function snapshotProvider(value: JsonValue): SuiteRunManifestIdentity["provider"] {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "id",
      "route",
      "implementationVersion",
      "protocolVersion",
      "requested",
    ]) ||
    !isSafeLabel(value.id) ||
    !isSafeLabel(value.route) ||
    !isNullableSafeLabel(value.implementationVersion) ||
    !isNullableSafeLabel(value.protocolVersion) ||
    !isJsonObject(value.requested) ||
    !hasExactKeys(value.requested, ["model", "effort", "maxTokens"]) ||
    !isNullableSafeLabel(value.requested.model) ||
    !isNullableSafeLabel(value.requested.effort) ||
    !isNullablePositiveInteger(value.requested.maxTokens)
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    id: value.id,
    route: value.route,
    implementationVersion: value.implementationVersion,
    protocolVersion: value.protocolVersion,
    requested: Object.freeze({
      model: value.requested.model,
      effort: value.requested.effort,
      maxTokens: value.requested.maxTokens,
    }),
  });
}

function snapshotRequirementVerifier(
  value: JsonValue,
): SuiteRunManifestIdentity["requirementVerifier"] {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, ["id", "version", "consumerSourceCommit"]) ||
    !isSafeLabel(value.id) ||
    !isSafeLabel(value.version) ||
    !isNullableSafeLabel(value.consumerSourceCommit)
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    id: value.id,
    version: value.version,
    consumerSourceCommit: value.consumerSourceCommit,
  });
}

function snapshotApproval(value: JsonValue): NonNullable<SuiteRunManifestIdentity["approval"]> {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "required",
      "gateId",
      "protocolVersion",
      "snapshotDigest",
      "runtimeBindingIdentity",
      "runtimeBindingDigest",
      "approvedScopeIdentity",
      "approvedScopeDigest",
      "phase",
    ]) ||
    typeof value.required !== "boolean" ||
    !isSafeLabel(value.gateId) ||
    value.protocolVersion !== 1 ||
    !isDigest(value.snapshotDigest) ||
    !isSafeLabel(value.runtimeBindingIdentity) ||
    !isDigest(value.runtimeBindingDigest) ||
    !isSafeLabel(value.approvedScopeIdentity) ||
    !isDigest(value.approvedScopeDigest) ||
    !isSafeLabel(value.phase)
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    required: value.required,
    gateId: value.gateId,
    protocolVersion: 1,
    snapshotDigest: value.snapshotDigest,
    runtimeBindingIdentity: value.runtimeBindingIdentity,
    runtimeBindingDigest: value.runtimeBindingDigest,
    approvedScopeIdentity: value.approvedScopeIdentity,
    approvedScopeDigest: value.approvedScopeDigest,
    phase: value.phase,
  });
}

function snapshotSanitizer(
  value: JsonValue,
): NonNullable<SuiteRunManifestIdentity["sanitizer"]> {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "id",
      "protocolVersion",
      "findingPathAllowlistVersion",
      "findingPathAllowlistDigest",
      "allowedFindingPathPatterns",
      "failureCodes",
    ]) ||
    !isSafeLabel(value.id) ||
    value.protocolVersion !== 1 ||
    value.findingPathAllowlistVersion !== 1 ||
    !isDigest(value.findingPathAllowlistDigest) ||
    !Array.isArray(value.failureCodes) ||
    value.failureCodes.length > 100 ||
    value.failureCodes.some((entry) => !isSafeLabel(entry)) ||
    new Set(value.failureCodes).size !== value.failureCodes.length
  ) {
    throw invalidManifest();
  }
  let patterns: readonly string[];
  try {
    patterns = snapshotSanitizerFindingPathPatterns(value.allowedFindingPathPatterns);
  } catch {
    throw invalidManifest();
  }
  const sourcePatterns = value.allowedFindingPathPatterns as JsonValue[];
  if (
    sourcePatterns.length !== patterns.length ||
    patterns.some((pattern, index) => sourcePatterns[index] !== pattern)
  ) {
    throw invalidManifest();
  }
  if (
    computeSanitizerFindingPathAllowlistDigest(patterns) !==
    value.findingPathAllowlistDigest
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    id: value.id,
    protocolVersion: 1,
    findingPathAllowlistVersion: SANITIZER_FINDING_PATH_ALLOWLIST_VERSION,
    findingPathAllowlistDigest: value.findingPathAllowlistDigest,
    allowedFindingPathPatterns: Object.freeze([...patterns]),
    failureCodes: Object.freeze([...(value.failureCodes as string[])]),
  });
}

function snapshotCases(
  value: JsonValue,
  verifier: SuiteRunManifestIdentity["requirementVerifier"],
  sanitizerPresent: boolean,
): readonly SuiteRunCaseIdentity[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_CASES) {
    throw invalidManifest();
  }
  const cases = value.map((entry, index) => snapshotCase(entry, index, verifier));
  const required = cases.some((entry) => entry.sanitizerRequirement.sanitizerRequired);
  if (required !== sanitizerPresent) throw invalidManifest();
  return Object.freeze(cases);
}

function snapshotCase(
  value: JsonValue,
  index: number,
  verifier: SuiteRunManifestIdentity["requirementVerifier"],
): SuiteRunCaseIdentity {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "caseIndex",
      "bundleManifestDigest",
      "caseInputIdentityVersion",
      "caseInputIdentityDigest",
      "sanitizerRequirement",
      "policy",
    ]) ||
    value.caseIndex !== index ||
    !isDigest(value.bundleManifestDigest) ||
    value.caseInputIdentityVersion !== 1 ||
    !isDigest(value.caseInputIdentityDigest) ||
    !isJsonObject(value.sanitizerRequirement)
  ) {
    throw invalidManifest();
  }
  const requirement = value.sanitizerRequirement;
  if (
    !hasExactKeys(requirement, [
      "sanitizerRequirementVersion",
      "sanitizerRequired",
      "policyRequired",
      "sanitizerRequirementReason",
      "requirementVerifierId",
      "requirementVerifierVersion",
      "consumerSourceCommit",
      "requirementDecisionDigest",
    ]) ||
    requirement.sanitizerRequirementVersion !== 1 ||
    typeof requirement.sanitizerRequired !== "boolean" ||
    typeof requirement.policyRequired !== "boolean" ||
    requirement.sanitizerRequired !== requirement.policyRequired ||
    !isSafeLabel(requirement.sanitizerRequirementReason) ||
    requirement.requirementVerifierId !== verifier.id ||
    requirement.requirementVerifierVersion !== verifier.version ||
    requirement.consumerSourceCommit !== verifier.consumerSourceCommit ||
    !isDigest(requirement.requirementDecisionDigest) ||
    computeSanitizerRequirementDigest({
      sanitizerRequirementVersion: 1,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
      requirementVerifierId: requirement.requirementVerifierId,
      requirementVerifierVersion: requirement.requirementVerifierVersion,
      consumerSourceCommit: requirement.consumerSourceCommit,
    }) !== requirement.requirementDecisionDigest
  ) {
    throw invalidManifest();
  }
  const policy =
    value.policy === null
      ? null
      : snapshotPolicy(requiredJson(value, "policy"), value.caseInputIdentityDigest);
  if (requirement.policyRequired !== (policy !== null)) throw invalidManifest();
  return Object.freeze({
    caseIndex: index,
    bundleManifestDigest: value.bundleManifestDigest,
    caseInputIdentityVersion: 1,
    caseInputIdentityDigest: value.caseInputIdentityDigest,
    sanitizerRequirement: Object.freeze({
      sanitizerRequirementVersion: 1,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
      requirementVerifierId: requirement.requirementVerifierId,
      requirementVerifierVersion: requirement.requirementVerifierVersion,
      consumerSourceCommit: requirement.consumerSourceCommit,
      requirementDecisionDigest: requirement.requirementDecisionDigest,
    }),
    policy,
  });
}

function snapshotPolicy(
  value: JsonValue,
  caseInputIdentityDigest: string,
): NonNullable<SuiteRunCaseIdentity["policy"]> {
  if (
    !isJsonObject(value) ||
    !hasExactKeys(value, [
      "policyVersion",
      "policyDigest",
      "policyTargetIdentityDigest",
      "policyBindingDigest",
    ]) ||
    !isBoundedInteger(value.policyVersion, 1, Number.MAX_SAFE_INTEGER) ||
    !isDigest(value.policyDigest) ||
    value.policyTargetIdentityDigest !== caseInputIdentityDigest ||
    !isDigest(value.policyBindingDigest) ||
    computePolicyBindingDigest({
      caseInputIdentityDigest,
      policyVersion: value.policyVersion,
      policyDigest: value.policyDigest,
    }) !== value.policyBindingDigest
  ) {
    throw invalidManifest();
  }
  return Object.freeze({
    policyVersion: value.policyVersion,
    policyDigest: value.policyDigest,
    policyTargetIdentityDigest: value.policyTargetIdentityDigest,
    policyBindingDigest: value.policyBindingDigest,
  });
}

function snapshotSlots(
  value: JsonValue,
  caseCount: number,
  repeat: number,
  context: Readonly<{
    suite: SuiteRunManifestIdentity["suite"];
    provider: SuiteRunManifestIdentity["provider"];
    phase: string;
    approval: SuiteRunManifestIdentity["approval"];
    sanitizer: SuiteRunManifestIdentity["sanitizer"];
    cases: readonly SuiteRunCaseIdentity[];
  }>,
  allowDerivedSlots: boolean,
): readonly SuiteRunSlotIdentity[] {
  if (
    !Array.isArray(value) ||
    value.length !== caseCount * repeat ||
    value.length > MAX_SLOTS
  ) {
    throw invalidManifest();
  }
  const runIds = context.cases.map((entry) => computeCaseRunId(context, entry));
  const slots = value.map((entry, index) => {
    const caseIndex = Math.floor(index / repeat);
    const repeatIndex = index % repeat;
    const attemptKey = deriveSuiteAttemptKey(caseIndex, repeatIndex);
    const runId = runIds[caseIndex]!;
    const attemptId = computeAttemptIdentity({ runId, attemptKey }).attemptId;
    const expectedKeys = allowDerivedSlots
      ? ["caseIndex", "repeatIndex", "attemptKey"]
      : [
          "caseIndex",
          "repeatIndex",
          "attemptKey",
          "runIdentityVersion",
          "runId",
          "attemptIdentityVersion",
          "attemptId",
        ];
    if (
      !isJsonObject(entry) ||
      !hasExactKeys(entry, expectedKeys) ||
      entry.caseIndex !== caseIndex ||
      entry.repeatIndex !== repeatIndex ||
      entry.attemptKey !== attemptKey ||
      (!allowDerivedSlots &&
        (entry.runIdentityVersion !== RUN_IDENTITY_VERSION ||
          entry.runId !== runId ||
          entry.attemptIdentityVersion !== ATTEMPT_IDENTITY_VERSION ||
          entry.attemptId !== attemptId))
    ) {
      throw invalidManifest();
    }
    return Object.freeze({
      caseIndex,
      repeatIndex,
      attemptKey,
      runIdentityVersion: RUN_IDENTITY_VERSION,
      runId,
      attemptIdentityVersion: ATTEMPT_IDENTITY_VERSION,
      attemptId,
    });
  });
  return Object.freeze(slots);
}

function computeCaseRunId(
  context: Readonly<{
    suite: SuiteRunManifestIdentity["suite"];
    provider: SuiteRunManifestIdentity["provider"];
    phase: string;
    approval: SuiteRunManifestIdentity["approval"];
    sanitizer: SuiteRunManifestIdentity["sanitizer"];
  }>,
  entry: SuiteRunCaseIdentity,
): string {
  const approval = context.approval;
  const requirement = entry.sanitizerRequirement;
  const sanitizer =
    requirement.sanitizerRequired && entry.policy !== null
      ? context.sanitizer
      : null;
  if (requirement.sanitizerRequired && sanitizer === null) throw invalidManifest();
  const sanitizerBindingDigest =
    sanitizer === null || entry.policy === null
      ? null
      : computeSanitizerExecutionBindingDigest({
          policyBindingDigest: entry.policy.policyBindingDigest,
          findingPathAllowlistDigest: sanitizer.findingPathAllowlistDigest,
        });
  return computeRunIdentity({
    caseInputIdentityDigest: entry.caseInputIdentityDigest,
    bundleManifestDigest: entry.bundleManifestDigest,
    phase: context.phase,
    providerId: context.provider.id,
    providerRoute: context.provider.route,
    providerImplementationVersion: context.provider.implementationVersion,
    providerProtocolVersion: context.provider.protocolVersion,
    requestedModel: context.provider.requested.model,
    requestedEffort: context.provider.requested.effort,
    maxTokens: context.provider.requested.maxTokens,
    approvalBindingDigest: approval?.runtimeBindingDigest ?? null,
    approvalBindingIdentity: approval?.runtimeBindingIdentity ?? null,
    approvalGateId: approval?.gateId ?? null,
    approvalProtocolVersion: approval?.protocolVersion ?? null,
    approvalSnapshotDigest: approval?.snapshotDigest ?? null,
    approvalPhase: approval?.phase ?? null,
    approvalScopeDigest: approval?.approvedScopeDigest ?? null,
    approvalScopeIdentity: approval?.approvedScopeIdentity ?? null,
    approvalRequired: approval?.required ?? false,
    sanitizerBindingDigest,
    sanitizerId: sanitizer?.id ?? null,
    sanitizerProtocolVersion: sanitizer?.protocolVersion ?? null,
    sanitizerRequired: requirement.sanitizerRequired,
    policyRequired: requirement.policyRequired,
    sanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
    sanitizerRequirementReason: requirement.sanitizerRequirementReason,
    requirementVerifierId: requirement.requirementVerifierId,
    requirementVerifierVersion: requirement.requirementVerifierVersion,
    consumerSourceCommit: requirement.consumerSourceCommit,
    requirementDecisionDigest: requirement.requirementDecisionDigest,
    suiteContext: {
      suiteVersion: context.suite.suiteVersion,
      suiteId: context.suite.suiteId,
      suiteDigest: context.suite.suiteDigest,
      suitePlanDigest: context.suite.suitePlanDigest,
      casePolicyMapDigest: context.suite.casePolicyMapDigest,
      caseIndex: entry.caseIndex,
      repeatIndex: 0,
    },
  });
}

function projectApproval(value: JsonValue | undefined): JsonValue {
  if (value === undefined) return null;
  if (!isJsonObject(value)) throw invalidManifest();
  return {
    required: requiredJson(value, "required"),
    gateId: requiredJson(value, "expectedGateId"),
    protocolVersion: requiredJson(value, "expectedProtocolVersion"),
    snapshotDigest: requiredJson(value, "snapshotDigest"),
    runtimeBindingIdentity: requiredJson(value, "runtimeBindingIdentity"),
    runtimeBindingDigest: requiredJson(value, "runtimeBindingDigest"),
    approvedScopeIdentity: requiredJson(value, "approvedScopeIdentity"),
    approvedScopeDigest: requiredJson(value, "approvedScopeDigest"),
    phase: requiredJson(value, "phase"),
  };
}

function projectSanitizer(value: JsonValue | undefined): JsonValue {
  if (value === undefined) return null;
  if (!isJsonObject(value)) throw invalidManifest();
  const patterns = requiredJson(value, "allowedFindingPathPatterns");
  return {
    id: requiredJson(value, "expectedSanitizerId"),
    protocolVersion: requiredJson(value, "expectedProtocolVersion"),
    findingPathAllowlistVersion: SANITIZER_FINDING_PATH_ALLOWLIST_VERSION,
    findingPathAllowlistDigest: computeSanitizerFindingPathAllowlistDigest(
      patterns as string[],
    ),
    allowedFindingPathPatterns: patterns,
    failureCodes: requiredJson(value, "failureCodes"),
  };
}

function projectCase(value: JsonValue, index: number): JsonValue {
  if (!isJsonObject(value) || !isJsonObject(value.caseInputIdentity)) {
    throw invalidManifest();
  }
  return {
    caseIndex: index,
    bundleManifestDigest: requiredJson(value, "bundleManifestDigest"),
    caseInputIdentityVersion: requiredJson(value.caseInputIdentity, "identityVersion"),
    caseInputIdentityDigest: requiredJson(value.caseInputIdentity, "digest"),
    sanitizerRequirement: requiredJson(value, "sanitizerRequirement"),
    policy:
      value.policy === undefined || value.policy === null
        ? null
        : projectPolicy(value.policy),
  };
}

function projectPolicy(value: JsonValue): JsonValue {
  if (!isJsonObject(value)) throw invalidManifest();
  return {
    policyVersion: requiredJson(value, "policyVersion"),
    policyDigest: requiredJson(value, "policyDigest"),
    policyTargetIdentityDigest: requiredJson(value, "policyTargetIdentityDigest"),
    policyBindingDigest: requiredJson(value, "policyBindingDigest"),
  };
}

function computeIdentityDigest(identity: SuiteRunManifestIdentity): string {
  const bytes = Buffer.from(JSON.stringify(identity), "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return createHash("sha256")
    .update(Buffer.from("svbench-suite-run-v1", "ascii"))
    .update(length)
    .update(bytes)
    .digest("hex");
}

function toIdentity(manifest: SuiteRunManifest): SuiteRunManifestIdentity {
  const {
    suiteRunId: _suiteRunId,
    ...identity
  } = manifest;
  return identity;
}

function snapshotPlainData(value: unknown): JsonValue {
  let nodes = 0;
  function visit(candidate: unknown, depth: number): JsonValue {
    nodes += 1;
    if (nodes > 100_000 || depth > 12) throw new Error();
    if (
      candidate === null ||
      typeof candidate === "string" ||
      typeof candidate === "boolean"
    ) {
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate)) throw new Error();
      return candidate;
    }
    if (typeof candidate !== "object" || Object.getOwnPropertySymbols(candidate).length > 0) {
      throw new Error();
    }
    if (Array.isArray(candidate)) {
      const length = Object.getOwnPropertyDescriptor(candidate, "length")?.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_SLOTS) throw new Error();
      const ownNames = Object.getOwnPropertyNames(candidate);
      if (ownNames.length !== length + 1 || !ownNames.includes("length")) throw new Error();
      const result: JsonValue[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(candidate, String(index));
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new Error();
        }
        result.push(visit(descriptor.value, depth + 1));
      }
      return result;
    }
    if (!isJsonObject(candidate)) throw new Error();
    const keys = Object.getOwnPropertyNames(candidate);
    if (keys.length > 64) throw new Error();
    const result: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error();
      }
      result[key] = visit(descriptor.value, depth + 1);
    }
    return result;
  }
  return visit(value, 0);
}

function hasExactKeys(value: Record<string, JsonValue>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function requiredJson(value: Record<string, JsonValue>, key: string): JsonValue {
  const candidate = value[key];
  if (candidate === undefined) throw invalidManifest();
  return candidate;
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL_PATTERN.test(value);
}

function isNullableSafeLabel(value: unknown): value is string | null {
  return value === null || isSafeLabel(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

function isNullablePositiveInteger(value: unknown): value is number | null {
  return value === null || isBoundedInteger(value, 1, Number.MAX_SAFE_INTEGER);
}

function invalidManifest(): SuiteRunManifestError {
  return new SuiteRunManifestError(
    "suite_run_manifest_invalid",
    "suite run manifest is invalid",
  );
}
