import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../bundle/json.js";
import { validateJsonSchema } from "../bundle/schema-validator.js";
import {
  BundleValidationError,
  inspectBundleForSuitePreflight,
} from "../bundle/validate-bundle.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  computeSanitizerRequirementDigest,
  createSanitizerRequirementDecision,
  type CaseInputIdentity,
  type SanitizerRequirementDecisionV1,
  type SanitizerRequirementVerifier,
} from "../runner/identity.js";
import { RunnerError } from "../runner/errors.js";
import { snapshotSanitizerFindingPathPatterns } from "../runner/sanitizer-finding-path.js";
import { MAX_SANITIZER_POLICY_BYTES, prepareSanitizerPolicy } from "../runner/sanitizer.js";
import {
  computeSuitePlanDigest as computeSuitePlanDigestV1,
  deriveSuiteAttemptKey as deriveSuiteAttemptKeyV1,
  snapshotSuiteAttemptContext,
  type SuiteAttemptContext,
} from "./context.js";
import { computeCasePolicyMapIdentityDigest } from "./case-policy-map-identity.js";

const SUITE_FILE_NAME = "suite.json";
const MAX_SUITE_BYTES = 4 * 1024 * 1024;
const MAX_SUITE_SLOTS = 10_000;
const MAX_CASE_POLICY_ENTRIES = 1000;
const MAX_CASE_POLICY_OBJECT_KEYS = 8;
const IMAGE_MEDIA_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "application/pdf"]);

type FileIdentity = Readonly<{
  device: number;
  inode: number;
}>;

type StableReference = Readonly<{
  path: string;
  identity: FileIdentity;
  assertStable: () => Promise<void>;
}>;

type ValidatedRequirementVerifier = Readonly<{
  id: string;
  version: string;
  derive: SanitizerRequirementVerifier["derive"];
}>;

export type SuitePreflightErrorCode =
  | "suite_not_found"
  | "suite_invalid"
  | "suite_reference_invalid"
  | "suite_case_bundle_invalid"
  | "suite_case_identity_mismatch"
  | "suite_requirement_mismatch"
  | "suite_sanitizer_configuration_invalid"
  | "suite_policy_invalid"
  | "suite_policy_identity_mismatch"
  | "suite_policy_target_mismatch"
  | "suite_policy_binding_mismatch"
  | "suite_slot_invalid";

export class SuitePreflightError extends Error {
  readonly code: SuitePreflightErrorCode;
  readonly caseIndex: number | null;
  readonly repeatIndex: number | null;

  constructor(
    code: SuitePreflightErrorCode,
    message: string,
    location: { caseIndex?: number; repeatIndex?: number } = {},
  ) {
    super(message);
    this.name = "SuitePreflightError";
    this.code = code;
    this.caseIndex = location.caseIndex ?? null;
    this.repeatIndex = location.repeatIndex ?? null;
  }
}

export type SuiteCommandSnapshot = Readonly<{
  executable: string;
  argv: readonly string[];
  envAllowlist: readonly string[];
  timeoutMs: number;
  outputLimitBytes: number;
}>;

export type SuiteApprovalSnapshot = Readonly<{
  required: boolean;
  command: SuiteCommandSnapshot;
  expectedGateId: string;
  expectedProtocolVersion: 1;
  snapshotDigest: string;
  runtimeBindingIdentity: string;
  runtimeBindingDigest: string;
  approvedScopeIdentity: string;
  approvedScopeDigest: string;
  phase: string;
}>;

export type SuiteSanitizerSnapshot = Readonly<{
  command: SuiteCommandSnapshot;
  expectedSanitizerId: string;
  expectedProtocolVersion: 1;
  allowedFindingPathPatterns: readonly string[];
  failureCodes: readonly string[];
}>;

export type SuitePolicyPlan = Readonly<{
  path: string;
  policyVersion: number;
  policyDigest: string;
  policyTargetIdentityDigest: string;
  policyBindingDigest: string;
}>;

export type SuiteCasePlan = Readonly<{
  caseIndex: number;
  bundlePath: string;
  bundleManifestDigest: string;
  caseInputIdentity: Readonly<CaseInputIdentity>;
  sanitizerRequirement: Readonly<SanitizerRequirementDecisionV1>;
  policy?: SuitePolicyPlan;
}>;

export type SuiteSlotDescriptor = Readonly<{
  caseIndex: number;
  repeatIndex: number;
  attemptKey: string;
}>;

export type SuitePreflightPlan = Readonly<{
  suiteVersion: 1;
  suiteId: string;
  suiteDigest: string;
  suitePlanDigest: string;
  casePolicyMapDigest: string;
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
  approval?: SuiteApprovalSnapshot;
  sanitizer?: SuiteSanitizerSnapshot;
  cases: readonly SuiteCasePlan[];
  slots: readonly SuiteSlotDescriptor[];
}>;

export { type SuiteAttemptContext } from "./context.js";

type SuiteManifestV1 = {
  suiteVersion: 1;
  suiteId: string;
  provider: {
    id: string;
    route: string;
    implementationVersion: string | null;
    protocolVersion: string | null;
    requested: { model: string | null; effort: string | null; maxTokens: number | null };
  };
  phase: string;
  repeat: number;
  requirementVerifier: {
    id: string;
    version: string;
    consumerSourceCommit: string | null;
  };
  approval?: {
    required: boolean;
    command: CommandManifest;
    expectedGateId: string;
    expectedProtocolVersion: 1;
    snapshotDigest: string;
    runtimeBindingIdentity: string;
    runtimeBindingDigest: string;
    approvedScopeIdentity: string;
    approvedScopeDigest: string;
    phase: string;
  };
  sanitizer?: {
    command: CommandManifest;
    expectedSanitizerId: string;
    expectedProtocolVersion: 1;
    allowedFindingPathPatterns: string[];
    failureCodes: string[];
  };
  cases: CaseManifest[];
};

type CommandManifest = {
  executable: string;
  argv: string[];
  envAllowlist: string[];
  timeoutMs: number;
  outputLimitBytes: number;
};

type CaseManifest = {
  bundlePath: string;
  expectedBundleManifestDigest: string;
  expectedCaseInputIdentityVersion: 1;
  expectedCaseInputIdentityDigest: string;
  sanitizerRequirementVersion: 1;
  sanitizerRequired: boolean;
  policyRequired: boolean;
  sanitizerRequirementReason: string;
  requirementDecisionDigest: string;
  policy?: {
    path: string;
    expectedPolicyVersion: number;
    expectedPolicyDigest: string;
    expectedPolicyTargetIdentityDigest: string;
    expectedPolicyBindingDigest: string;
  };
};

/**
 * Reads an exact-byte suite manifest and preflights every case before any
 * approval, sanitizer, or provider process can start.
 */
export async function preflightSuite(
  suiteDirectory: string,
  options: {
    requirementVerifier: SanitizerRequirementVerifier;
    suiteSchemaPath?: string;
    bundleSchemaPath?: string;
  },
): Promise<SuitePreflightPlan> {
  const suiteRoot = await resolveSuiteRoot(suiteDirectory);
  let suiteBytes: Buffer;
  try {
    const suiteFile = await resolveStableReference(suiteRoot, SUITE_FILE_NAME, "file");
    suiteBytes = await readStableFile(suiteFile, MAX_SUITE_BYTES, true);
  } catch {
    throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
  }
  const manifest = await parseSuiteManifest(
    suiteBytes,
    options.suiteSchemaPath ?? path.resolve("schemas/suite-v1.schema.json"),
  );
  const verifier = snapshotRequirementVerifier(options.requirementVerifier);
  if (
    verifier.id !== manifest.requirementVerifier.id ||
    verifier.version !== manifest.requirementVerifier.version
  ) {
    throw new SuitePreflightError(
      "suite_requirement_mismatch",
      "suite requirement verifier does not match",
    );
  }
  const suiteDigest = digest(suiteBytes);
  if (manifest.cases.length * manifest.repeat > MAX_SUITE_SLOTS) {
    throw new SuitePreflightError("suite_slot_invalid", "suite slot plan is invalid");
  }

  const approval = manifest.approval === undefined ? undefined : snapshotApproval(manifest.approval);
  if (approval !== undefined && approval.phase !== manifest.phase) {
    throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
  }
  const sanitizer = snapshotSanitizer(manifest.sanitizer);
  const hasRequiredCase = manifest.cases.some((entry) => entry.sanitizerRequired);
  if (hasRequiredCase !== (sanitizer !== undefined)) {
    throw new SuitePreflightError(
      "suite_sanitizer_configuration_invalid",
      "suite sanitizer configuration is invalid",
    );
  }

  const cases: SuiteCasePlan[] = [];
  for (const [caseIndex, entry] of manifest.cases.entries()) {
    cases.push(
      await preflightCase({
        suiteRoot,
        caseIndex,
        entry,
        verifier,
        expectedConsumerSourceCommit: manifest.requirementVerifier.consumerSourceCommit,
        sanitizer,
        ...(options.bundleSchemaPath === undefined
          ? {}
          : { bundleSchemaPath: options.bundleSchemaPath }),
      }),
    );
  }

  const casePolicyMapDigest = computeCasePolicyMapDigest(cases);
  const slots = deriveSuiteSlots(cases.length, manifest.repeat);
  const suitePlanDigest = computeSuitePlanDigest(suiteDigest, casePolicyMapDigest);

  const plan: SuitePreflightPlan = {
    suiteVersion: 1,
    suiteId: manifest.suiteId,
    suiteDigest,
    suitePlanDigest,
    casePolicyMapDigest,
    provider: Object.freeze({
      id: manifest.provider.id,
      route: manifest.provider.route,
      implementationVersion: manifest.provider.implementationVersion,
      protocolVersion: manifest.provider.protocolVersion,
      requested: Object.freeze({ ...manifest.provider.requested }),
    }),
    phase: manifest.phase,
    repeat: manifest.repeat,
    requirementVerifier: Object.freeze({ ...manifest.requirementVerifier }),
    ...(approval === undefined ? {} : { approval }),
    ...(sanitizer === undefined ? {} : { sanitizer }),
    cases: Object.freeze(cases),
    slots,
  };
  return Object.freeze(plan);
}

export function deriveSuiteAttemptKey(caseIndex: number, repeatIndex: number): string {
  try {
    return deriveSuiteAttemptKeyV1(caseIndex, repeatIndex);
  } catch {
    throw new SuitePreflightError(
      "suite_slot_invalid",
      "suite slot is invalid",
      suiteSlotLocation(caseIndex, repeatIndex),
    );
  }
}

/** Commits the exact suite bytes and its ordered case-policy mapping. */
export function computeSuitePlanDigest(
  suiteDigest: string,
  casePolicyMapDigest: string,
): string {
  try {
    return computeSuitePlanDigestV1(suiteDigest, casePolicyMapDigest);
  } catch {
    throw new SuitePreflightError("suite_invalid", "suite plan identity is invalid");
  }
}

/** Projects one preflighted slot into the exact context accepted by runBundle. */
export function createSuiteAttemptContext(
  plan: SuitePreflightPlan,
  slot: SuiteSlotDescriptor,
): SuiteAttemptContext {
  const slotSnapshot = snapshotSuiteSlotDescriptor(slot);
  const expected = plan.slots.find(
    (candidate) =>
      candidate.caseIndex === slotSnapshot.caseIndex &&
      candidate.repeatIndex === slotSnapshot.repeatIndex,
  );
  if (expected === undefined || expected.attemptKey !== slotSnapshot.attemptKey) {
    throw new SuitePreflightError("suite_slot_invalid", "suite slot is invalid", {
      caseIndex: slotSnapshot.caseIndex,
      repeatIndex: slotSnapshot.repeatIndex,
    });
  }
  try {
    return snapshotSuiteAttemptContext({
      suiteVersion: plan.suiteVersion,
      suiteId: plan.suiteId,
      suiteDigest: plan.suiteDigest,
      suitePlanDigest: plan.suitePlanDigest,
      casePolicyMapDigest: plan.casePolicyMapDigest,
      caseIndex: slotSnapshot.caseIndex,
      repeatIndex: slotSnapshot.repeatIndex,
    });
  } catch {
    throw new SuitePreflightError("suite_invalid", "suite attempt context is invalid");
  }
}

function suiteSlotLocation(
  caseIndex: unknown,
  repeatIndex: unknown,
): { caseIndex?: number; repeatIndex?: number } {
  return Number.isSafeInteger(caseIndex) &&
    (caseIndex as number) >= 0 &&
    (caseIndex as number) <= 999 &&
    Number.isSafeInteger(repeatIndex) &&
    (repeatIndex as number) >= 0 &&
    (repeatIndex as number) <= 999
    ? { caseIndex: caseIndex as number, repeatIndex: repeatIndex as number }
    : {};
}

function snapshotSuiteSlotDescriptor(value: unknown): SuiteSlotDescriptor {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== 3 ||
      !keys.includes("caseIndex") ||
      !keys.includes("repeatIndex") ||
      !keys.includes("attemptKey")
    ) {
      throw new Error();
    }
    const caseIndex = ownEnumerableDataValue(value, "caseIndex");
    const repeatIndex = ownEnumerableDataValue(value, "repeatIndex");
    const attemptKey = ownEnumerableDataValue(value, "attemptKey");
    const location = suiteSlotLocation(caseIndex, repeatIndex);
    if (
      location.caseIndex === undefined ||
      location.repeatIndex === undefined
    ) {
      throw new Error();
    }
    if (
      typeof attemptKey !== "string" ||
      deriveSuiteAttemptKeyV1(location.caseIndex, location.repeatIndex) !== attemptKey
    ) {
      throw new SuitePreflightError("suite_slot_invalid", "suite slot is invalid", location);
    }
    return Object.freeze({
      caseIndex: location.caseIndex,
      repeatIndex: location.repeatIndex,
      attemptKey,
    });
  } catch (error) {
    if (error instanceof SuitePreflightError) throw error;
    throw new SuitePreflightError("suite_slot_invalid", "suite slot is invalid");
  }
}

function ownEnumerableDataValue(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    throw new Error();
  }
  return descriptor.value;
}

/** Commits the ordered requirement and case-specific policy mapping. */
export function computeCasePolicyMapDigest(cases: readonly SuiteCasePlan[]): string {
  let snapshot: unknown;
  try {
    snapshot = snapshotPlainData(cases);
  } catch {
    throw new SuitePreflightError("suite_invalid", "suite case-policy mapping is invalid");
  }
  if (
    !Array.isArray(snapshot) ||
    snapshot.length < 1 ||
    snapshot.length > MAX_CASE_POLICY_ENTRIES
  ) {
    throw new SuitePreflightError("suite_invalid", "suite case-policy mapping is invalid");
  }
  const safeCases = snapshot as unknown as readonly SuiteCasePlan[];
  for (let index = 0; index < safeCases.length; index += 1) {
    const rawEntry: unknown = safeCases[index];
    try {
      if (!isPlainRecord(rawEntry)) throw new Error();
      const entry = rawEntry as unknown as SuiteCasePlan;
      const identity = entry.caseInputIdentity;
      const requirement = entry.sanitizerRequirement;
      if (
        !hasExactKeys(
          rawEntry,
          entry.policy === undefined
            ? [
                "caseIndex",
                "bundlePath",
                "bundleManifestDigest",
                "caseInputIdentity",
                "sanitizerRequirement",
              ]
            : [
                "caseIndex",
                "bundlePath",
                "bundleManifestDigest",
                "caseInputIdentity",
                "sanitizerRequirement",
                "policy",
              ],
        ) ||
        entry.caseIndex !== index ||
        typeof entry.bundlePath !== "string" ||
        !isDigest(entry.bundleManifestDigest) ||
        !isPlainRecord(identity) ||
        !hasExactKeys(identity, [
          "identityVersion",
          "caseId",
          "documentKind",
          "preparedImage",
          "digest",
        ]) ||
        identity.identityVersion !== 1 ||
        typeof identity.caseId !== "string" ||
        !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(identity.caseId) ||
        !isSafeLabel(identity.documentKind) ||
        !isPlainRecord(identity.preparedImage) ||
        !hasExactKeys(identity.preparedImage, ["mediaType", "sha256"]) ||
        typeof identity.preparedImage.mediaType !== "string" ||
        !IMAGE_MEDIA_TYPES.has(identity.preparedImage.mediaType) ||
        !isDigest(identity.preparedImage.sha256) ||
        !isDigest(identity.digest) ||
        computeCaseInputIdentity({
          caseId: identity.caseId,
          documentKind: identity.documentKind,
          preparedImage: identity.preparedImage,
        }).digest !== identity.digest ||
        !isPlainRecord(requirement) ||
        !hasExactKeys(requirement, [
          "sanitizerRequired",
          "policyRequired",
          "sanitizerRequirementReason",
          "consumerSourceCommit",
          "sanitizerRequirementVersion",
          "requirementVerifierId",
          "requirementVerifierVersion",
          "requirementDecisionDigest",
        ]) ||
        requirement.sanitizerRequirementVersion !== 1 ||
        typeof requirement.sanitizerRequired !== "boolean" ||
        typeof requirement.policyRequired !== "boolean" ||
        requirement.sanitizerRequired !== requirement.policyRequired ||
        !isSafeLabel(requirement.sanitizerRequirementReason) ||
        !isSafeLabel(requirement.requirementVerifierId) ||
        !isSafeLabel(requirement.requirementVerifierVersion) ||
        (requirement.consumerSourceCommit !== null &&
          !isSafeLabel(requirement.consumerSourceCommit)) ||
        !isDigest(requirement.requirementDecisionDigest) ||
        computeSanitizerRequirementDigest(requirement) !==
          requirement.requirementDecisionDigest ||
        requirement.policyRequired !== (entry.policy !== undefined)
      ) {
        throw new Error();
      }
      assertSafeRelativePath(entry.bundlePath);
      if (entry.policy !== undefined) {
        if (
          !isPlainRecord(entry.policy) ||
          !hasExactKeys(entry.policy, [
            "path",
            "policyVersion",
            "policyDigest",
            "policyTargetIdentityDigest",
            "policyBindingDigest",
          ]) ||
          typeof entry.policy.path !== "string" ||
          !Number.isSafeInteger(entry.policy.policyVersion) ||
          entry.policy.policyVersion < 1 ||
          !isDigest(entry.policy.policyDigest) ||
          entry.policy.policyTargetIdentityDigest !== identity.digest ||
          !isDigest(entry.policy.policyBindingDigest) ||
          computePolicyBindingDigest({
            caseInputIdentityDigest: identity.digest,
            policyVersion: entry.policy.policyVersion,
            policyDigest: entry.policy.policyDigest,
          }) !== entry.policy.policyBindingDigest
        ) {
          throw new Error();
        }
        assertSafeRelativePath(entry.policy.path);
      }
    } catch {
      throw new SuitePreflightError("suite_invalid", "suite case-policy mapping is invalid", {
        caseIndex: index,
      });
    }
  }
  return computeCasePolicyMapIdentityDigest(
    safeCases.map((entry) => ({
      caseIndex: entry.caseIndex,
      caseInputIdentityDigest: entry.caseInputIdentity.digest,
      sanitizerRequirement: entry.sanitizerRequirement,
      policy:
        entry.policy === undefined
          ? null
          : {
              policyVersion: entry.policy.policyVersion,
              policyDigest: entry.policy.policyDigest,
              policyTargetIdentityDigest: entry.policy.policyTargetIdentityDigest,
              policyBindingDigest: entry.policy.policyBindingDigest,
            },
    })),
  );
}

async function preflightCase(input: {
  suiteRoot: StableReference;
  caseIndex: number;
  entry: CaseManifest;
  verifier: ValidatedRequirementVerifier;
  expectedConsumerSourceCommit: string | null;
  sanitizer: SuiteSanitizerSnapshot | undefined;
  bundleSchemaPath?: string;
}): Promise<SuiteCasePlan> {
  const {
    suiteRoot,
    caseIndex,
    entry,
    verifier,
    expectedConsumerSourceCommit,
    sanitizer,
  } = input;
  let bundleReference: StableReference;
  let manifestReference: StableReference;
  try {
    bundleReference = await resolveStableReference(suiteRoot, entry.bundlePath, "directory");
    manifestReference = await resolveStableReference(
      bundleReference,
      "bundle.json",
      "file",
    );
  } catch {
    throw caseError("suite_reference_invalid", "suite case reference is invalid", caseIndex);
  }

  let bundle;
  try {
    bundle = await inspectBundleForSuitePreflight(
      bundleReference.path,
      input.bundleSchemaPath,
    );
    if (
      bundle.manifestFileIdentity.device !== manifestReference.identity.device ||
      bundle.manifestFileIdentity.inode !== manifestReference.identity.inode
    ) {
      throw new Error();
    }
    await manifestReference.assertStable();
  } catch (error) {
    if (error instanceof BundleValidationError) {
      throw caseError("suite_case_bundle_invalid", "suite case bundle is invalid", caseIndex);
    }
    throw caseError("suite_case_bundle_invalid", "suite case bundle is invalid", caseIndex);
  }
  const identity = computeCaseInputIdentity({
    caseId: bundle.caseId,
    documentKind: bundle.documentKind,
    preparedImage: bundle.image,
  });
  if (
    bundle.manifestDigest !== entry.expectedBundleManifestDigest ||
    identity.identityVersion !== entry.expectedCaseInputIdentityVersion ||
    identity.digest !== entry.expectedCaseInputIdentityDigest
  ) {
    throw caseError(
      "suite_case_identity_mismatch",
      "suite case identity does not match",
      caseIndex,
    );
  }

  let requirement: SanitizerRequirementDecisionV1;
  try {
    const core = verifier.derive(bundle.documentKind);
    if (
      !isPlainRecord(core) ||
      typeof core.sanitizerRequired !== "boolean" ||
      typeof core.policyRequired !== "boolean" ||
      core.sanitizerRequired !== core.policyRequired ||
      !isSafeLabel(core.sanitizerRequirementReason) ||
      (core.consumerSourceCommit !== null && !isSafeLabel(core.consumerSourceCommit))
    ) {
      throw new Error();
    }
    requirement = createSanitizerRequirementDecision(
      {
        sanitizerRequired: core.sanitizerRequired,
        policyRequired: core.policyRequired,
        sanitizerRequirementReason: core.sanitizerRequirementReason,
        consumerSourceCommit: core.consumerSourceCommit,
      },
      verifier,
    );
  } catch {
    throw caseError(
      "suite_requirement_mismatch",
      "suite case requirement does not match",
      caseIndex,
    );
  }
  if (
    requirement.consumerSourceCommit !== expectedConsumerSourceCommit ||
    requirement.sanitizerRequirementVersion !== entry.sanitizerRequirementVersion ||
    requirement.sanitizerRequired !== entry.sanitizerRequired ||
    requirement.policyRequired !== entry.policyRequired ||
    requirement.sanitizerRequirementReason !== entry.sanitizerRequirementReason ||
    requirement.requirementDecisionDigest !== entry.requirementDecisionDigest
  ) {
    throw caseError(
      "suite_requirement_mismatch",
      "suite case requirement does not match",
      caseIndex,
    );
  }
  try {
    await manifestReference.assertStable();
  } catch {
    throw caseError("suite_case_bundle_invalid", "suite case bundle is invalid", caseIndex);
  }

  if (!entry.sanitizerRequired) {
    if (entry.policy !== undefined) {
      throw caseError(
        "suite_sanitizer_configuration_invalid",
        "suite case sanitizer configuration is invalid",
        caseIndex,
      );
    }
    return Object.freeze({
      caseIndex,
      bundlePath: entry.bundlePath,
      bundleManifestDigest: bundle.manifestDigest,
      caseInputIdentity: freezeIdentity(identity),
      sanitizerRequirement: Object.freeze(requirement),
    });
  }

  if (entry.policy === undefined || sanitizer === undefined) {
    throw caseError(
      "suite_sanitizer_configuration_invalid",
      "suite case sanitizer configuration is invalid",
      caseIndex,
    );
  }
  const policy = await preflightPolicy(suiteRoot, caseIndex, entry.policy, identity, sanitizer);
  return Object.freeze({
    caseIndex,
    bundlePath: entry.bundlePath,
    bundleManifestDigest: bundle.manifestDigest,
    caseInputIdentity: freezeIdentity(identity),
    sanitizerRequirement: Object.freeze(requirement),
    policy,
  });
}

async function preflightPolicy(
  suiteRoot: StableReference,
  caseIndex: number,
  policy: NonNullable<CaseManifest["policy"]>,
  identity: CaseInputIdentity,
  sanitizer: SuiteSanitizerSnapshot,
): Promise<SuitePolicyPlan> {
  if (policy.expectedPolicyTargetIdentityDigest !== identity.digest) {
    throw caseError(
      "suite_policy_target_mismatch",
      "suite case policy target does not match",
      caseIndex,
    );
  }
  let policyReference: StableReference;
  try {
    policyReference = await resolveStableReference(suiteRoot, policy.path, "file");
  } catch {
    throw caseError("suite_reference_invalid", "suite policy reference is invalid", caseIndex);
  }

  let bytes: Buffer | undefined;
  try {
    if (process.platform === "win32") throw new Error();
    bytes = await readStableFile(policyReference, MAX_SANITIZER_POLICY_BYTES, true);
    const prepared = prepareSanitizerPolicy(
      {
        required: true,
        sanitizer: {
          id: sanitizer.expectedSanitizerId,
          protocolVersion: 1,
          sanitize: async () => {
            throw new Error("suite preflight must not invoke a sanitizer");
          },
        },
        policyEnvelopeBytes: bytes,
        expectedPolicyVersion: policy.expectedPolicyVersion,
        expectedPolicyDigest: policy.expectedPolicyDigest,
        expectedCaseInputIdentityVersion: identity.identityVersion,
        expectedCaseInputIdentityDigest: identity.digest,
        expectedPolicyBindingDigest: policy.expectedPolicyBindingDigest,
      },
      identity,
    );
    if (prepared === undefined) throw new Error();
    return Object.freeze({
      path: policy.path,
      policyVersion: prepared.policyVersion,
      policyDigest: prepared.policyDigest,
      policyTargetIdentityDigest: prepared.policyTargetIdentityDigest,
      policyBindingDigest: prepared.policyBindingDigest,
    });
  } catch (error) {
    if (error instanceof RunnerError) {
      const code = policyErrorCode(error.code);
      throw caseError(code, policyErrorMessage(code), caseIndex);
    }
    throw caseError("suite_policy_invalid", "suite case policy is invalid", caseIndex);
  } finally {
    bytes?.fill(0);
  }
}

function policyErrorCode(code: string): SuitePreflightErrorCode {
  if (code === "sanitizer_policy_target_mismatch") return "suite_policy_target_mismatch";
  if (code === "sanitizer_policy_binding_mismatch") return "suite_policy_binding_mismatch";
  if (code === "sanitizer_policy_identity_mismatch") return "suite_policy_identity_mismatch";
  return "suite_policy_invalid";
}

function policyErrorMessage(code: SuitePreflightErrorCode): string {
  if (code === "suite_policy_target_mismatch") return "suite case policy target does not match";
  if (code === "suite_policy_binding_mismatch") return "suite case policy binding does not match";
  if (code === "suite_policy_identity_mismatch") return "suite case policy identity does not match";
  return "suite case policy is invalid";
}

function deriveSuiteSlots(caseCount: number, repeat: number): readonly SuiteSlotDescriptor[] {
  const slots: SuiteSlotDescriptor[] = [];
  const keys = new Set<string>();
  for (let caseIndex = 0; caseIndex < caseCount; caseIndex += 1) {
    for (let repeatIndex = 0; repeatIndex < repeat; repeatIndex += 1) {
      const attemptKey = deriveSuiteAttemptKey(caseIndex, repeatIndex);
      if (keys.has(attemptKey)) {
        throw new SuitePreflightError("suite_slot_invalid", "suite slot plan is invalid", {
          caseIndex,
          repeatIndex,
        });
      }
      keys.add(attemptKey);
      slots.push(Object.freeze({ caseIndex, repeatIndex, attemptKey }));
    }
  }
  return Object.freeze(slots);
}

async function parseSuiteManifest(bytes: Buffer, schemaPath: string): Promise<SuiteManifestV1> {
  let manifest: JsonValue;
  let schema: JsonValue;
  try {
    manifest = parseJson(decodeUtf8Strict(bytes, SUITE_FILE_NAME), SUITE_FILE_NAME);
    const schemaBytes = await readBoundedRegularFile(schemaPath, MAX_SUITE_BYTES);
    schema = parseJson(decodeUtf8Strict(schemaBytes, "suite v1 schema"), "suite v1 schema");
  } catch {
    throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
  }
  if (!isJsonObject(manifest) || validateJsonSchema(schema, manifest).length > 0) {
    throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
  }
  return manifest as unknown as SuiteManifestV1;
}

async function resolveSuiteRoot(directory: string): Promise<StableReference> {
  try {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error();
    const canonical = await realpath(directory);
    const canonicalMetadata = await lstat(canonical);
    if (!canonicalMetadata.isDirectory() || canonicalMetadata.isSymbolicLink()) throw new Error();
    const identity = fileIdentity(canonicalMetadata);
    return Object.freeze({
      path: canonical,
      identity,
      assertStable: async () => {
        const current = await lstat(canonical);
        if (
          !current.isDirectory() ||
          current.isSymbolicLink() ||
          !sameFileIdentity(identity, fileIdentity(current)) ||
          (await realpath(canonical)) !== canonical
        ) {
          throw new Error();
        }
      },
    });
  } catch {
    throw new SuitePreflightError("suite_not_found", "suite directory is unavailable");
  }
}

async function readStableFile(
  reference: StableReference,
  maxBytes: number,
  requirePrivateMode: boolean,
): Promise<Buffer> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let bounded: Buffer | undefined;
  try {
    await reference.assertStable();
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
    handle = await open(reference.path, flags);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      !sameFileIdentity(reference.identity, fileIdentity(metadata)) ||
      metadata.size > maxBytes ||
      (requirePrivateMode && (metadata.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
    bounded = await readBoundedHandle(handle, maxBytes);
    await reference.assertStable();
    return Buffer.from(bounded);
  } catch {
    throw new Error();
  } finally {
    bounded?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function readBoundedRegularFile(file: string, maxBytes: number): Promise<Buffer> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let bounded: Buffer | undefined;
  try {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
    handle = await open(file, flags);
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maxBytes) throw new Error();
    bounded = await readBoundedHandle(handle, maxBytes);
    return Buffer.from(bounded);
  } catch {
    throw new Error();
  } finally {
    bounded?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function readBoundedHandle(
  handle: Awaited<ReturnType<typeof open>>,
  maxBytes: number,
): Promise<Buffer> {
  const bytes = Buffer.allocUnsafe(maxBytes + 1);
  let total = 0;
  while (total < bytes.length) {
    const { bytesRead } = await handle.read(bytes, total, bytes.length - total, null);
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  if (total > maxBytes) {
    bytes.fill(0);
    throw new Error();
  }
  const result = Buffer.from(bytes.subarray(0, total));
  bytes.fill(0);
  return result;
}

async function resolveStableReference(
  parent: StableReference,
  reference: string,
  expected: "file" | "directory",
): Promise<StableReference> {
  assertSafeRelativePath(reference);
  await parent.assertStable();
  const segments = reference.split("/");
  const snapshots: Array<{
    path: string;
    identity: FileIdentity;
    kind: "file" | "directory";
  }> = [];
  let candidate = parent.path;
  for (const [index, segment] of segments.entries()) {
    candidate = path.join(candidate, segment!);
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) throw new Error();
    const last = index === segments.length - 1;
    if (!last && !metadata.isDirectory()) throw new Error();
    if (last && (expected === "file" ? !metadata.isFile() : !metadata.isDirectory())) {
      throw new Error();
    }
    snapshots.push({
      path: candidate,
      identity: fileIdentity(metadata),
      kind: last ? expected : "directory",
    });
  }
  const canonical = await realpath(candidate);
  const relative = path.relative(parent.path, canonical);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error();
  }
  if (canonical !== candidate) throw new Error();
  const identity = snapshots.at(-1)?.identity;
  if (identity === undefined) throw new Error();
  return Object.freeze({
    path: canonical,
    identity,
    assertStable: async () => {
      await parent.assertStable();
      for (const snapshot of snapshots) {
        const current = await lstat(snapshot.path);
        if (
          current.isSymbolicLink() ||
          (snapshot.kind === "file" ? !current.isFile() : !current.isDirectory()) ||
          !sameFileIdentity(snapshot.identity, fileIdentity(current))
        ) {
          throw new Error();
        }
      }
      if ((await realpath(candidate)) !== canonical) throw new Error();
    },
  });
}

function assertSafeRelativePath(reference: string): void {
  if (
    reference.length === 0 ||
    reference.length > 512 ||
    reference.includes("\\") ||
    reference.includes("\0") ||
    path.posix.isAbsolute(reference) ||
    path.posix.normalize(reference) !== reference
  ) {
    throw new Error();
  }
  const segments = reference.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error();
  }
}

function snapshotRequirementVerifier(value: unknown): ValidatedRequirementVerifier {
  try {
    if (value === null || typeof value !== "object") throw new Error();
    const candidate = value as {
      id?: unknown;
      version?: unknown;
      derive?: unknown;
    };
    if (
      !isSafeLabel(candidate.id) ||
      !isSafeLabel(candidate.version) ||
      typeof candidate.derive !== "function"
    ) {
      throw new Error();
    }
    return Object.freeze({
      id: candidate.id,
      version: candidate.version,
      derive: Function.prototype.bind.call(
        candidate.derive,
        value,
      ) as SanitizerRequirementVerifier["derive"],
    });
  } catch {
    throw new SuitePreflightError(
      "suite_requirement_mismatch",
      "suite requirement verifier does not match",
    );
  }
}

function snapshotApproval(value: NonNullable<SuiteManifestV1["approval"]>): SuiteApprovalSnapshot {
  return Object.freeze({
    required: value.required,
    command: snapshotCommand(value.command),
    expectedGateId: value.expectedGateId,
    expectedProtocolVersion: value.expectedProtocolVersion,
    snapshotDigest: value.snapshotDigest,
    runtimeBindingIdentity: value.runtimeBindingIdentity,
    runtimeBindingDigest: value.runtimeBindingDigest,
    approvedScopeIdentity: value.approvedScopeIdentity,
    approvedScopeDigest: value.approvedScopeDigest,
    phase: value.phase,
  });
}

function snapshotSanitizer(
  value: SuiteManifestV1["sanitizer"],
): SuiteSanitizerSnapshot | undefined {
  if (value === undefined) return undefined;
  let patterns: readonly string[];
  try {
    patterns = snapshotSanitizerFindingPathPatterns(value.allowedFindingPathPatterns);
  } catch {
    throw new SuitePreflightError(
      "suite_sanitizer_configuration_invalid",
      "suite sanitizer configuration is invalid",
    );
  }
  return Object.freeze({
    command: snapshotCommand(value.command),
    expectedSanitizerId: value.expectedSanitizerId,
    expectedProtocolVersion: value.expectedProtocolVersion,
    allowedFindingPathPatterns: Object.freeze([...patterns]),
    failureCodes: Object.freeze([...value.failureCodes]),
  });
}

function snapshotCommand(value: CommandManifest): SuiteCommandSnapshot {
  if (!path.isAbsolute(value.executable)) {
    throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
  }
  const normalizedEnvironmentNames = new Set<string>();
  for (const name of value.envAllowlist) {
    const normalized = name.toUpperCase();
    if (normalizedEnvironmentNames.has(normalized)) {
      throw new SuitePreflightError("suite_invalid", "suite manifest is invalid");
    }
    normalizedEnvironmentNames.add(normalized);
  }
  return Object.freeze({
    executable: value.executable,
    argv: Object.freeze([...value.argv]),
    envAllowlist: Object.freeze([...value.envAllowlist]),
    timeoutMs: value.timeoutMs,
    outputLimitBytes: value.outputLimitBytes,
  });
}

function freezeIdentity(identity: CaseInputIdentity): Readonly<CaseInputIdentity> {
  return Object.freeze({
    ...identity,
    preparedImage: Object.freeze({ ...identity.preparedImage }),
  });
}

function fileIdentity(metadata: { dev: number; ino: number }): FileIdentity {
  return Object.freeze({ device: metadata.dev, inode: metadata.ino });
}

function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function snapshotPlainData(value: unknown, depth = 0): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (depth > 8 || typeof value !== "object" || Object.getOwnPropertySymbols(value).length > 0) {
    throw new Error();
  }
  if (Array.isArray(value)) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > MAX_CASE_POLICY_ENTRIES
    ) {
      throw new Error();
    }
    const keys = boundedEnumerableKeys(value, lengthDescriptor.value);
    if (keys.length !== lengthDescriptor.value) throw new Error();
    const result: unknown[] = [];
    for (let index = 0; index < lengthDescriptor.value; index += 1) {
      if (keys[index] !== String(index)) throw new Error();
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor)) throw new Error();
      result.push(snapshotPlainData(descriptor.value, depth + 1));
    }
    return result;
  }
  if (!isPlainRecord(value)) throw new Error();
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of boundedEnumerableKeys(value, MAX_CASE_POLICY_OBJECT_KEYS)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) throw new Error();
    result[key] = snapshotPlainData(descriptor.value, depth + 1);
  }
  return result;
}

function boundedEnumerableKeys(value: object, maximum: number): string[] {
  const keys: string[] = [];
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (keys.length >= maximum) throw new Error();
    keys.push(key);
  }
  return keys;
}

function caseError(
  code: SuitePreflightErrorCode,
  message: string,
  caseIndex: number,
): SuitePreflightError {
  return new SuitePreflightError(code, message, { caseIndex });
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,64}$/u.test(value);
}

function digestParts(parts: readonly Buffer[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function lengthPrefixedUtf8(value: string): Buffer {
  return lengthPrefix(Buffer.from(value, "utf8"));
}

function lengthPrefixedAscii(value: string): Buffer {
  if (!/^[\x00-\x7f]*$/u.test(value)) throw new Error("suite identity input is invalid");
  return lengthPrefix(Buffer.from(value, "ascii"));
}

function optionalUtf8(value: string | null): Buffer {
  return value === null
    ? Buffer.from([0])
    : Buffer.concat([Buffer.from([1]), lengthPrefixedUtf8(value)]);
}

function lengthPrefix(value: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(value.length, 0);
  return Buffer.concat([prefix, value]);
}
