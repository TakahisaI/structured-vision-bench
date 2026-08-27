import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdtemp, mkdir, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { validateJsonSchema } from "../bundle/schema-validator.js";
import {
  loadBundleForRunner,
  prepareBundleForRunner,
} from "../bundle/validate-bundle.js";
import {
  MAX_DOCUMENT_BYTES,
  claimAttemptDirectory,
  cleanupAttemptClaim,
  writeAttemptFiles,
  type AttemptManifest,
  type AttemptManifestBase,
} from "./attempt.js";
import { RunnerError } from "./errors.js";
import { isAbortSettlingCommandProvider } from "../provider/command.js";
import {
  computeCaseInputIdentity,
  computeAttemptIdentity,
  createSanitizerRequirementDecision,
  computeRunIdentity,
  type CaseInputIdentity,
  type SanitizerRequirementDecisionV1,
} from "./identity.js";
import { prepareSanitizerPolicy, type PreparedSanitizerPolicy } from "./sanitizer.js";
import {
  createCommandApprovalGate,
  DEFAULT_APPROVAL_OUTPUT_LIMIT_BYTES,
} from "./approval.js";
import type {
  ApprovalGate,
  ApprovalRequest,
  ApprovalResponse,
  ApprovalSettings,
  JsonRecord,
  Provider,
  ProviderAdapterContext,
  ProviderModelRequest,
  ProviderOutput,
  ProviderResponse,
  ProviderUsage,
  RequestedExecutionSettings,
  RunBundleOptions,
  RunResult,
  Sanitizer,
  SanitizerFinding,
  SanitizerResponse,
  SanitizerSettings,
} from "./types.js";
import {
  decodeUtf8Strict,
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";

export const DEFAULT_HARNESS_VERSION = "structured-vision-bench-runner-v1";
export const DEFAULT_ATTEMPT_KEY = "single";
export const DEFAULT_EXECUTION_PHASE = "development";
export const MAX_TIMEOUT_MS = 2_147_483_647;
const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;
const DEFAULT_SANITIZER_TIMEOUT_MS = 30_000;
const DEFAULT_PROVIDER_TIMEOUT_MS = 120_000;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ATTEMPT_ROOT_NOFOLLOW = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_DIRECTORY ?? 0);
const INTERNAL_RUNNER_ERRORS = new WeakSet<object>();

type NormalizedProviderResponse = {
  document: JsonValue;
  approval: ApprovalResponse | undefined;
  respondedModel: string | null;
  effectiveEffort: string | null;
  usage: ProviderUsage;
  stopReason: string | null;
};

type ProviderIdentity = {
  id: string;
  route: string;
  implementationVersion: string | null;
  protocolVersion: string | null;
};

type ValidatedProvider = Readonly<
  ProviderIdentity &
    Pick<Provider, "invoke"> & {
      awaitAbort: boolean;
      prepareTransport?: NonNullable<Provider["prepareTransport"]>;
    }
>;

type ValidatedApprovalPlan = Readonly<{
  required: boolean;
  gate: ApprovalGate;
  expectedGateId: string;
  expectedProtocolVersion: 1;
  snapshotDigest: string;
  runtimeBindingDigest: string;
  runtimeBindingIdentity: string;
  approvedScopeDigest: string;
  approvedScopeIdentity: string;
  phase: string;
  timeoutMs?: number;
}>;

type ValidatedSanitizerImplementation = Readonly<{
  id: string;
  protocolVersion: 1;
  sanitize: Sanitizer["sanitize"];
}>;

export async function runBundle(options: RunBundleOptions): Promise<RunResult> {
  const requested = normalizeRequestedSettings(options);
  const attemptKey = normalizeAttemptKey(options.attemptKey);
  const phase = normalizeOptionalSetting(options.phase) ?? DEFAULT_EXECUTION_PHASE;
  const providerTimeoutMs = options.providerTimeoutMs;
  const approvalSettings = snapshotApprovalSettings(options.approval);
  const sanitizerImplementation = validateSanitizerImplementation(options.sanitizer);
  const sanitizerSettings = snapshotSanitizerSettings(
    options.sanitizer,
    sanitizerImplementation,
  );
  try {
    validateBoundarySettings(approvalSettings, sanitizerSettings, sanitizerImplementation);
    validateTimeoutSetting(providerTimeoutMs, "run_configuration_invalid");
    const provider = validateProvider(options.provider);
    const harnessVersion =
      normalizeOptionalSetting(options.harnessVersion) ?? DEFAULT_HARNESS_VERSION;
    const harnessCommit = normalizeOptionalSetting(options.harnessCommit);
    const startedAt = new Date().toISOString();
    const attemptRoot = path.resolve(options.attemptRoot);

    const temporaryParent = await mkdtemp(path.join(tmpdir(), "svbench-run-"));
    const inputStagingDirectory = path.join(temporaryParent, "inputs");
    let loaded:
      | Awaited<ReturnType<typeof loadBundleForRunner>>
      | undefined;
    let attemptRootHandle: Awaited<ReturnType<typeof open>> | undefined;
    let attemptClaim: Awaited<ReturnType<typeof claimAttemptDirectory>> | undefined;
    let attemptRootGuard: { assertStable: () => Promise<void> } | undefined;
    try {
    const prepared = await prepareBundleForRunner(
      options.bundleDirectory,
      options.contractSchemaPath,
    );
    const rootGuard = await prepared.prepareAttemptRootGuard(attemptRoot);
    attemptRootGuard = rootGuard;
    const identity = computeCaseInputIdentity({
      caseId: prepared.caseId,
      documentKind: prepared.documentKind,
      preparedImage: {
        mediaType: prepared.image.mediaType,
        sha256: prepared.image.sha256,
      },
    });
    const requirement = verifySanitizerRequirement(
      options.sanitizerRequirement,
      prepared.documentKind,
    );
    validateSanitizerRequirementSettings(
      requirement,
      sanitizerSettings,
      sanitizerImplementation,
    );
      const preparedPolicy: PreparedSanitizerPolicy | undefined = requirement.policyRequired
        ? prepareSanitizerPolicy(sanitizerSettings, identity)
        : undefined;
    const approvalPlan = validateApprovalSettings(approvalSettings, requirement);
    if (approvalPlan !== undefined && approvalPlan.phase !== phase) {
      throw new RunnerError(
        "approval_configuration_invalid",
        "approval phase does not match the run phase",
      );
    }
    validateProviderTransportPreparation(provider, approvalPlan);
    const runId = computeRunIdentity({
      caseInputIdentityDigest: identity.digest,
      bundleManifestDigest: prepared.manifestDigest,
      phase,
      providerId: provider.id,
      providerRoute: provider.route,
      providerImplementationVersion: provider.implementationVersion,
      providerProtocolVersion: provider.protocolVersion,
      requestedModel: requested.model,
      requestedEffort: requested.effort,
      maxTokens: requested.maxTokens,
      approvalBindingDigest: approvalPlan?.runtimeBindingDigest ?? null,
      approvalBindingIdentity: approvalPlan?.runtimeBindingIdentity ?? null,
      approvalGateId: approvalPlan?.expectedGateId ?? null,
      approvalProtocolVersion: approvalPlan?.expectedProtocolVersion ?? null,
      approvalSnapshotDigest: approvalPlan?.snapshotDigest ?? null,
      approvalPhase: approvalPlan?.phase ?? null,
      approvalScopeDigest: approvalPlan?.approvedScopeDigest ?? null,
      approvalScopeIdentity: approvalPlan?.approvedScopeIdentity ?? null,
      approvalRequired: approvalPlan?.required ?? false,
      sanitizerBindingDigest: preparedPolicy?.policyBindingDigest ?? null,
      sanitizerId:
        sanitizerImplementation?.id ?? sanitizerSettings?.expectedSanitizerId ?? null,
      sanitizerProtocolVersion:
        sanitizerImplementation?.protocolVersion ??
        sanitizerSettings?.expectedProtocolVersion ??
        null,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
      requirementVerifierId: requirement.requirementVerifierId,
      requirementVerifierVersion: requirement.requirementVerifierVersion,
      consumerSourceCommit: requirement.consumerSourceCommit,
      requirementDecisionDigest: requirement.requirementDecisionDigest,
    });
    const attemptIdentity = computeAttemptIdentity({ runId, attemptKey });

    const approval = await executeApproval(
      approvalPlan,
      provider,
      requested,
      harnessVersion,
      harnessCommit,
      prepared.documentKind,
      prepared.metadata,
      requirement,
    );
    loaded = await loadBundleForRunner(
      options.bundleDirectory,
      inputStagingDirectory,
      options.contractSchemaPath,
    );
    assertBundleMatchesPreparation(prepared, loaded, identity);
    attemptRootHandle = await ensureAttemptRoot(attemptRoot, rootGuard.assertStable);
    await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
    const attemptDirectory = path.join(attemptRoot, attemptIdentity.attemptId);
    const claim = await claimAttemptDirectory(attemptDirectory);
    attemptClaim = claim;
    await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
    await prepareProviderTransport(provider, approval, approvalPlan?.timeoutMs);
    const providerResponse = await executeProvider(
      provider,
      loaded,
      identity,
      requested,
      harnessVersion,
      harnessCommit,
      providerTimeoutMs,
      phase,
      approval,
      requirement,
    );
    validateProviderApprovalAttestation(providerResponse.approval, approval);
    const providerMetadata = normalizeProviderMetadata(provider, requested, providerResponse);
    const sanitized = await executeSanitizer(
      requirement.sanitizerRequired ? sanitizerSettings : undefined,
      requirement.sanitizerRequired ? sanitizerImplementation : undefined,
      preparedPolicy,
      identity,
      loaded.documentKind,
      providerResponse,
      providerMetadata,
      {
        harnessVersion,
        harnessCommit,
        promptVersion: loaded.metadata.promptVersion,
        preprocessVersion: loaded.metadata.preprocessVersion,
        sourceCommit: loaded.metadata.sourceCommit,
      },
    );
    const schemaIssues = validateJsonSchema(loaded.inputs.schema.value, sanitized.document);
    if (schemaIssues.length > 0) {
      throw new RunnerError(
        "provider_document_schema_invalid",
        "sanitized document does not match the bundle output schema",
      );
    }

    const finishedAt = new Date().toISOString();
    const manifest: AttemptManifestBase = {
      attemptVersion: 1,
      attemptIdentityVersion: attemptIdentity.attemptIdentityVersion,
      attemptKey: attemptIdentity.attemptKey,
      attemptId: attemptIdentity.attemptId,
      runId,
      bundleVersion: 1,
      caseId: loaded.caseId,
      documentKind: loaded.documentKind,
      bundleManifestDigest: loaded.manifestDigest,
      inputs: {
        image: { sha256: loaded.inputs.image.sha256, mediaType: loaded.inputs.image.mediaType },
        schema: { sha256: loaded.inputs.schema.sha256, mediaType: loaded.inputs.schema.mediaType },
        system: { sha256: loaded.inputs.system.sha256, mediaType: loaded.inputs.system.mediaType },
        instruction: {
          sha256: loaded.inputs.instruction.sha256,
          mediaType: loaded.inputs.instruction.mediaType,
        },
      },
      caseInputIdentity: identity,
      sanitizerRequirement: requirement,
      provenance: {
        harnessVersion,
        harnessCommit,
        promptVersion: loaded.metadata.promptVersion,
        preprocessVersion: loaded.metadata.preprocessVersion,
        sourceCommit: loaded.metadata.sourceCommit,
      },
      run: {
        phase,
        providerId: provider.id,
        route: provider.route,
        implementationVersion: provider.implementationVersion,
        protocolVersion: provider.protocolVersion,
        requested,
        responded: providerMetadata.responded,
      },
      approval,
      stages: {
        approval: passedStage(),
        provider: passedStage(),
        parse: passedStage(),
        schemaValidation: passedStage(),
      },
      timing: {
        startedAt,
        finishedAt,
        durationMs: Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)),
      },
    };
    if (sanitized.manifest !== undefined) {
      manifest.sanitizer = sanitized.manifest;
      manifest.stages.policyTargetPreflight = passedStage();
      manifest.stages.sanitizer = passedStage();
      manifest.stages.targetBinding = passedStage();
    }

    await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
    const artifact = await writeAttemptFiles(
      claim,
      manifest,
      sanitized.document,
      async () => {
        try {
          await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
          return true;
        } catch {
          return false;
        }
      },
      async () => assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard),
    );
    return {
      phase,
      attemptDirectory: claim.attemptDirectory,
      attemptId: attemptIdentity.attemptId,
      runId,
      attemptKey: attemptIdentity.attemptKey,
      caseId: loaded.caseId,
      documentSha256: artifact.documentSha256,
    };
    } finally {
      if (attemptClaim !== undefined) {
        await cleanupAttemptClaim(attemptClaim, async () => {
          if (attemptRootGuard === undefined) return false;
          try {
            await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, attemptRootGuard);
            return true;
          } catch {
            return false;
          }
        });
      }
      await loaded?.cleanup().catch(() => undefined);
      await attemptRootHandle?.close().catch(() => undefined);
      await rm(temporaryParent, { recursive: true, force: true }).catch(() => undefined);
    }
  } finally {
    sanitizerSettings?.policyEnvelopeBytes?.fill(0);
  }
}

function normalizeAttemptKey(value: unknown): string {
  const attemptKey = value === undefined ? DEFAULT_ATTEMPT_KEY : value;
  if (typeof attemptKey !== "string" || !/^[A-Za-z0-9._-]{1,64}$/u.test(attemptKey)) {
    throw new RunnerError("run_configuration_invalid", "attempt key is invalid");
  }
  return attemptKey;
}

function assertBundleMatchesPreparation(
  prepared: Awaited<ReturnType<typeof prepareBundleForRunner>>,
  loaded: Awaited<ReturnType<typeof loadBundleForRunner>>,
  identity: CaseInputIdentity,
): void {
  const loadedIdentity = computeCaseInputIdentity({
    caseId: loaded.caseId,
    documentKind: loaded.documentKind,
    preparedImage: {
      mediaType: loaded.inputs.image.mediaType,
      sha256: loaded.inputs.image.sha256,
    },
  });
  if (
    prepared.manifestDigest !== loaded.manifestDigest ||
    prepared.caseId !== loaded.caseId ||
    prepared.documentKind !== loaded.documentKind ||
    prepared.image.sha256 !== loaded.inputs.image.sha256 ||
    prepared.image.mediaType !== loaded.inputs.image.mediaType ||
    identity.digest !== loadedIdentity.digest
  ) {
    throw new RunnerError(
      "runner_bundle_changed_after_approval",
      "bundle changed after approval",
    );
  }
}

function normalizeRequestedSettings(options: RunBundleOptions): RequestedExecutionSettings {
  const maxTokens = options.maxTokens ?? null;
  if (maxTokens !== null && (!Number.isSafeInteger(maxTokens) || maxTokens < 1)) {
    throw new RunnerError("run_configuration_invalid", "max tokens must be a positive safe integer");
  }
  return {
    model: normalizeOptionalSetting(options.requestedModel),
    effort: normalizeOptionalSetting(options.requestedEffort),
    maxTokens,
  };
}

function normalizeOptionalSetting(value: string | null | undefined): string | null {
  if (value === undefined || value === null) return null;
  if (!isSafeLabel(value)) {
    throw new RunnerError("run_configuration_invalid", "run setting is invalid");
  }
  return value;
}

function validateBoundarySettings(
  approval: ApprovalSettings | undefined,
  sanitizer: SanitizerSettings | undefined,
  sanitizerImplementation: ValidatedSanitizerImplementation | undefined,
): void {
  validateCommandSettings(approval, "approval_configuration_invalid");
  validateTimeoutSetting(approval?.timeoutMs, "approval_configuration_invalid");
  validateTimeoutSetting(sanitizer?.timeoutMs, "sanitizer_configuration_invalid");
  if (approval !== undefined && typeof approval.required !== "boolean") {
    throw new RunnerError("run_configuration_invalid", "approval configuration is invalid");
  }
  if (sanitizer !== undefined && typeof sanitizer.required !== "boolean") {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer configuration is invalid");
  }
  if (sanitizer?.expectedSanitizerId !== undefined && sanitizerImplementation === undefined) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedSanitizerId !== undefined &&
    sanitizerImplementation !== undefined &&
    sanitizer.expectedSanitizerId !== sanitizerImplementation.id
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedProtocolVersion !== undefined &&
    sanitizerImplementation !== undefined &&
    sanitizer.expectedProtocolVersion !== sanitizerImplementation.protocolVersion
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedProtocolVersion !== undefined &&
    sanitizerImplementation === undefined
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer protocol is invalid");
  }
  if (
    sanitizer?.expectedSanitizerId !== undefined &&
    !isSafeLabel(sanitizer.expectedSanitizerId)
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
}

function snapshotApprovalSettings(
  settings: ApprovalSettings | undefined,
): ApprovalSettings | undefined {
  if (settings === undefined) return undefined;
  try {
    const snapshot = { ...settings } as ApprovalSettings;
    if (Array.isArray(settings.argv)) snapshot.argv = [...settings.argv];
    if (Array.isArray(settings.envAllowlist)) {
      snapshot.envAllowlist = [...settings.envAllowlist];
    }
    return Object.freeze(snapshot);
  } catch {
    throw new RunnerError(
      "approval_configuration_invalid",
      "approval configuration is invalid",
    );
  }
}

function validateSanitizerImplementation(
  settings: SanitizerSettings | undefined,
): ValidatedSanitizerImplementation | undefined {
  try {
    const value: unknown = settings?.sanitizer;
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "object") throw new Error();
    const sanitizer = value as { id?: unknown; protocolVersion?: unknown; sanitize?: unknown };
    const id = sanitizer.id;
    const protocolVersion = sanitizer.protocolVersion;
    const sanitize = sanitizer.sanitize;
    if (
      typeof id !== "string" ||
      !isSafeLabel(id) ||
      protocolVersion !== 1 ||
      typeof sanitize !== "function"
    ) {
      throw new Error();
    }
    return Object.freeze({
      id,
      protocolVersion: 1,
      sanitize: Function.prototype.bind.call(sanitize, value) as Sanitizer["sanitize"],
    });
  } catch {
    throw new RunnerError(
      "sanitizer_configuration_invalid",
      "sanitizer implementation is invalid",
    );
  }
}

function snapshotSanitizerSettings(
  settings: SanitizerSettings | undefined,
  sanitizer: ValidatedSanitizerImplementation | undefined,
): SanitizerSettings | undefined {
  if (settings === undefined) return undefined;
  try {
    const snapshot = { ...settings } as SanitizerSettings;
    if (sanitizer === undefined) {
      delete snapshot.sanitizer;
    } else {
      snapshot.sanitizer = sanitizer;
    }
    if (snapshot.policyEnvelopeBytes !== undefined) {
      if (!(snapshot.policyEnvelopeBytes instanceof Uint8Array)) throw new Error();
      snapshot.policyEnvelopeBytes = Uint8Array.from(snapshot.policyEnvelopeBytes);
    }
    return Object.freeze(snapshot);
  } catch {
    throw new RunnerError(
      "sanitizer_configuration_invalid",
      "sanitizer configuration is invalid",
    );
  }
}

function verifySanitizerRequirement(
  settings: RunBundleOptions["sanitizerRequirement"],
  documentKind: string,
): SanitizerRequirementDecisionV1 {
  try {
    if (
      settings === null ||
      typeof settings !== "object" ||
      settings.verifier === null ||
      typeof settings.verifier !== "object" ||
      typeof settings.verifier.id !== "string" ||
      !isSafeLabel(settings.verifier.id) ||
      typeof settings.verifier.version !== "string" ||
      !isSafeLabel(settings.verifier.version) ||
      typeof settings.verifier.derive !== "function"
    ) {
      throw new Error();
    }
    const core = settings.verifier.derive(documentKind);
    if (
      core === null ||
      typeof core !== "object" ||
      typeof core.sanitizerRequired !== "boolean" ||
      typeof core.policyRequired !== "boolean" ||
      !isSafeLabel(core.sanitizerRequirementReason) ||
      (core.consumerSourceCommit !== null && !isSafeLabel(core.consumerSourceCommit)) ||
      core.sanitizerRequired !== core.policyRequired
    ) {
      throw new Error();
    }
    const expected = createSanitizerRequirementDecision(core, settings.verifier);
    const actual = settings.decision;
    const expectedKeys = new Set([
      "sanitizerRequirementVersion",
      "sanitizerRequired",
      "policyRequired",
      "sanitizerRequirementReason",
      "requirementVerifierId",
      "requirementVerifierVersion",
      "consumerSourceCommit",
      "requirementDecisionDigest",
    ]);
    if (
      actual === null ||
      typeof actual !== "object" ||
      Object.keys(actual).length !== expectedKeys.size ||
      Object.keys(actual).some((key) => !expectedKeys.has(key)) ||
      actual.sanitizerRequirementVersion !== expected.sanitizerRequirementVersion ||
      actual.sanitizerRequired !== expected.sanitizerRequired ||
      actual.policyRequired !== expected.policyRequired ||
      actual.sanitizerRequirementReason !== expected.sanitizerRequirementReason ||
      actual.requirementVerifierId !== expected.requirementVerifierId ||
      actual.requirementVerifierVersion !== expected.requirementVerifierVersion ||
      actual.consumerSourceCommit !== expected.consumerSourceCommit ||
      actual.requirementDecisionDigest !== expected.requirementDecisionDigest
    ) {
      throw new Error();
    }
    return freezeObject({ ...expected });
  } catch {
    throw new RunnerError("sanitizer_requirement_invalid", "sanitizer requirement decision is invalid");
  }
}

function validateSanitizerRequirementSettings(
  requirement: SanitizerRequirementDecisionV1,
  sanitizer: SanitizerSettings | undefined,
  sanitizerImplementation: ValidatedSanitizerImplementation | undefined,
): void {
  if (!requirement.sanitizerRequired) {
    if (sanitizer !== undefined) {
      throw new RunnerError(
        "sanitizer_configuration_invalid",
        "sanitizer configuration is not permitted for this decision",
      );
    }
    return;
  }
  if (sanitizer === undefined || !sanitizer.required || sanitizerImplementation === undefined) {
    throw new RunnerError("sanitizer_required", "required sanitizer is missing");
  }
  if (
    typeof sanitizer.expectedSanitizerId !== "string" ||
    !isSafeLabel(sanitizer.expectedSanitizerId) ||
    sanitizer.expectedProtocolVersion !== 1 ||
    typeof sanitizer.expectedPolicyVersion !== "number" ||
    !Number.isSafeInteger(sanitizer.expectedPolicyVersion) ||
    sanitizer.expectedPolicyVersion < 1 ||
    typeof sanitizer.expectedPolicyDigest !== "string" ||
    !isDigest(sanitizer.expectedPolicyDigest) ||
    sanitizer.expectedCaseInputIdentityVersion !== 1 ||
    typeof sanitizer.expectedCaseInputIdentityDigest !== "string" ||
    !isDigest(sanitizer.expectedCaseInputIdentityDigest) ||
    typeof sanitizer.expectedPolicyBindingDigest !== "string" ||
    !isDigest(sanitizer.expectedPolicyBindingDigest)
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer configuration is incomplete");
  }
}

function validateCommandSettings(
  settings:
    | Pick<ApprovalSettings, "executable" | "argv" | "envAllowlist" | "outputLimitBytes">
    | undefined,
  errorCode: "approval_configuration_invalid" | "sanitizer_configuration_invalid",
): void {
  if (settings === undefined) return;
  if (
    (settings.executable !== undefined &&
      (typeof settings.executable !== "string" ||
        settings.executable.length === 0 ||
        settings.executable.length > 240)) ||
    (settings.argv !== undefined &&
      (!Array.isArray(settings.argv) ||
        settings.argv.length > 64 ||
        settings.argv.some((value) => typeof value !== "string" || value.length > 240))) ||
    (settings.envAllowlist !== undefined &&
      (!Array.isArray(settings.envAllowlist) ||
        settings.envAllowlist.length > 64 ||
        settings.envAllowlist.some(
          (value) =>
            typeof value !== "string" ||
            !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(value),
        ))) ||
    (settings.outputLimitBytes !== undefined &&
      (!Number.isSafeInteger(settings.outputLimitBytes) ||
        settings.outputLimitBytes < 1 ||
        settings.outputLimitBytes > 16 * 1024 * 1024))
  ) {
    throw new RunnerError(errorCode, "command configuration is invalid");
  }
}

function validateTimeoutSetting(
  timeoutMs: number | undefined,
  errorCode:
    | "run_configuration_invalid"
    | "approval_configuration_invalid"
    | "sanitizer_configuration_invalid",
): void {
  if (
    timeoutMs !== undefined &&
    (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS)
  ) {
    throw new RunnerError(errorCode, "timeout is invalid");
  }
}

function validateProvider(provider: Provider): ValidatedProvider {
  try {
    const value: unknown = provider;
    if (
      value === null ||
      typeof value !== "object"
    ) {
      throw new Error();
    }
    const implementation = value as {
      id?: unknown;
      route?: unknown;
      implementationVersion?: unknown;
      protocolVersion?: unknown;
      prepareTransport?: unknown;
      invoke?: unknown;
    };
    const id = implementation.id;
    const route = implementation.route;
    const implementationVersion = implementation.implementationVersion;
    const protocolVersion = implementation.protocolVersion;
    const prepareTransport = implementation.prepareTransport;
    const invoke = implementation.invoke;
    const awaitAbort = isAbortSettlingCommandProvider(value);
    if (
      typeof id !== "string" ||
      !isSafeLabel(id) ||
      typeof route !== "string" ||
      !isSafeLabel(route) ||
      (prepareTransport !== undefined && typeof prepareTransport !== "function") ||
      typeof invoke !== "function" ||
      (implementationVersion !== undefined &&
        implementationVersion !== null &&
        (typeof implementationVersion !== "string" ||
          !isSafeLabel(implementationVersion))) ||
      (protocolVersion !== undefined &&
        protocolVersion !== null &&
        (typeof protocolVersion !== "string" || !isSafeLabel(protocolVersion)))
    ) {
      throw new Error();
    }
    return Object.freeze({
      id,
      route,
      implementationVersion: implementationVersion ?? null,
      protocolVersion: protocolVersion ?? null,
      awaitAbort,
      ...(prepareTransport === undefined
        ? {}
        : {
            prepareTransport: Function.prototype.bind.call(
              prepareTransport,
              value,
            ) as NonNullable<Provider["prepareTransport"]>,
          }),
      invoke: Function.prototype.bind.call(invoke, value) as Provider["invoke"],
    });
  } catch {
    throw new RunnerError("provider_invalid", "provider configuration is invalid");
  }
}

function isSafeLabel(value: string): boolean {
  return value.length > 0 && value.length <= 64 && /^[A-Za-z0-9._-]+$/u.test(value);
}

function validateApprovalSettings(
  settings: ApprovalSettings | undefined,
  requirement: SanitizerRequirementDecisionV1,
): ValidatedApprovalPlan | undefined {
  if (settings === undefined) return undefined;
  try {
    const configuredGate = settings.gate;
    const hasCommand = settings.executable !== undefined;
    if (configuredGate !== undefined && hasCommand) throw new Error();
    if (configuredGate === undefined && !hasCommand) {
      if (settings.required) {
        throw new RunnerError("approval_required", "approval gate is required");
      }
      if (Object.keys(settings).some((key) => key !== "required")) throw new Error();
      return undefined;
    }
    const expectedGateId = settings.expectedGateId;
    const snapshotDigest = settings.snapshotDigest;
    const runtimeBindingDigest = settings.runtimeBindingDigest;
    const runtimeBindingIdentity = settings.runtimeBindingIdentity;
    const approvedScopeDigest = settings.approvedScopeDigest;
    const approvedScopeIdentity = settings.approvedScopeIdentity;
    const phase = settings.phase;
    if (
      typeof expectedGateId !== "string" ||
      !isSafeLabel(expectedGateId) ||
      settings.expectedProtocolVersion !== 1 ||
      !isDigest(snapshotDigest) ||
      !isDigest(runtimeBindingDigest) ||
      typeof runtimeBindingIdentity !== "string" ||
      !isSafeLabel(runtimeBindingIdentity) ||
      !isDigest(approvedScopeDigest) ||
      typeof approvedScopeIdentity !== "string" ||
      !isSafeLabel(approvedScopeIdentity) ||
      typeof phase !== "string" ||
      !isSafeLabel(phase) ||
      settings.expectedRequirementVerifierId !== requirement.requirementVerifierId ||
      settings.expectedRequirementVerifierVersion !== requirement.requirementVerifierVersion ||
      !Object.hasOwn(settings, "expectedConsumerSourceCommit") ||
      settings.expectedConsumerSourceCommit !== requirement.consumerSourceCommit ||
      settings.expectedRequirementDecisionDigest !== requirement.requirementDecisionDigest ||
      settings.expectedSanitizerRequirementVersion !== requirement.sanitizerRequirementVersion ||
      settings.expectedSanitizerRequired !== requirement.sanitizerRequired ||
      settings.expectedPolicyRequired !== requirement.policyRequired ||
      settings.expectedSanitizerRequirementReason !== requirement.sanitizerRequirementReason
    ) {
      throw new Error();
    }
    const gate =
      configuredGate ??
      createCommandApprovalGate({
        executable: settings.executable!,
        argv: settings.argv ?? [],
        envAllowlist: settings.envAllowlist ?? [],
        outputLimitBytes:
          settings.outputLimitBytes ?? DEFAULT_APPROVAL_OUTPUT_LIMIT_BYTES,
        gateId: expectedGateId,
      });
    if (
      configuredGate !== undefined &&
      (settings.argv !== undefined ||
        settings.envAllowlist !== undefined ||
        settings.outputLimitBytes !== undefined)
    ) {
      throw new Error();
    }
    const approve = gate.approve;
    if (
      gate.id !== expectedGateId ||
      gate.protocolVersion !== 1 ||
      typeof approve !== "function"
    ) {
      throw new Error();
    }
    const gateSnapshot = Object.freeze({
      id: gate.id,
      protocolVersion: 1 as const,
      approve: Function.prototype.bind.call(approve, gate) as NonNullable<
        ApprovalSettings["gate"]
      >["approve"],
    });
    return Object.freeze({
      required: settings.required,
      gate: gateSnapshot,
      expectedGateId,
      expectedProtocolVersion: 1 as const,
      snapshotDigest,
      runtimeBindingDigest,
      runtimeBindingIdentity,
      approvedScopeDigest,
      approvedScopeIdentity,
      phase,
      ...(settings.timeoutMs === undefined ? {} : { timeoutMs: settings.timeoutMs }),
    });
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError(
      "approval_configuration_invalid",
      "approval configuration is invalid",
    );
  }
}

function validateProviderTransportPreparation(
  provider: ValidatedProvider,
  approval: ValidatedApprovalPlan | undefined,
): void {
  if (approval !== undefined && provider.prepareTransport === undefined) {
    throw new RunnerError(
      "approval_configuration_invalid",
      "provider transport approval boundary is missing",
    );
  }
}

async function executeApproval(
  settings: ValidatedApprovalPlan | undefined,
  providerIdentity: ProviderIdentity,
  requested: RequestedExecutionSettings,
  harnessVersion: string,
  harnessCommit: string | null,
  documentKind: string,
  provenance: {
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  },
  requirement: SanitizerRequirementDecisionV1,
): Promise<AttemptManifest["approval"]> {
  if (settings === undefined) {
    return {
      required: false,
      applied: false,
      gateId: null,
      protocolVersion: null,
      snapshotDigest: null,
      runtimeBindingDigest: null,
      runtimeBindingIdentity: null,
      approvedScopeDigest: null,
      approvedScopeIdentity: null,
      phase: null,
      requirementVerifierId: null,
      requirementVerifierVersion: null,
      consumerSourceCommit: null,
      requirementDecisionDigest: null,
      sanitizerRequirementVersion: null,
      sanitizerRequired: null,
      policyRequired: null,
      sanitizerRequirementReason: null,
      checkedAt: null,
      expiresAt: null,
      reasonCode: null,
    };
  }
  const request: ApprovalRequest = freezeObject({
    requestVersion: 1,
    provider: freezeObject({
      id: providerIdentity.id,
      route: providerIdentity.route,
      implementationVersion: providerIdentity.implementationVersion,
      protocolVersion: providerIdentity.protocolVersion,
    }),
    requested: freezeObject({ ...requested }),
    harness: freezeObject({ version: harnessVersion, commit: harnessCommit }),
    documentKind,
    phase: settings.phase,
    provenance: freezeObject({ ...provenance }),
    sanitizerRequirement: freezeObject({
      sanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
    }),
    expected: freezeObject({
      gateId: settings.expectedGateId,
      protocolVersion: settings.expectedProtocolVersion,
      snapshotDigest: settings.snapshotDigest,
      runtimeBindingDigest: settings.runtimeBindingDigest,
      runtimeBindingIdentity: settings.runtimeBindingIdentity,
      approvedScopeDigest: settings.approvedScopeDigest,
      approvedScopeIdentity: settings.approvedScopeIdentity,
      requirementVerifierId: requirement.requirementVerifierId,
      requirementVerifierVersion: requirement.requirementVerifierVersion,
      consumerSourceCommit: requirement.consumerSourceCommit,
      requirementDecisionDigest: requirement.requirementDecisionDigest,
    }),
  });
  let responseValue: ApprovalResponse;
  try {
    const controller = new AbortController();
    responseValue = await withTimeout(
      () => settings.gate.approve(request, controller.signal),
      settings.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
      "approval_timeout",
      () => controller.abort(),
    );
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("approval_response_invalid", "approval gate failed");
  }
  let response: ApprovalResponse;
  try {
    response = snapshotApprovalResponse(responseValue);
    if (
      response.responseVersion !== 1 ||
      typeof response.approved !== "boolean" ||
      response.gateId !== settings.expectedGateId ||
      response.protocolVersion !== settings.expectedProtocolVersion ||
      response.snapshotDigest !== settings.snapshotDigest ||
      response.runtimeBindingDigest !== settings.runtimeBindingDigest ||
      response.runtimeBindingIdentity !== settings.runtimeBindingIdentity ||
      response.approvedScopeDigest !== settings.approvedScopeDigest ||
      response.approvedScopeIdentity !== settings.approvedScopeIdentity ||
      response.phase !== settings.phase ||
      response.requirementVerifierId !== requirement.requirementVerifierId ||
      response.requirementVerifierVersion !== requirement.requirementVerifierVersion ||
      response.consumerSourceCommit !== requirement.consumerSourceCommit ||
      response.requirementDecisionDigest !== requirement.requirementDecisionDigest ||
      response.sanitizerRequirementVersion !== requirement.sanitizerRequirementVersion ||
      response.sanitizerRequired !== requirement.sanitizerRequired ||
      response.policyRequired !== requirement.policyRequired ||
      response.sanitizerRequirementReason !== requirement.sanitizerRequirementReason ||
      (response.reasonCode !== undefined && !isSafeLabel(response.reasonCode)) ||
      !isOptionalDateTime(response.checkedAt) ||
      !isOptionalDateTime(response.expiresAt)
    ) {
      throw new Error();
    }
  } catch {
    throw internalRunnerError("approval_response_invalid", "approval response is invalid");
  }
  if (!response.approved) {
    throw new RunnerError("approval_denied", "approval gate denied this run");
  }
  assertApprovalNotExpired(response.expiresAt);
  return {
    required: settings.required,
    applied: true,
    gateId: response.gateId,
    protocolVersion: response.protocolVersion,
    snapshotDigest: response.snapshotDigest,
    runtimeBindingDigest: response.runtimeBindingDigest,
    runtimeBindingIdentity: response.runtimeBindingIdentity,
    approvedScopeDigest: response.approvedScopeDigest,
    approvedScopeIdentity: response.approvedScopeIdentity,
    phase: response.phase,
    requirementVerifierId: response.requirementVerifierId,
    requirementVerifierVersion: response.requirementVerifierVersion,
    consumerSourceCommit: response.consumerSourceCommit,
    requirementDecisionDigest: response.requirementDecisionDigest,
    sanitizerRequirementVersion: response.sanitizerRequirementVersion,
    sanitizerRequired: response.sanitizerRequired,
    policyRequired: response.policyRequired,
    sanitizerRequirementReason: response.sanitizerRequirementReason,
    checkedAt: response.checkedAt ?? null,
    expiresAt: response.expiresAt ?? null,
    reasonCode: response.reasonCode ?? null,
  };
}

async function prepareProviderTransport(
  provider: ValidatedProvider,
  approval: AttemptManifest["approval"],
  timeoutMs: number | undefined,
): Promise<void> {
  if (!approval.applied) return;
  const expected = approvalManifestResponse(approval);
  assertApprovalNotExpired(expected.expiresAt);
  let responseValue: ApprovalResponse;
  try {
    const controller = new AbortController();
    responseValue = await withTimeout(
      () => provider.prepareTransport!(expected, controller.signal),
      timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
      "approval_timeout",
      () => controller.abort(),
      provider.awaitAbort,
    );
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError(
      "approval_response_invalid",
      "provider transport approval failed",
    );
  }
  let response: ApprovalResponse;
  try {
    response = snapshotApprovalResponse(responseValue);
  } catch {
    throw internalRunnerError(
      "approval_response_invalid",
      "provider transport approval is invalid",
    );
  }
  validateProviderApprovalAttestation(response, approval);
  assertApprovalNotExpired(response.expiresAt);
}

function approvalManifestResponse(
  approval: AttemptManifest["approval"],
): ApprovalResponse {
  if (
    !approval.applied ||
    approval.gateId === null ||
    approval.protocolVersion === null ||
    approval.snapshotDigest === null ||
    approval.runtimeBindingDigest === null ||
    approval.runtimeBindingIdentity === null ||
    approval.approvedScopeDigest === null ||
    approval.approvedScopeIdentity === null ||
    approval.phase === null ||
    approval.requirementVerifierId === null ||
    approval.requirementVerifierVersion === null ||
    approval.requirementDecisionDigest === null ||
    approval.sanitizerRequirementVersion === null ||
    approval.sanitizerRequired === null ||
    approval.policyRequired === null ||
    approval.sanitizerRequirementReason === null
  ) {
    throw internalRunnerError(
      "approval_response_invalid",
      "provider transport approval is incomplete",
    );
  }
  return Object.freeze({
    responseVersion: 1,
    approved: true,
    gateId: approval.gateId,
    protocolVersion: approval.protocolVersion,
    snapshotDigest: approval.snapshotDigest,
    runtimeBindingDigest: approval.runtimeBindingDigest,
    runtimeBindingIdentity: approval.runtimeBindingIdentity,
    approvedScopeDigest: approval.approvedScopeDigest,
    approvedScopeIdentity: approval.approvedScopeIdentity,
    phase: approval.phase,
    requirementVerifierId: approval.requirementVerifierId,
    requirementVerifierVersion: approval.requirementVerifierVersion,
    consumerSourceCommit: approval.consumerSourceCommit,
    requirementDecisionDigest: approval.requirementDecisionDigest,
    sanitizerRequirementVersion: approval.sanitizerRequirementVersion,
    sanitizerRequired: approval.sanitizerRequired,
    policyRequired: approval.policyRequired,
    sanitizerRequirementReason: approval.sanitizerRequirementReason,
    checkedAt: approval.checkedAt,
    expiresAt: approval.expiresAt,
    ...(approval.reasonCode === null ? {} : { reasonCode: approval.reasonCode }),
  });
}

function assertApprovalNotExpired(expiresAt: string | null | undefined): void {
  if (expiresAt !== undefined && expiresAt !== null && Date.parse(expiresAt) <= Date.now()) {
    throw new RunnerError("approval_denied", "approval gate denied this run");
  }
}

function snapshotApprovalResponse(value: unknown): ApprovalResponse {
  if (value === null || typeof value !== "object") throw new Error();
  const required = [
    "responseVersion",
    "approved",
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
  ] as const;
  const allowed = new Set<string>([
    ...required,
    "checkedAt",
    "expiresAt",
    "reasonCode",
  ]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new Error();
  }
  const response = value as ApprovalResponse;
  return Object.freeze({
    responseVersion: response.responseVersion,
    approved: response.approved,
    gateId: response.gateId,
    protocolVersion: response.protocolVersion,
    snapshotDigest: response.snapshotDigest,
    runtimeBindingDigest: response.runtimeBindingDigest,
    runtimeBindingIdentity: response.runtimeBindingIdentity,
    approvedScopeDigest: response.approvedScopeDigest,
    approvedScopeIdentity: response.approvedScopeIdentity,
    phase: response.phase,
    requirementVerifierId: response.requirementVerifierId,
    requirementVerifierVersion: response.requirementVerifierVersion,
    consumerSourceCommit: response.consumerSourceCommit,
    requirementDecisionDigest: response.requirementDecisionDigest,
    sanitizerRequirementVersion: response.sanitizerRequirementVersion,
    sanitizerRequired: response.sanitizerRequired,
    policyRequired: response.policyRequired,
    sanitizerRequirementReason: response.sanitizerRequirementReason,
    ...(Object.hasOwn(value, "checkedAt") ? { checkedAt: response.checkedAt } : {}),
    ...(Object.hasOwn(value, "expiresAt") ? { expiresAt: response.expiresAt } : {}),
    ...(Object.hasOwn(value, "reasonCode") ? { reasonCode: response.reasonCode } : {}),
  });
}

function isOptionalDateTime(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/u.exec(
    value,
  );
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  return match[7] === "Z" || (Number(match[8]) <= 23 && Number(match[9]) <= 59);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

async function executeProvider(
  provider: ValidatedProvider,
  loaded: Awaited<ReturnType<typeof loadBundleForRunner>>,
  identity: CaseInputIdentity,
  requested: RequestedExecutionSettings,
  harnessVersion: string,
  harnessCommit: string | null,
  providerTimeoutMs: number | undefined,
  phase: string,
  approval: AttemptManifest["approval"],
  sanitizerRequirement: SanitizerRequirementDecisionV1,
): Promise<NormalizedProviderResponse> {
  const controller = new AbortController();
  let active = true;
  try {
    const readBytes = async (reader: () => Promise<Buffer>): Promise<Buffer> => {
      if (!active || controller.signal.aborted) throw new Error();
      assertTransportApprovalActive(approval.expiresAt);
      return reader();
    };
    const readText = async (reader: () => Promise<string>): Promise<string> => {
      if (!active || controller.signal.aborted) throw new Error();
      assertTransportApprovalActive(approval.expiresAt);
      return reader();
    };
    const request = {
      image: Object.freeze({
        mediaType: loaded.inputs.image.mediaType,
        readBytes: () => readBytes(loaded.inputs.image.readBytes),
      }),
      schema: freezeObject(normalizeJsonValue(loaded.inputs.schema.value, "provider schema", MAX_DOCUMENT_BYTES)),
      schemaInput: Object.freeze({
        mediaType: loaded.inputs.schema.mediaType,
        readBytes: () => readBytes(loaded.inputs.schema.readBytes),
      }),
      system: Object.freeze({
        mediaType: loaded.inputs.system.mediaType,
        readText: () => readText(loaded.inputs.system.readText),
      }),
      instruction: Object.freeze({
        mediaType: loaded.inputs.instruction.mediaType,
        readText: () => readText(loaded.inputs.instruction.readText),
      }),
      requested: freezeObject({ ...requested }),
    } satisfies ProviderModelRequest;
    const context: ProviderAdapterContext = freezeObject({
      phase,
      bundle: freezeObject({
        version: loaded.bundleVersion,
        manifestDigest: loaded.manifestDigest,
      }),
      caseId: loaded.caseId,
      documentKind: loaded.documentKind,
      caseInputIdentity: freezeObject({
        identityVersion: identity.identityVersion,
        caseId: identity.caseId,
        documentKind: identity.documentKind,
        preparedImage: freezeObject({ ...identity.preparedImage }),
        digest: identity.digest,
      }),
      inputDigests: freezeObject({
        image: loaded.inputs.image.sha256,
        schema: loaded.inputs.schema.sha256,
        system: loaded.inputs.system.sha256,
        instruction: loaded.inputs.instruction.sha256,
      }),
      requested: freezeObject({ ...requested }),
      provenance: freezeObject({
        harnessVersion,
        harnessCommit,
        promptVersion: loaded.metadata.promptVersion,
        preprocessVersion: loaded.metadata.preprocessVersion,
        sourceCommit: loaded.metadata.sourceCommit,
      }),
      sanitizerRequirement: freezeObject({ ...sanitizerRequirement }),
      approval: approval.applied ? approvalManifestResponse(approval) : null,
    });
    assertTransportApprovalActive(approval.expiresAt);
    const response = await withTimeout(
      () => provider.invoke(request, context, controller.signal),
      providerTimeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS,
      "provider_timeout",
      () => {
        active = false;
        controller.abort();
      },
      provider.awaitAbort,
    );
    active = false;
    if (response === null || typeof response !== "object" || !Object.hasOwn(response, "rawDocument")) {
      throw internalRunnerError("provider_response_invalid", "provider response is invalid");
    }
    const metadata = normalizeProviderResponseMetadata(response);
    return {
      document: parseProviderOutput(response.rawDocument),
      approval: readProviderApprovalAttestation(response),
      ...metadata,
    };
  } catch (error) {
    active = false;
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("provider_failed", "provider invocation failed");
  } finally {
    active = false;
    controller.abort();
  }
}

function assertTransportApprovalActive(expiresAt: string | null): void {
  if (expiresAt !== null && Date.parse(expiresAt) <= Date.now()) {
    throw internalRunnerError("approval_denied", "approval gate denied this run");
  }
}

function readProviderApprovalAttestation(
  response: ProviderResponse,
): ApprovalResponse | undefined {
  try {
    const approval = response.approval;
    return approval === undefined ? undefined : snapshotApprovalResponse(approval);
  } catch {
    throw internalRunnerError(
      "approval_response_invalid",
      "provider approval attestation is invalid",
    );
  }
}

function validateProviderApprovalAttestation(
  response: ApprovalResponse | undefined,
  approval: AttemptManifest["approval"],
): void {
  if (response === undefined) return;
  try {
    if (
      !approval.applied ||
      response === null ||
      typeof response !== "object" ||
      response.responseVersion !== 1 ||
      response.approved !== true ||
      response.gateId !== approval.gateId ||
      response.protocolVersion !== approval.protocolVersion ||
      response.snapshotDigest !== approval.snapshotDigest ||
      response.runtimeBindingDigest !== approval.runtimeBindingDigest ||
      response.runtimeBindingIdentity !== approval.runtimeBindingIdentity ||
      response.approvedScopeDigest !== approval.approvedScopeDigest ||
      response.approvedScopeIdentity !== approval.approvedScopeIdentity ||
      response.phase !== approval.phase ||
      response.requirementVerifierId !== approval.requirementVerifierId ||
      response.requirementVerifierVersion !== approval.requirementVerifierVersion ||
      response.consumerSourceCommit !== approval.consumerSourceCommit ||
      response.requirementDecisionDigest !== approval.requirementDecisionDigest ||
      response.sanitizerRequirementVersion !== approval.sanitizerRequirementVersion ||
      response.sanitizerRequired !== approval.sanitizerRequired ||
      response.policyRequired !== approval.policyRequired ||
      response.sanitizerRequirementReason !== approval.sanitizerRequirementReason ||
      (response.checkedAt ?? null) !== approval.checkedAt ||
      (response.expiresAt ?? null) !== approval.expiresAt ||
      (response.reasonCode ?? null) !== approval.reasonCode
    ) {
      throw new Error();
    }
  } catch {
    throw internalRunnerError(
      "approval_response_invalid",
      "provider approval attestation is invalid",
    );
  }
}

function normalizeProviderMetadata(
  providerIdentity: ProviderIdentity,
  requested: RequestedExecutionSettings,
  response: NormalizedProviderResponse,
): {
  responded: AttemptManifest["run"]["responded"];
  sanitizerProvider: {
    id: string;
    route: string;
    requested: RequestedExecutionSettings;
    respondedModel: string | null;
    effectiveEffort: string | null;
    usage: ProviderUsage;
    stopReason: string | null;
  };
} {
  const respondedModel = nullableSafeLabel(response.respondedModel);
  const effectiveEffort = nullableSafeLabel(response.effectiveEffort);
  const stopReason = nullableSafeLabel(response.stopReason);
  const usage = response.usage;
  const responded = { model: respondedModel, effort: effectiveEffort, usage, stopReason };
  return {
    responded,
    sanitizerProvider: {
      id: providerIdentity.id,
      route: providerIdentity.route,
      requested,
      respondedModel,
      effectiveEffort,
      usage,
      stopReason,
    },
  };
}

function normalizeProviderResponseMetadata(response: ProviderResponse): {
  respondedModel: string | null;
  effectiveEffort: string | null;
  usage: ProviderUsage;
  stopReason: string | null;
} {
  try {
    return {
      respondedModel: nullableSafeLabel(response.respondedModel),
      effectiveEffort: nullableSafeLabel(response.effectiveEffort),
      usage: normalizeUsage(response.usage),
      stopReason: nullableSafeLabel(response.stopReason),
    };
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("provider_response_invalid", "provider response metadata is invalid");
  }
}

async function executeSanitizer(
  settings: SanitizerSettings | undefined,
  sanitizer: ValidatedSanitizerImplementation | undefined,
  preparedPolicy: PreparedSanitizerPolicy | undefined,
  identity: CaseInputIdentity,
  documentKind: string,
  providerResponse: NormalizedProviderResponse,
  providerMetadata: ReturnType<typeof normalizeProviderMetadata>,
  provenance: {
    harnessVersion: string;
    harnessCommit: string | null;
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  },
): Promise<{
  document: JsonValue;
  manifest: NonNullable<AttemptManifest["sanitizer"]> | undefined;
}> {
  if (preparedPolicy === undefined) {
    return {
      document: normalizeJsonValue(
        providerResponse.document,
        "formal provider document",
        MAX_DOCUMENT_BYTES,
      ),
      manifest: undefined,
    };
  }
  if (settings === undefined) {
    throw new RunnerError("sanitizer_required", "sanitizer configuration is missing");
  }
  if (sanitizer === undefined) {
    throw new RunnerError("sanitizer_required", "sanitizer implementation is missing");
  }
  let response: SanitizerResponse;
  try {
    const controller = new AbortController();
    const request = freezeObject({
      caseInputIdentity: freezeObject({
        identityVersion: identity.identityVersion,
        caseId: identity.caseId,
        documentKind: identity.documentKind,
        preparedImage: freezeObject({ ...identity.preparedImage }),
        digest: identity.digest,
      }),
      documentKind,
      document: freezeObject(normalizeJsonValue(providerResponse.document, "sanitizer document", MAX_DOCUMENT_BYTES)),
      policyEnvelope: freezeObject(normalizeJsonRecord(preparedPolicy.envelope, "sanitizer policy")),
      policy: freezeObject(normalizeJsonRecord(preparedPolicy.policy, "sanitizer policy")),
      policyVersion: preparedPolicy.policyVersion,
      policyDigest: preparedPolicy.policyDigest,
      policyBindingDigest: preparedPolicy.policyBindingDigest,
      provider: freezeObject({
        id: providerMetadata.sanitizerProvider.id,
        route: providerMetadata.sanitizerProvider.route,
        requested: freezeObject({ ...providerMetadata.sanitizerProvider.requested }),
        respondedModel: providerMetadata.sanitizerProvider.respondedModel,
        effectiveEffort: providerMetadata.sanitizerProvider.effectiveEffort,
        usage: freezeObject({ ...providerMetadata.sanitizerProvider.usage }),
        stopReason: providerMetadata.sanitizerProvider.stopReason,
      }),
      provenance: freezeObject({ ...provenance }),
    });
    const responseValue = await withTimeout(
      () => sanitizer.sanitize(request, controller.signal),
      settings.timeoutMs ?? DEFAULT_SANITIZER_TIMEOUT_MS,
      "sanitizer_timeout",
      () => controller.abort(),
    );
    response = snapshotSanitizerResponse(responseValue);
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("sanitizer_failed", "sanitizer failed");
  }
  try {
    if (
      response === null ||
      typeof response !== "object" ||
      response.sanitizerId !== sanitizer.id ||
      response.protocolVersion !== sanitizer.protocolVersion ||
      response.policyVersion !== preparedPolicy.policyVersion ||
      response.policyDigest !== preparedPolicy.policyDigest ||
      response.caseInputIdentityVersion !== identity.identityVersion ||
      response.caseInputIdentityDigest !== identity.digest ||
      response.policyTargetIdentityDigest !== preparedPolicy.policyTargetIdentityDigest ||
      response.policyBindingDigest !== preparedPolicy.policyBindingDigest
    ) {
      throw new Error();
    }
    const sanitizedDocument = normalizeJsonValue(
      response.sanitizedDocument,
      "sanitizer document",
      MAX_DOCUMENT_BYTES,
    );
    return {
      document: sanitizedDocument,
      manifest: {
        required: true,
        applied: true,
        id: response.sanitizerId,
        protocolVersion: response.protocolVersion,
        policyVersion: response.policyVersion,
        policyDigest: response.policyDigest,
        policyTargetIdentityDigest: response.policyTargetIdentityDigest,
        policyBindingIdentity: preparedPolicy.policyBindingIdentity,
        policyBindingDigest: response.policyBindingDigest,
        findings: normalizeFindings(response.findings),
      },
    };
  } catch {
    throw internalRunnerError("sanitizer_response_invalid", "sanitizer response is invalid");
  }
}

function normalizeFindings(findings: SanitizerFinding[] | undefined): SanitizerFinding[] {
  if (findings === undefined) return [];
  if (!Array.isArray(findings) || findings.length > 100) {
    throw new RunnerError("sanitizer_response_invalid", "sanitizer findings are invalid");
  }
  return findings.map((finding) => {
    const allowedKeys = new Set(["code", "severity", "classification", "hardGate", "path"]);
    if (
      !isJsonObject(finding) ||
      Object.keys(finding).some((key) => !allowedKeys.has(key)) ||
      !Object.hasOwn(finding, "code") ||
      !Object.hasOwn(finding, "severity") ||
      !Object.hasOwn(finding, "classification") ||
      !Object.hasOwn(finding, "hardGate") ||
      typeof finding.code !== "string" ||
      !isSafeLabel(finding.code) ||
      (finding.severity !== "info" &&
        finding.severity !== "warning" &&
        finding.severity !== "error") ||
      typeof finding.classification !== "string" ||
      !isSafeLabel(finding.classification) ||
      typeof finding.hardGate !== "boolean" ||
      (finding.path !== undefined &&
        finding.path !== null &&
        (typeof finding.path !== "string" ||
          finding.path.length > 1024 ||
          !/^(?:\/(?:[^~/]|~[01])*)*$/u.test(finding.path)))
    ) {
      throw new RunnerError("sanitizer_response_invalid", "sanitizer findings are invalid");
    }
    return {
      code: finding.code,
      severity: finding.severity,
      classification: finding.classification,
      hardGate: finding.hardGate,
      path: null,
    };
  });
}

function snapshotSanitizerResponse(value: unknown): SanitizerResponse {
  try {
    const normalized = normalizeJsonValue(
      value,
      "sanitizer response",
      MAX_DOCUMENT_BYTES + 256 * 1024,
    );
    if (!isJsonObject(normalized)) throw new Error();
    const allowedKeys = new Set([
      "sanitizedDocument",
      "sanitizerId",
      "protocolVersion",
      "policyVersion",
      "policyDigest",
      "caseInputIdentityVersion",
      "caseInputIdentityDigest",
      "policyTargetIdentityDigest",
      "policyBindingDigest",
      "findings",
    ]);
    const requiredKeys = [...allowedKeys].filter((key) => key !== "findings");
    if (
      Object.keys(normalized).some((key) => !allowedKeys.has(key)) ||
      requiredKeys.some((key) => !Object.hasOwn(normalized, key)) ||
      typeof normalized.sanitizerId !== "string" ||
      !isSafeLabel(normalized.sanitizerId) ||
      normalized.protocolVersion !== 1 ||
      typeof normalized.policyVersion !== "number" ||
      !Number.isSafeInteger(normalized.policyVersion) ||
      normalized.policyVersion < 1 ||
      typeof normalized.policyDigest !== "string" ||
      !isDigest(normalized.policyDigest) ||
      normalized.caseInputIdentityVersion !== 1 ||
      typeof normalized.caseInputIdentityDigest !== "string" ||
      !isDigest(normalized.caseInputIdentityDigest) ||
      typeof normalized.policyTargetIdentityDigest !== "string" ||
      !isDigest(normalized.policyTargetIdentityDigest) ||
      typeof normalized.policyBindingDigest !== "string" ||
      !isDigest(normalized.policyBindingDigest)
    ) {
      throw new Error();
    }
    const findings = normalizeFindings(
      normalized.findings === undefined
        ? undefined
        : (normalized.findings as SanitizerFinding[]),
    );
    return freezeObject({
      sanitizedDocument: normalizeJsonValue(
        normalized.sanitizedDocument,
        "sanitizer document",
        MAX_DOCUMENT_BYTES,
      ),
      sanitizerId: normalized.sanitizerId,
      protocolVersion: 1,
      policyVersion: normalized.policyVersion,
      policyDigest: normalized.policyDigest,
      caseInputIdentityVersion: 1,
      caseInputIdentityDigest: normalized.caseInputIdentityDigest,
      policyTargetIdentityDigest: normalized.policyTargetIdentityDigest,
      policyBindingDigest: normalized.policyBindingDigest,
      findings,
    });
  } catch {
    throw internalRunnerError("sanitizer_response_invalid", "sanitizer response is invalid");
  }
}

function parseProviderOutput(output: ProviderOutput): JsonValue {
  try {
    if (typeof output === "string") {
      if (new TextEncoder().encode(output).length > MAX_DOCUMENT_BYTES) throw new Error();
      return normalizeJsonValue(parseJson(output, "provider output"), "provider output", MAX_DOCUMENT_BYTES);
    }
    if (output instanceof Uint8Array) {
      if (output.byteLength > MAX_DOCUMENT_BYTES) throw new Error();
      return normalizeJsonValue(
        parseJson(decodeUtf8Strict(output, "provider output"), "provider output"),
        "provider output",
        MAX_DOCUMENT_BYTES,
      );
    }
    return normalizeJsonValue(output, "provider output", MAX_DOCUMENT_BYTES);
  } catch {
    throw internalRunnerError("provider_response_invalid", "provider output is invalid JSON");
  }
}

function normalizeJsonRecord(value: unknown, label: string): JsonRecord {
  const normalized = normalizeJsonValue(value, label);
  if (!isJsonObject(normalized)) throw new RunnerError("sanitizer_response_invalid", "sanitizer policy is invalid");
  return normalized;
}

function normalizeUsage(usage: unknown): ProviderUsage {
  if (usage === undefined) return { available: false };
  if (!isJsonObject(usage) || !Object.hasOwn(usage, "available") || typeof usage.available !== "boolean") throw new Error();
  if (!usage.available) return { available: false };
  const result: ProviderUsage = { available: true };
  for (const key of ["inputTokens", "outputTokens", "totalTokens"] as const) {
    const value = Object.hasOwn(usage, key) ? usage[key] : undefined;
    if (value !== undefined && value !== null) {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error();
      }
      result[key] = value;
    } else if (value === null) {
      result[key] = null;
    }
  }
  return result;
}

function nullableSafeLabel(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !isSafeLabel(value)) {
    throw new RunnerError("provider_response_invalid", "provider response metadata is invalid");
  }
  return value;
}

function isDigest(value: string | undefined): value is string {
  return value !== undefined && SHA256_PATTERN.test(value);
}

function freezeObject<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeObject(child);
  Object.freeze(value);
  return value;
}

function internalRunnerError(code: ConstructorParameters<typeof RunnerError>[0], message: string): RunnerError {
  const error = new RunnerError(code, message);
  INTERNAL_RUNNER_ERRORS.add(error);
  return error;
}

function isInternalRunnerError(error: unknown): error is RunnerError {
  return typeof error === "object" && error !== null && INTERNAL_RUNNER_ERRORS.has(error);
}

function passedStage(): { status: "passed"; errorCode: null } {
  return { status: "passed", errorCode: null };
}

async function withTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  timeoutCode: "approval_timeout" | "provider_timeout" | "sanitizer_timeout",
  onTimeout?: () => void,
  awaitAbort = false,
): Promise<T> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw internalRunnerError("run_configuration_invalid", "timeout is invalid");
  }
  return new Promise<T>((resolve, reject) => {
    let timeoutError: RunnerError | undefined;
    const timer = setTimeout(() => {
      timeoutError = internalRunnerError(timeoutCode, "operation timed out");
      try {
        onTimeout?.();
      } catch {
        // Timeout classification remains deterministic even if cancellation fails.
      } finally {
        if (!awaitAbort) reject(timeoutError);
      }
    }, timeoutMs);
    Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          clearTimeout(timer);
          if (timeoutError === undefined) resolve(value);
          else reject(timeoutError);
        },
        (error: unknown) => {
          clearTimeout(timer);
          if (timeoutError === undefined) reject(error);
          else reject(timeoutError);
        },
      );
  });
}

async function ensureAttemptRoot(
  directory: string,
  assertStable: () => Promise<void>,
): Promise<Awaited<ReturnType<typeof open>>> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    try {
      const existing = await lstat(directory);
      if (existing.isSymbolicLink() || !existing.isDirectory()) {
        throw new RunnerError("attempt_write_failed", "attempt root is invalid");
      }
    } catch (error) {
      if (error instanceof RunnerError) throw error;
      if (!isNotFoundError(error)) {
        throw new RunnerError("attempt_write_failed", "attempt root could not be inspected");
      }
      try {
        await mkdir(directory, { recursive: true, mode: 0o700 });
      } catch {
        throw new RunnerError("attempt_write_failed", "attempt root could not be prepared");
      }
    }
    await assertStable();
    handle = await open(directory, ATTEMPT_ROOT_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isDirectory()) throw new Error();
    await assertStable();
    const pathInfo = await lstat(directory);
    if (pathInfo.isSymbolicLink() || !pathInfo.isDirectory() || !sameFile(info, pathInfo)) {
      throw new Error();
    }
    await handle.chmod(0o700);
    return handle;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("attempt_write_failed", "attempt root could not be secured");
  }
}

async function assertAttemptRootHandleStable(
  handle: Awaited<ReturnType<typeof open>> | undefined,
  directory: string,
  guard: { assertStable: () => Promise<void> },
): Promise<void> {
  if (handle === undefined) {
    throw new RunnerError("attempt_write_failed", "attempt root is unavailable");
  }
  try {
    await guard.assertStable();
    const handleInfo = await handle.stat();
    const pathInfo = await lstat(directory);
    if (
      pathInfo.isSymbolicLink() ||
      !pathInfo.isDirectory() ||
      !sameFile(handleInfo, pathInfo) ||
      (process.platform !== "win32" && (handleInfo.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("attempt_write_failed", "attempt root changed");
  }
}

function isNotFoundError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}

function sameFile(left: { dev: number; ino: number }, right: { dev: number; ino: number }): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}
