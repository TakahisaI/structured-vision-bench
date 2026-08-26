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
import {
  computeCaseInputIdentity,
  createSanitizerRequirementDecision,
  computeRunIdentity,
  type CaseInputIdentity,
  type SanitizerRequirementDecisionV1,
} from "./identity.js";
import { prepareSanitizerPolicy, type PreparedSanitizerPolicy } from "./sanitizer.js";
import type {
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
const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;
const DEFAULT_SANITIZER_TIMEOUT_MS = 30_000;
const DEFAULT_PROVIDER_TIMEOUT_MS = 120_000;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ATTEMPT_ROOT_NOFOLLOW = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_DIRECTORY ?? 0);
const INTERNAL_RUNNER_ERRORS = new WeakSet<object>();

type NormalizedProviderResponse = {
  document: JsonValue;
  respondedModel: string | null;
  effectiveEffort: string | null;
  usage: ProviderUsage;
  stopReason: string | null;
};

type ProviderIdentity = {
  id: string;
  route: string;
};

export async function runBundle(options: RunBundleOptions): Promise<RunResult> {
  const requested = normalizeRequestedSettings(options);
  validateBoundarySettings(options.approval, options.sanitizer);
  validateTimeoutSetting(options.providerTimeoutMs);
  const providerIdentity = validateProvider(options.provider);
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
    validateSanitizerRequirementSettings(requirement, options.sanitizer);
    const preparedPolicy = requirement.policyRequired
      ? prepareSanitizerPolicy(options.sanitizer, identity)
      : undefined;
    const approvalPlan = validateApprovalSettings(options.approval);
    const runId = computeRunIdentity({
      caseInputIdentityDigest: identity.digest,
      bundleManifestDigest: prepared.manifestDigest,
      providerId: providerIdentity.id,
      providerRoute: providerIdentity.route,
      requestedModel: requested.model,
      requestedEffort: requested.effort,
      maxTokens: requested.maxTokens,
      approvalBindingDigest: approvalPlan?.runtimeBindingDigest ?? null,
      approvalBindingIdentity: approvalPlan?.runtimeBindingIdentity ?? null,
      approvalGateId: approvalPlan?.expectedGateId ?? null,
      approvalProtocolVersion: approvalPlan?.expectedProtocolVersion ?? null,
      approvalSnapshotDigest: approvalPlan?.snapshotDigest ?? null,
      approvalRequired: approvalPlan?.required ?? false,
      sanitizerBindingDigest: preparedPolicy?.policyBindingDigest ?? null,
      sanitizerId:
        options.sanitizer?.sanitizer?.id ?? options.sanitizer?.expectedSanitizerId ?? null,
      sanitizerProtocolVersion:
        options.sanitizer?.sanitizer?.protocolVersion ?? options.sanitizer?.expectedProtocolVersion ?? null,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
      requirementVerifierId: requirement.requirementVerifierId,
      requirementVerifierVersion: requirement.requirementVerifierVersion,
      consumerSourceCommit: requirement.consumerSourceCommit,
      requirementDecisionDigest: requirement.requirementDecisionDigest,
    });

    const approval = await executeApproval(
      approvalPlan,
      providerIdentity,
      requested,
      harnessVersion,
    );
    loaded = await loadBundleForRunner(
      options.bundleDirectory,
      inputStagingDirectory,
      options.contractSchemaPath,
    );
    assertBundleMatchesPreparation(prepared, loaded, identity);
    attemptRootHandle = await ensureAttemptRoot(attemptRoot, rootGuard.assertStable);
    await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
    const attemptDirectory = path.join(attemptRoot, runId);
    const claim = await claimAttemptDirectory(attemptDirectory);
    attemptClaim = claim;
    await assertAttemptRootHandleStable(attemptRootHandle, attemptRoot, rootGuard);
    const providerResponse = await executeProvider(
      options.provider,
      loaded,
      identity,
      requested,
      harnessVersion,
      harnessCommit,
      options.providerTimeoutMs,
    );
    const providerMetadata = normalizeProviderMetadata(providerIdentity, requested, providerResponse);
    const sanitized = await executeSanitizer(
      requirement.sanitizerRequired ? options.sanitizer : undefined,
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
      attemptId: runId,
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
        providerId: providerIdentity.id,
        route: providerIdentity.route,
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
      attemptDirectory: claim.attemptDirectory,
      attemptId: runId,
      runId,
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
    await rm(temporaryParent, { recursive: true, force: true });
  }
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
): void {
  validateCommandSettings(approval);
  validateCommandSettings(sanitizer);
  validateTimeoutSetting(approval?.timeoutMs);
  validateTimeoutSetting(sanitizer?.timeoutMs);
  if (approval !== undefined && typeof approval.required !== "boolean") {
    throw new RunnerError("run_configuration_invalid", "approval configuration is invalid");
  }
  if (sanitizer !== undefined && typeof sanitizer.required !== "boolean") {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer configuration is invalid");
  }
  if (sanitizer?.expectedSanitizerId !== undefined && sanitizer.sanitizer === undefined) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedSanitizerId !== undefined &&
    sanitizer.sanitizer !== undefined &&
    sanitizer.expectedSanitizerId !== sanitizer.sanitizer.id
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedProtocolVersion !== undefined &&
    sanitizer.sanitizer !== undefined &&
    sanitizer.expectedProtocolVersion !== sanitizer.sanitizer.protocolVersion
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedProtocolVersion !== undefined &&
    sanitizer.sanitizer === undefined
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer protocol is invalid");
  }
  if (
    sanitizer?.sanitizer !== undefined &&
    (!isSafeLabel(sanitizer.sanitizer.id) || sanitizer.sanitizer.protocolVersion !== 1)
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
  }
  if (
    sanitizer?.expectedSanitizerId !== undefined &&
    !isSafeLabel(sanitizer.expectedSanitizerId)
  ) {
    throw new RunnerError("sanitizer_configuration_invalid", "sanitizer identity is invalid");
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
  if (sanitizer === undefined || !sanitizer.required || sanitizer.sanitizer === undefined) {
    throw new RunnerError("sanitizer_required", "required sanitizer is missing");
  }
}

function validateCommandSettings(
  settings:
    | Pick<ApprovalSettings, "executable" | "argv" | "envAllowlist" | "outputLimitBytes">
    | undefined,
): void {
  if (settings === undefined) return;
  if (
    (settings.executable !== undefined &&
      (typeof settings.executable !== "string" ||
        settings.executable.length === 0 ||
        settings.executable.length > 240)) ||
    (settings.argv !== undefined &&
      (settings.argv.length > 64 ||
        settings.argv.some((value) => typeof value !== "string" || value.length > 240))) ||
    (settings.envAllowlist !== undefined &&
      (settings.envAllowlist.length > 64 ||
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
    throw new RunnerError("run_configuration_invalid", "command configuration is invalid");
  }
}

function validateTimeoutSetting(timeoutMs: number | undefined): void {
  if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)) {
    throw new RunnerError("run_configuration_invalid", "timeout is invalid");
  }
}

function validateProvider(provider: Provider): ProviderIdentity {
  try {
    if (
      provider === null ||
      typeof provider !== "object" ||
      typeof provider.id !== "string" ||
      !isSafeLabel(provider.id) ||
      typeof provider.route !== "string" ||
      !isSafeLabel(provider.route) ||
      typeof provider.invoke !== "function"
    ) {
      throw new Error();
    }
    return { id: provider.id, route: provider.route };
  } catch {
    throw new RunnerError("provider_invalid", "provider configuration is invalid");
  }
}

function isSafeLabel(value: string): boolean {
  return value.length > 0 && value.length <= 64 && /^[A-Za-z0-9._-]+$/u.test(value);
}

function validateApprovalSettings(settings: ApprovalSettings | undefined):
  | (ApprovalSettings & {
      gate: NonNullable<ApprovalSettings["gate"]>;
      expectedGateId: string;
      expectedProtocolVersion: 1;
      snapshotDigest: string;
      runtimeBindingDigest: string;
    })
  | undefined {
  if (settings === undefined) return undefined;
  if (!settings.required) {
    if (settings.gate !== undefined) {
      throw new RunnerError("approval_configuration_invalid", "optional approval gates are not supported");
    }
    return undefined;
  }
  if (settings.required && settings.gate === undefined) {
    throw new RunnerError("approval_required", "approval gate is required");
  }
  if (
    settings.gate === undefined ||
    typeof settings.expectedGateId !== "string" ||
    !isSafeLabel(settings.expectedGateId) ||
    settings.expectedProtocolVersion !== 1 ||
    !isDigest(settings.snapshotDigest) ||
    !isDigest(settings.runtimeBindingDigest)
  ) {
    throw new RunnerError("approval_configuration_invalid", "approval configuration is incomplete");
  }
  if (settings.gate.id !== settings.expectedGateId || settings.gate.protocolVersion !== 1) {
    throw new RunnerError("approval_configuration_invalid", "approval gate identity is invalid");
  }
  if (
    settings.runtimeBindingIdentity !== undefined &&
    !isSafeLabel(settings.runtimeBindingIdentity)
  ) {
    throw new RunnerError("approval_configuration_invalid", "approval binding identity is invalid");
  }
  return settings as ApprovalSettings & {
    gate: NonNullable<ApprovalSettings["gate"]>;
    expectedGateId: string;
    expectedProtocolVersion: 1;
    snapshotDigest: string;
    runtimeBindingDigest: string;
  };
}

async function executeApproval(
  settings:
    | (ApprovalSettings & {
        gate: NonNullable<ApprovalSettings["gate"]>;
        expectedGateId: string;
        expectedProtocolVersion: 1;
        snapshotDigest: string;
        runtimeBindingDigest: string;
      })
    | undefined,
  providerIdentity: ProviderIdentity,
  requested: RequestedExecutionSettings,
  harnessVersion: string,
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
    };
  }
  const request: ApprovalRequest = freezeObject({
    gateId: settings.expectedGateId,
    protocolVersion: settings.expectedProtocolVersion,
    providerId: providerIdentity.id,
    providerRoute: providerIdentity.route,
    requested: freezeObject({ ...requested }),
    harnessVersion,
    snapshotDigest: settings.snapshotDigest,
    runtimeBindingDigest: settings.runtimeBindingDigest,
    runtimeBindingIdentity: settings.runtimeBindingIdentity ?? null,
  });
  let response: ApprovalResponse;
  try {
    const controller = new AbortController();
    response = await withTimeout(
      () => settings.gate.approve(request, controller.signal),
      settings.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
      "approval_timeout",
      () => controller.abort(),
    );
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("approval_response_invalid", "approval gate failed");
  }
  try {
    if (
      response === null ||
      typeof response !== "object" ||
      response.responseVersion !== 1 ||
      typeof response.approved !== "boolean" ||
      response.gateId !== settings.expectedGateId ||
      response.protocolVersion !== settings.expectedProtocolVersion ||
      response.snapshotDigest !== settings.snapshotDigest ||
      response.runtimeBindingDigest !== settings.runtimeBindingDigest ||
      (response.runtimeBindingIdentity ?? null) !== (settings.runtimeBindingIdentity ?? null)
    ) {
      throw new Error();
    }
  } catch {
    throw internalRunnerError("approval_response_invalid", "approval response is invalid");
  }
  if (!response.approved) {
    throw new RunnerError("approval_denied", "approval gate denied this run");
  }
  return {
    required: settings.required,
    applied: true,
    gateId: response.gateId,
    protocolVersion: response.protocolVersion,
    snapshotDigest: response.snapshotDigest,
    runtimeBindingDigest: response.runtimeBindingDigest,
    runtimeBindingIdentity: response.runtimeBindingIdentity ?? null,
  };
}

async function executeProvider(
  provider: Provider,
  loaded: Awaited<ReturnType<typeof loadBundleForRunner>>,
  identity: CaseInputIdentity,
  requested: RequestedExecutionSettings,
  harnessVersion: string,
  harnessCommit: string | null,
  providerTimeoutMs: number | undefined,
): Promise<NormalizedProviderResponse> {
  try {
    const controller = new AbortController();
    let active = true;
    const readBytes = async (reader: () => Promise<Buffer>): Promise<Buffer> => {
      if (!active || controller.signal.aborted) throw new Error();
      return reader();
    };
    const readText = async (reader: () => Promise<string>): Promise<string> => {
      if (!active || controller.signal.aborted) throw new Error();
      return reader();
    };
    const request = {
      image: Object.freeze({
        mediaType: loaded.inputs.image.mediaType,
        readBytes: () => readBytes(loaded.inputs.image.readBytes),
      }),
      schema: freezeObject(normalizeJsonValue(loaded.inputs.schema.value, "provider schema", MAX_DOCUMENT_BYTES)),
      system: Object.freeze({ readText: () => readText(loaded.inputs.system.readText) }),
      instruction: Object.freeze({ readText: () => readText(loaded.inputs.instruction.readText) }),
      requested: freezeObject({ ...requested }),
    } satisfies ProviderModelRequest;
    const context: ProviderAdapterContext = freezeObject({
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
    });
    const response = await withTimeout(
      () => provider.invoke(request, context, controller.signal),
      providerTimeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS,
      "provider_timeout",
      () => {
        active = false;
        controller.abort();
      },
    );
    if (response === null || typeof response !== "object" || !Object.hasOwn(response, "rawDocument")) {
      throw internalRunnerError("provider_response_invalid", "provider response is invalid");
    }
    const metadata = normalizeProviderResponseMetadata(response);
    return {
      document: parseProviderOutput(response.rawDocument),
      ...metadata,
    };
  } catch (error) {
    if (isInternalRunnerError(error)) throw error;
    throw internalRunnerError("provider_failed", "provider invocation failed");
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
  const sanitizer = settings.sanitizer;
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
    response = await withTimeout(
      () => sanitizer.sanitize(request, controller.signal),
      settings.timeoutMs ?? DEFAULT_SANITIZER_TIMEOUT_MS,
      "sanitizer_timeout",
      () => controller.abort(),
    );
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
        required: settings.required,
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
    if (
      !isJsonObject(finding) ||
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
        typeof finding.path !== "string")
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
): Promise<T> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw internalRunnerError("run_configuration_invalid", "timeout is invalid");
  }
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        onTimeout?.();
      } catch {
        // Timeout classification remains deterministic even if cancellation fails.
      } finally {
        reject(internalRunnerError(timeoutCode, "operation timed out"));
      }
    }, timeoutMs);
    Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        (error: unknown) => {
          clearTimeout(timer);
          reject(error);
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
