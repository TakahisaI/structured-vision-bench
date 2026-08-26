import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rename, rm, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { validateJsonSchema } from "../bundle/schema-validator.js";
import { loadBundleForRunner } from "../bundle/validate-bundle.js";
import { writeAttemptFiles, type AttemptManifest, type AttemptManifestBase } from "./attempt.js";
import { RunnerError } from "./errors.js";
import {
  computeCaseInputIdentity,
  computeRunIdentity,
  type CaseInputIdentity,
} from "./identity.js";
import { prepareSanitizerPolicy, type PreparedSanitizerPolicy } from "./sanitizer.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
  ApprovalSettings,
  Provider,
  ProviderAdapterContext,
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
import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../bundle/json.js";

export const DEFAULT_HARNESS_VERSION = "structured-vision-bench-runner-v1";
const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;
const DEFAULT_SANITIZER_TIMEOUT_MS = 30_000;
const DEFAULT_PROVIDER_TIMEOUT_MS = 120_000;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

type NormalizedProviderResponse = Omit<ProviderResponse, "rawDocument"> & {
  rawDocument: JsonValue;
};

export async function runBundle(options: RunBundleOptions): Promise<RunResult> {
  const requested = normalizeRequestedSettings(options);
  validateBoundarySettings(options.approval, options.sanitizer);
  validateTimeoutSetting(options.providerTimeoutMs);
  validateProvider(options.provider);
  const harnessVersion =
    normalizeOptionalSetting(options.harnessVersion) ?? DEFAULT_HARNESS_VERSION;
  const harnessCommit = normalizeOptionalSetting(options.harnessCommit);
  const startedAt = new Date().toISOString();

  const temporaryParent = await mkdtemp(path.join(tmpdir(), "svbench-run-"));
  const inputStagingDirectory = path.join(temporaryParent, "inputs");
  let loaded:
    | Awaited<ReturnType<typeof loadBundleForRunner>>
    | undefined;
  try {
    loaded = await loadBundleForRunner(
      options.bundleDirectory,
      inputStagingDirectory,
      options.contractSchemaPath,
    );
    const identity = computeCaseInputIdentity({
      caseId: loaded.caseId,
      documentKind: loaded.documentKind,
      preparedImage: {
        mediaType: loaded.inputs.image.mediaType,
        sha256: loaded.inputs.image.sha256,
      },
    });
    const preparedPolicy = prepareSanitizerPolicy(options.sanitizer, identity);
    const approvalPlan = validateApprovalSettings(options.approval);
    const runId = computeRunIdentity({
      caseInputIdentityDigest: identity.digest,
      bundleManifestDigest: loaded.manifestDigest,
      providerId: options.provider.id,
      providerRoute: options.provider.route,
      requestedModel: requested.model,
      requestedEffort: requested.effort,
      maxTokens: requested.maxTokens,
      approvalBindingDigest: approvalPlan?.runtimeBindingDigest ?? null,
      approvalBindingIdentity: approvalPlan?.runtimeBindingIdentity ?? null,
      sanitizerBindingDigest: preparedPolicy?.policyBindingDigest ?? null,
    });

    await ensureAttemptRoot(options.attemptRoot);
    const attemptDirectory = path.join(options.attemptRoot, runId);
    if (await exists(attemptDirectory)) {
      throw new RunnerError("attempt_exists", "an attempt already exists for this run identity");
    }
    const temporaryAttemptDirectory = path.join(options.attemptRoot, `.staging-${runId}`);
    if (await exists(temporaryAttemptDirectory)) {
      throw new RunnerError("attempt_exists", "an attempt staging directory already exists");
    }

    const approval = await executeApproval(
      approvalPlan,
      options.provider,
      requested,
      harnessVersion,
    );
    const providerResponse = await executeProvider(
      options.provider,
      loaded,
      identity,
      requested,
      harnessVersion,
      harnessCommit,
      options.providerTimeoutMs,
    );
    const providerMetadata = normalizeProviderMetadata(options.provider, requested, providerResponse);
    const sanitized = await executeSanitizer(
      options.sanitizer,
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
      provenance: {
        harnessVersion,
        harnessCommit,
        promptVersion: loaded.metadata.promptVersion,
        preprocessVersion: loaded.metadata.preprocessVersion,
        sourceCommit: loaded.metadata.sourceCommit,
      },
      run: {
        providerId: options.provider.id,
        route: options.provider.route,
        requested,
        responded: providerMetadata.responded,
      },
      approval,
      sanitizer: sanitized.manifest,
      stages: {
        policyTargetPreflight: passedStage(),
        approval: passedStage(),
        provider: passedStage(),
        parse: passedStage(),
        sanitizer: passedStage(),
        targetBinding: passedStage(),
        schemaValidation: passedStage(),
      },
      timing: {
        startedAt,
        finishedAt,
        durationMs: Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)),
      },
    };

    try {
      const artifact = await writeAttemptFiles(
        temporaryAttemptDirectory,
        manifest,
        sanitized.document,
      );
      try {
        await rename(temporaryAttemptDirectory, attemptDirectory);
      } catch {
        if (await exists(attemptDirectory)) {
          throw new RunnerError("attempt_exists", "an attempt already exists for this run identity");
        }
        throw new RunnerError("attempt_write_failed", "attempt directory could not be finalized");
      }
      return {
        attemptDirectory,
        attemptId: runId,
        runId,
        caseId: loaded.caseId,
        documentSha256: artifact.documentSha256,
      };
    } catch (error) {
      await rm(temporaryAttemptDirectory, { recursive: true, force: true });
      throw error;
    }
  } finally {
    await loaded?.cleanup().catch(() => undefined);
    await rm(temporaryParent, { recursive: true, force: true });
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
  if (value.length === 0 || value.length > 240) {
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

function validateProvider(provider: Provider): void {
  if (
    provider === null ||
    typeof provider !== "object" ||
    typeof provider.id !== "string" ||
    !isSafeLabel(provider.id) ||
    typeof provider.route !== "string" ||
    !isSafeLabel(provider.route) ||
    typeof provider.invoke !== "function"
  ) {
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
  if (!settings.required && settings.gate === undefined) return undefined;
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
  provider: Provider,
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
  const request: ApprovalRequest = {
    gateId: settings.expectedGateId,
    protocolVersion: settings.expectedProtocolVersion,
    providerId: provider.id,
    providerRoute: provider.route,
    requested,
    harnessVersion,
    snapshotDigest: settings.snapshotDigest,
    runtimeBindingDigest: settings.runtimeBindingDigest,
    runtimeBindingIdentity: settings.runtimeBindingIdentity ?? null,
  };
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
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("approval_response_invalid", "approval gate failed");
  }
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
    throw new RunnerError("approval_response_invalid", "approval response is invalid");
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
  const request = {
    image: loaded.inputs.image,
    schema: loaded.inputs.schema.value,
    system: loaded.inputs.system,
    instruction: loaded.inputs.instruction,
    requested,
  };
  const context: ProviderAdapterContext = {
    caseId: loaded.caseId,
    documentKind: loaded.documentKind,
    caseInputIdentity: identity,
    inputDigests: {
      image: loaded.inputs.image.sha256,
      schema: loaded.inputs.schema.sha256,
      system: loaded.inputs.system.sha256,
      instruction: loaded.inputs.instruction.sha256,
    },
    requested,
    provenance: {
      harnessVersion,
      harnessCommit,
      promptVersion: loaded.metadata.promptVersion,
      preprocessVersion: loaded.metadata.preprocessVersion,
      sourceCommit: loaded.metadata.sourceCommit,
    },
  };
  try {
    const controller = new AbortController();
    const response = await withTimeout(
      () => provider.invoke(request, context, controller.signal),
      providerTimeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS,
      "provider_timeout",
      () => controller.abort(),
    );
    if (response === null || typeof response !== "object" || !Object.hasOwn(response, "rawDocument")) {
      throw new RunnerError("provider_response_invalid", "provider response is invalid");
    }
    return { ...response, rawDocument: parseProviderOutput(response.rawDocument) };
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("provider_failed", "provider invocation failed");
  }
}

function normalizeProviderMetadata(
  provider: Provider,
  requested: RequestedExecutionSettings,
  response: ProviderResponse,
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
  const respondedModel = nullableString(response.respondedModel);
  const effectiveEffort = nullableString(response.effectiveEffort);
  const stopReason = nullableString(response.stopReason);
  const usage = normalizeUsage(response.usage);
  const responded = { model: respondedModel, effort: effectiveEffort, usage, stopReason };
  return {
    responded,
    sanitizerProvider: {
      id: provider.id,
      route: provider.route,
      requested,
      respondedModel,
      effectiveEffort,
      usage,
      stopReason,
    },
  };
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
  manifest: AttemptManifest["sanitizer"];
}> {
  if (preparedPolicy === undefined) {
    return {
      document: providerResponse.rawDocument,
      manifest: {
        required: false,
        applied: false,
        id: null,
        protocolVersion: null,
        policyVersion: null,
        policyDigest: null,
        policyTargetIdentityDigest: null,
        policyBindingIdentity: null,
        policyBindingDigest: null,
        findings: [],
      },
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
    response = await withTimeout(
      () =>
        sanitizer.sanitize({
          caseInputIdentity: identity,
          documentKind,
          policyEnvelope: preparedPolicy.envelope,
          policy: preparedPolicy.policy,
          policyVersion: preparedPolicy.policyVersion,
          policyDigest: preparedPolicy.policyDigest,
          policyBindingDigest: preparedPolicy.policyBindingDigest,
          document: providerResponse.rawDocument,
          provider: providerMetadata.sanitizerProvider,
          provenance,
        }, controller.signal),
      settings.timeoutMs ?? DEFAULT_SANITIZER_TIMEOUT_MS,
      "sanitizer_timeout",
      () => controller.abort(),
    );
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError("sanitizer_failed", "sanitizer failed");
  }
  if (
    response === null ||
    typeof response !== "object" ||
    !isJsonValue(response.sanitizedDocument) ||
    response.sanitizerId !== sanitizer.id ||
    response.protocolVersion !== sanitizer.protocolVersion ||
    response.policyVersion !== preparedPolicy.policyVersion ||
    response.policyDigest !== preparedPolicy.policyDigest ||
    response.caseInputIdentityVersion !== identity.identityVersion ||
    response.caseInputIdentityDigest !== identity.digest ||
    response.policyTargetIdentityDigest !== preparedPolicy.policyTargetIdentityDigest ||
    response.policyBindingDigest !== preparedPolicy.policyBindingDigest
  ) {
    throw new RunnerError("sanitizer_response_invalid", "sanitizer response is invalid");
  }
  return {
    document: response.sanitizedDocument,
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
      finding.code.length === 0 ||
      finding.code.length > 120 ||
      (finding.severity !== "info" &&
        finding.severity !== "warning" &&
        finding.severity !== "error") ||
      typeof finding.classification !== "string" ||
      finding.classification.length === 0 ||
      finding.classification.length > 120 ||
      typeof finding.hardGate !== "boolean" ||
      (finding.path !== undefined &&
        finding.path !== null &&
        (typeof finding.path !== "string" || finding.path.length > 240))
    ) {
      throw new RunnerError("sanitizer_response_invalid", "sanitizer findings are invalid");
    }
    return {
      code: finding.code,
      severity: finding.severity,
      classification: finding.classification,
      hardGate: finding.hardGate,
      path: finding.path ?? null,
    };
  });
}

function parseProviderOutput(output: ProviderOutput): JsonValue {
  try {
    if (typeof output === "string") return parseJson(output, "provider output");
    if (output instanceof Uint8Array) {
      return parseJson(decodeUtf8Strict(output, "provider output"), "provider output");
    }
    if (!isJsonValue(output)) throw new Error();
    return output;
  } catch {
    throw new RunnerError("provider_response_invalid", "provider output is invalid JSON");
  }
}

function normalizeUsage(usage: ProviderUsage | undefined): ProviderUsage {
  if (usage === undefined) return { available: false };
  if (typeof usage.available !== "boolean") {
    throw new RunnerError("provider_response_invalid", "provider usage metadata is invalid");
  }
  if (!usage.available) return { available: false };
  const result: ProviderUsage = { available: true };
  for (const key of ["inputTokens", "outputTokens", "totalTokens"] as const) {
    const value = usage[key];
    if (value !== undefined && value !== null) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new RunnerError("provider_response_invalid", "provider usage metadata is invalid");
      }
      result[key] = value;
    } else if (value === null) {
      result[key] = null;
    }
  }
  return result;
}

function nullableString(value: string | null | undefined): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > 240) {
    throw new RunnerError("provider_response_invalid", "provider response metadata is invalid");
  }
  return value;
}

function isJsonValue(value: unknown, seen = new Set<object>(), depth = 0): value is JsonValue {
  if (depth > 1000 || value === null) return value === null;
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.every((entry) => isJsonValue(entry, seen, depth + 1));
  if (!isJsonObject(value)) return false;
  return Object.values(value).every((entry) => isJsonValue(entry, seen, depth + 1));
}

function isDigest(value: string | undefined): value is string {
  return value !== undefined && SHA256_PATTERN.test(value);
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
    throw new RunnerError("run_configuration_invalid", "timeout is invalid");
  }
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout?.();
      reject(new RunnerError(timeoutCode, "operation timed out"));
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

async function ensureAttemptRoot(directory: string): Promise<void> {
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
      await mkdir(directory, { recursive: true });
    } catch {
      throw new RunnerError("attempt_write_failed", "attempt root could not be prepared");
    }
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

async function exists(file: string): Promise<boolean> {
  try {
    await lstat(file);
    return true;
  } catch {
    return false;
  }
}
