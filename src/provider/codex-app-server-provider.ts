import path from "node:path";

import {
  CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION,
  runCodexAppServerProcess,
  type CodexAppServerProcessOptions,
  type CodexAppServerProcessRequest,
} from "./codex-app-server-process.js";
import type {
  ApprovalResponse,
  Provider,
  ProviderAdapterContext,
  ProviderModelRequest,
  ProviderResponse,
  RequestedExecutionSettings,
} from "../runner/types.js";

export const CODEX_APP_SERVER_PROVIDER_ID = "codex-app-server";
export const CODEX_APP_SERVER_PROVIDER_ROUTE = "codex-app-server";
export const CODEX_APP_SERVER_PROVIDER_IMPLEMENTATION_VERSION =
  "codex-app-server-provider-v1";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const MAX_OPTION_STRINGS = 64;
const MAX_OPTION_STRING_BYTES = 4096;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const RESERVED_ENVIRONMENT_NAMES = new Set([
  "APPDATA",
  "CODEX_HOME",
  "HOME",
  "LOCALAPPDATA",
  "PATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
]);
const ABORT_SETTLING_CODEX_APP_SERVER_PROVIDERS = new WeakSet<object>();

export type CodexAppServerTransportRevalidator = (
  approval: ApprovalResponse,
  signal?: AbortSignal,
) => Promise<ApprovalResponse>;

export type CodexAppServerProviderOptions = Readonly<{
  process: CodexAppServerProcessOptions;
  revalidateTransport: CodexAppServerTransportRevalidator;
}>;

type ValidatedOptions = Readonly<{
  process: CodexAppServerProcessOptions;
  revalidateTransport: CodexAppServerTransportRevalidator;
}>;

type Authorization = Readonly<{
  generation: number;
  approval: ApprovalResponse;
}>;

type ActiveInvocation = Readonly<{
  controller: AbortController;
  settled: Promise<void>;
}>;

/** Creates the fixed, approval-bound Codex app-server Provider. */
export function createCodexAppServerProvider(
  optionsValue: CodexAppServerProviderOptions,
): Provider {
  const options = validateOptions(optionsValue);
  let generation = 0;
  let authorization: Authorization | undefined;
  let activeInvocation: ActiveInvocation | undefined;

  const provider = Object.freeze({
    id: CODEX_APP_SERVER_PROVIDER_ID,
    route: CODEX_APP_SERVER_PROVIDER_ROUTE,
    implementationVersion: CODEX_APP_SERVER_PROVIDER_IMPLEMENTATION_VERSION,
    protocolVersion: CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION,
    async prepareTransport(
      approvalValue: ApprovalResponse,
      signal?: AbortSignal,
    ): Promise<ApprovalResponse> {
      const currentGeneration = ++generation;
      authorization = undefined;
      const previousInvocation = activeInvocation;
      previousInvocation?.controller.abort();
      try {
        await previousInvocation?.settled;
        assertActive(signal);
        const approval = snapshotApproval(approvalValue);
        assertUsableApproval(approval);
        const revalidated = await revalidate(options, approval, signal);
        assertActive(signal);
        if (currentGeneration !== generation) throw new Error();
        authorization = Object.freeze({
          generation: currentGeneration,
          approval: revalidated,
        });
        return revalidated;
      } catch {
        if (currentGeneration === generation) authorization = undefined;
        throw new Error("codex app-server transport preparation failed");
      }
    },
    async invoke(
      requestValue: ProviderModelRequest,
      contextValue: ProviderAdapterContext,
      signal?: AbortSignal,
    ): Promise<ProviderResponse> {
      const claimed = authorization;
      authorization = undefined;
      if (claimed === undefined || activeInvocation !== undefined) {
        throw new Error("codex app-server provider failed");
      }

      const controller = new AbortController();
      const abort = (): void => controller.abort();
      let settleInvocation!: () => void;
      const settled = new Promise<void>((resolve) => {
        settleInvocation = resolve;
      });
      const invocation = Object.freeze({ controller, settled });
      activeInvocation = invocation;
      let listenerAttempted = false;
      let cleanupFailed = false;
      try {
        if (signal !== undefined) {
          listenerAttempted = true;
          signal.addEventListener("abort", abort, { once: true });
        }
        assertActive(signal);
        const request = snapshotInvocation(requestValue, contextValue, claimed.approval);
        const result = await runCodexAppServerProcess(
          options.process,
          request,
          controller.signal,
          async (processSignal) => {
            await revalidate(options, claimed.approval, processSignal);
            assertActive(processSignal);
            if (claimed.generation !== generation) throw new Error();
          },
        );
        return {
          rawDocument: result.document,
          approval: claimed.approval,
          respondedModel: result.respondedModel,
          effectiveEffort: result.effectiveEffort,
          usage: result.usage,
          stopReason: result.stopReason,
        };
      } catch {
        throw new Error("codex app-server provider failed");
      } finally {
        controller.abort();
        if (listenerAttempted) {
          try {
            signal!.removeEventListener("abort", abort);
          } catch {
            cleanupFailed = true;
          }
        }
        if (activeInvocation === invocation) activeInvocation = undefined;
        settleInvocation();
        if (cleanupFailed) throw new Error("codex app-server provider failed");
      }
    },
  });
  ABORT_SETTLING_CODEX_APP_SERVER_PROVIDERS.add(provider);
  return provider;
}

/** @internal Read-only lifecycle capability check; registration is module-private. */
export function isAbortSettlingCodexAppServerProvider(provider: object): boolean {
  return ABORT_SETTLING_CODEX_APP_SERVER_PROVIDERS.has(provider);
}

function validateOptions(value: CodexAppServerProviderOptions): ValidatedOptions {
  try {
    if (value === null || typeof value !== "object") throw new Error();
    const processOptions = value.process;
    const revalidateTransport = value.revalidateTransport;
    if (
      processOptions === null ||
      typeof processOptions !== "object" ||
      typeof processOptions.executable !== "string" ||
      !path.isAbsolute(processOptions.executable) ||
      typeof revalidateTransport !== "function"
    ) {
      throw new Error();
    }
    const executableArguments = snapshotStrings(
      processOptions.executableArguments ?? [],
      8,
    );
    const envAllowlist = snapshotStrings(
      processOptions.envAllowlist ?? [],
      MAX_OPTION_STRINGS,
    );
    const seenEnvironmentNames = new Set<string>();
    if (
      envAllowlist.some((name) => {
        if (
          !ENVIRONMENT_NAME_PATTERN.test(name) ||
          RESERVED_ENVIRONMENT_NAMES.has(name) ||
          seenEnvironmentNames.has(name)
        ) {
          return true;
        }
        seenEnvironmentNames.add(name);
        return false;
      })
    ) {
      throw new Error();
    }
    const timeoutMs = processOptions.timeoutMs;
    const outputLimitBytes = processOptions.outputLimitBytes;
    if (
      (timeoutMs !== undefined &&
        (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15 * 60_000)) ||
      (outputLimitBytes !== undefined &&
        (!Number.isSafeInteger(outputLimitBytes) ||
          outputLimitBytes < 1024 ||
          outputLimitBytes > 512 * 1024 * 1024))
    ) {
      throw new Error();
    }
    return Object.freeze({
      process: Object.freeze({
        executable: processOptions.executable,
        executableArguments: Object.freeze(executableArguments),
        envAllowlist: Object.freeze(envAllowlist),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        ...(outputLimitBytes === undefined ? {} : { outputLimitBytes }),
      }),
      revalidateTransport: Function.prototype.bind.call(
        revalidateTransport,
        undefined,
      ) as CodexAppServerTransportRevalidator,
    });
  } catch {
    throw new Error("codex app-server provider configuration is invalid");
  }
}

function snapshotStrings(value: readonly string[], limit: number): string[] {
  if (!Array.isArray(value) || value.length > limit) throw new Error();
  const result: string[] = [];
  for (const entry of value) {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      Buffer.byteLength(entry, "utf8") > MAX_OPTION_STRING_BYTES ||
      entry.includes("\0")
    ) {
      throw new Error();
    }
    result.push(entry);
  }
  return result;
}

async function revalidate(
  options: ValidatedOptions,
  expected: ApprovalResponse,
  signal: AbortSignal | undefined,
): Promise<ApprovalResponse> {
  assertActive(signal);
  const actual = snapshotApproval(
    await options.revalidateTransport(expected, signal),
  );
  assertActive(signal);
  assertUsableApproval(actual);
  if (!approvalEqual(actual, expected)) throw new Error();
  return actual;
}

function snapshotInvocation(
  request: ProviderModelRequest,
  context: ProviderAdapterContext,
  approval: ApprovalResponse,
): CodexAppServerProcessRequest {
  if (
    request === null ||
    typeof request !== "object" ||
    context === null ||
    typeof context !== "object" ||
    context.approval === null
  ) {
    throw new Error();
  }
  const contextApproval = snapshotApproval(context.approval);
  const requested = snapshotRequested(request.requested);
  const contextRequested = snapshotRequested(context.requested);
  const requirement = context.sanitizerRequirement;
  const digests = context.inputDigests;
  if (
    !approvalEqual(contextApproval, approval) ||
    context.phase !== approval.phase ||
    !requestedEqual(requested, contextRequested) ||
    requirement === null ||
    typeof requirement !== "object" ||
    requirement.sanitizerRequirementVersion !== approval.sanitizerRequirementVersion ||
    requirement.sanitizerRequired !== approval.sanitizerRequired ||
    requirement.policyRequired !== approval.policyRequired ||
    requirement.sanitizerRequirementReason !== approval.sanitizerRequirementReason ||
    requirement.requirementVerifierId !== approval.requirementVerifierId ||
    requirement.requirementVerifierVersion !== approval.requirementVerifierVersion ||
    requirement.consumerSourceCommit !== approval.consumerSourceCommit ||
    requirement.requirementDecisionDigest !== approval.requirementDecisionDigest ||
    digests === null ||
    typeof digests !== "object" ||
    !isDigest(digests.image) ||
    !isDigest(digests.schema) ||
    !isDigest(digests.system) ||
    !isDigest(digests.instruction)
  ) {
    throw new Error();
  }
  const image = request.image;
  const schema = request.schemaInput;
  const system = request.system;
  const instruction = request.instruction;
  if (
    image === null ||
    typeof image !== "object" ||
    typeof image.mediaType !== "string" ||
    typeof image.readBytes !== "function" ||
    schema === null ||
    typeof schema !== "object" ||
    typeof schema.readBytes !== "function" ||
    system === null ||
    typeof system !== "object" ||
    typeof system.readText !== "function" ||
    instruction === null ||
    typeof instruction !== "object" ||
    typeof instruction.readText !== "function"
  ) {
    throw new Error();
  }
  const readImage = Function.prototype.bind.call(image.readBytes, image) as () => Promise<Buffer>;
  const readSchema = Function.prototype.bind.call(schema.readBytes, schema) as () => Promise<Buffer>;
  const readSystem = Function.prototype.bind.call(system.readText, system) as () => Promise<string>;
  const readInstruction = Function.prototype.bind.call(
    instruction.readText,
    instruction,
  ) as () => Promise<string>;
  return Object.freeze({
    image: Object.freeze({
      mediaType: image.mediaType,
      sha256: digests.image,
      readBytes: readImage,
    }),
    schema: Object.freeze({ sha256: digests.schema, readBytes: readSchema }),
    system: Object.freeze({
      sha256: digests.system,
      readBytes: () => readTextBytes(readSystem),
    }),
    instruction: Object.freeze({
      sha256: digests.instruction,
      readBytes: () => readTextBytes(readInstruction),
    }),
    requested,
  });
}

async function readTextBytes(reader: () => Promise<string>): Promise<Buffer> {
  const value = await reader();
  if (typeof value !== "string") throw new Error();
  return Buffer.from(value, "utf8");
}

function snapshotRequested(value: RequestedExecutionSettings): RequestedExecutionSettings {
  if (value === null || typeof value !== "object") throw new Error();
  const model = value.model;
  const effort = value.effort;
  const maxTokens = value.maxTokens;
  if (
    typeof model !== "string" ||
    !isSafeLabel(model) ||
    (effort !== null && !isSafeLabel(effort)) ||
    maxTokens !== null
  ) {
    throw new Error();
  }
  return Object.freeze({ model, effort, maxTokens: null });
}

function snapshotApproval(value: unknown): ApprovalResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
  const approval = value as Record<string, unknown>;
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
  const optional = ["checkedAt", "expiresAt", "reasonCode"] as const;
  const allowed = new Set<string>([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(approval, key)) ||
    Object.keys(approval).some((key) => !allowed.has(key)) ||
    approval.responseVersion !== 1 ||
    typeof approval.approved !== "boolean" ||
    !isSafeLabel(approval.gateId) ||
    approval.protocolVersion !== 1 ||
    !isDigest(approval.snapshotDigest) ||
    !isDigest(approval.runtimeBindingDigest) ||
    !isSafeLabel(approval.runtimeBindingIdentity) ||
    !isDigest(approval.approvedScopeDigest) ||
    !isSafeLabel(approval.approvedScopeIdentity) ||
    !isSafeLabel(approval.phase) ||
    !isSafeLabel(approval.requirementVerifierId) ||
    !isSafeLabel(approval.requirementVerifierVersion) ||
    (approval.consumerSourceCommit !== null && !isSafeLabel(approval.consumerSourceCommit)) ||
    !isDigest(approval.requirementDecisionDigest) ||
    approval.sanitizerRequirementVersion !== 1 ||
    typeof approval.sanitizerRequired !== "boolean" ||
    typeof approval.policyRequired !== "boolean" ||
    !isSafeLabel(approval.sanitizerRequirementReason) ||
    !isOptionalDateTime(approval.checkedAt) ||
    !isOptionalDateTime(approval.expiresAt) ||
    (approval.reasonCode !== undefined && !isSafeLabel(approval.reasonCode))
  ) {
    throw new Error();
  }
  return Object.freeze({
    responseVersion: 1,
    approved: approval.approved,
    gateId: approval.gateId,
    protocolVersion: 1,
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
    sanitizerRequirementVersion: 1,
    sanitizerRequired: approval.sanitizerRequired,
    policyRequired: approval.policyRequired,
    sanitizerRequirementReason: approval.sanitizerRequirementReason,
    ...(Object.hasOwn(approval, "checkedAt") ? { checkedAt: approval.checkedAt } : {}),
    ...(Object.hasOwn(approval, "expiresAt") ? { expiresAt: approval.expiresAt } : {}),
    ...(Object.hasOwn(approval, "reasonCode") ? { reasonCode: approval.reasonCode } : {}),
  } as ApprovalResponse);
}

function assertUsableApproval(approval: ApprovalResponse): void {
  if (
    !approval.approved ||
    approval.sanitizerRequired ||
    approval.policyRequired ||
    (approval.expiresAt !== undefined &&
      approval.expiresAt !== null &&
      Date.parse(approval.expiresAt) <= Date.now())
  ) {
    throw new Error();
  }
}

function approvalEqual(left: ApprovalResponse, right: ApprovalResponse): boolean {
  const keys = [
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
    "checkedAt",
    "expiresAt",
    "reasonCode",
  ] as const;
  return keys.every((key) => (left[key] ?? null) === (right[key] ?? null));
}

function requestedEqual(
  left: RequestedExecutionSettings,
  right: RequestedExecutionSettings,
): boolean {
  return (
    left.model === right.model &&
    left.effort === right.effort &&
    left.maxTokens === right.maxTokens
  );
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL_PATTERN.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function isOptionalDateTime(value: unknown): value is string | null | undefined {
  if (value === undefined || value === null) return true;
  if (typeof value !== "string") return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|([+-])(\d{2}):(\d{2}))$/u.exec(
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
  return match[7] === "Z" || (Number(match[9]) <= 23 && Number(match[10]) <= 59);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function assertActive(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error();
}
