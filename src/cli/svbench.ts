import { parseArgs } from "node:util";
import path from "node:path";

import {
  compareAttempt,
  ComparisonError,
  renderComparisonMarkdown,
} from "../comparison/compare.js";
import { createMockProvider } from "../provider/mock.js";
import {
  createCodexAppServerProvider,
  type CodexAppServerTransportRevalidator,
} from "../provider/codex-app-server-provider.js";
import {
  MAX_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES,
} from "../provider/codex-app-server-process.js";
import {
  COMMAND_PROVIDER_OPERATION_ENV,
  COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV,
  createCommandProvider,
  MAX_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES,
  type CommandProviderOptions,
} from "../provider/command.js";
import { RunnerError } from "../runner/errors.js";
import {
  createCommandApprovalGate,
  DEFAULT_APPROVAL_OUTPUT_LIMIT_BYTES,
} from "../runner/approval.js";
import {
  createCommandSanitizer,
  MAX_COMMAND_SANITIZER_FAILURE_CODES,
  MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES,
  type CommandSanitizerOptions,
} from "../runner/command-sanitizer.js";
import {
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../runner/identity.js";
import { readPrivateSanitizerPolicy } from "./sanitizer-policy.js";
import {
  DEFAULT_EXECUTION_PHASE,
  MAX_TIMEOUT_MS,
  runBundle,
} from "../runner/run.js";
import { snapshotSanitizerFindingPathPatterns } from "../runner/sanitizer-finding-path.js";
import { BundleValidationError } from "../bundle/validate-bundle.js";
import type {
  ApprovalSettings,
  ApprovalGate,
  ApprovalRequest,
  ApprovalResponse,
  Provider,
  SanitizerSettings,
} from "../runner/types.js";

const RUN_USAGE =
  "usage: svbench run --bundle <bundle-directory> --provider mock|command|codex-app-server [--phase <label>] [--model <id>] [--effort <level>] [--max-tokens <n>] [--attempt-key <label>] [--attempt-root <directory>] [--provider-command <absolute-executable> <provider options>] [--provider-codex-home <absolute-directory>] [--approval required|optional --approval-command <executable> <approval identity options>] [--sanitizer required --sanitizer-command <absolute-executable> <sanitizer identity, policy, and failure-code options>] [--json]";
const COMPARE_USAGE =
  "usage: svbench compare --bundle <bundle-directory> --attempt <attempt-directory> [--rescore --rescore-reason <code>] [--json]";
const asJson = process.argv.slice(2).includes("--json");
const CODEX_APP_SERVER_EFFORTS = new Set([
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
  "ultra",
]);

type RunArguments = {
  bundle: string;
  provider: Provider;
  phase: string;
  model: string | null;
  effort: string | null;
  maxTokens: number | null;
  attemptKey: string | undefined;
  attemptRoot: string;
  providerTimeoutMs: number | undefined;
  approval: ApprovalSettings | undefined;
  sanitizerRequirement: SanitizerRequirementSettings;
  sanitizer: ParsedSanitizerSettings | undefined;
};

type ParsedSanitizerSettings = Omit<SanitizerSettings, "policyEnvelopeBytes"> & {
  policyPath: string;
};

type ParsedApprovalPlan = Readonly<{
  settings: ApprovalSettings | undefined;
  revalidateTransport: CodexAppServerTransportRevalidator | undefined;
}>;

type CompareArguments = {
  bundle: string;
  attempt: string;
  mode: "normal" | "rescore";
  rescoreReason: string | undefined;
};

type CommandArguments =
  | { kind: "run"; arguments: RunArguments }
  | { kind: "compare"; arguments: CompareArguments };

type Failure = {
  code: string;
  message: string;
  details: string[];
  exitCode: 1 | 2;
};

let command: CommandArguments | undefined;
try {
  if (process.argv[2] === "run") {
    command = { kind: "run", arguments: parseRunArguments() };
  } else if (process.argv[2] === "compare") {
    command = { kind: "compare", arguments: parseCompareArguments() };
  } else {
    throw new Error();
  }
} catch {
  reportFailure({
    code: "invalid_arguments",
    message: process.argv[2] === "compare" ? COMPARE_USAGE : RUN_USAGE,
    details: [],
    exitCode: 2,
  });
}

if (command !== undefined) {
  try {
    if (command.kind === "run") {
      await executeRun(command.arguments);
    } else {
      await executeCompare(command.arguments);
    }
  } catch (error) {
    if (
      error instanceof BundleValidationError ||
      error instanceof RunnerError ||
      error instanceof ComparisonError
    ) {
      reportFailure({
        code: error.code,
        message: error.message,
        details: error.details,
        exitCode: 1,
      });
    } else {
      reportFailure({
        code: "internal_error",
        message: "command failed unexpectedly",
        details: [],
        exitCode: 2,
      });
    }
  }
}

async function executeRun(runArguments: RunArguments): Promise<void> {
  let sanitizer: SanitizerSettings | undefined;
  let policyEnvelopeBytes: Buffer | undefined;
  if (runArguments.sanitizer !== undefined) {
    const { policyPath, ...settings } = runArguments.sanitizer;
    policyEnvelopeBytes = await readPrivateSanitizerPolicy(policyPath);
    sanitizer = { ...settings, policyEnvelopeBytes };
  }
  const result = await runBundle({
    bundleDirectory: runArguments.bundle,
    attemptRoot: runArguments.attemptRoot,
    provider: runArguments.provider,
    phase: runArguments.phase,
    requestedModel: runArguments.model,
    requestedEffort: runArguments.effort,
    maxTokens: runArguments.maxTokens,
    ...(runArguments.providerTimeoutMs === undefined
      ? {}
      : { providerTimeoutMs: runArguments.providerTimeoutMs }),
    ...(runArguments.attemptKey === undefined ? {} : { attemptKey: runArguments.attemptKey }),
    sanitizerRequirement: runArguments.sanitizerRequirement,
    ...(runArguments.approval === undefined ? {} : { approval: runArguments.approval }),
    ...(sanitizer === undefined ? {} : { sanitizer }),
  }).finally(() => policyEnvelopeBytes?.fill(0));
  if (asJson) {
    console.log(
      JSON.stringify({
        ok: true,
        phase: result.phase,
        caseId: result.caseId,
        attemptKey: result.attemptKey,
        attemptId: result.attemptId,
        artifactId: result.artifactId,
        runId: result.runId,
      }),
    );
  } else {
    console.log(
      `run complete: ${result.caseId} (phase ${result.phase}, key ${result.attemptKey}, attempt ${result.attemptId}, artifact ${result.artifactId}, run ${result.runId})`,
    );
  }
}

async function executeCompare(compareArguments: CompareArguments): Promise<void> {
  const result = await compareAttempt({
    bundleDirectory: compareArguments.bundle,
    attemptDirectory: compareArguments.attempt,
    mode: compareArguments.mode,
    ...(compareArguments.rescoreReason === undefined
      ? {}
      : { rescoreReason: compareArguments.rescoreReason }),
  });
  if (asJson) {
    console.log(JSON.stringify({ ok: true, result }));
  } else {
    process.stdout.write(renderComparisonMarkdown(result));
  }
}

function parseRunArguments(): RunArguments {
  if (process.argv[2] !== "run") throw new Error();
  const { positionals, values } = parseArgs({
    args: process.argv.slice(3),
    options: {
      bundle: { type: "string" },
      provider: { type: "string" },
      model: { type: "string" },
      effort: { type: "string" },
      "max-tokens": { type: "string" },
      "attempt-key": { type: "string" },
      "attempt-root": { type: "string" },
      phase: { type: "string" },
      "provider-command": { type: "string" },
      "provider-arg": { type: "string", multiple: true },
      "provider-env": { type: "string", multiple: true },
      "provider-codex-home": { type: "string" },
      "provider-id": { type: "string" },
      "provider-route": { type: "string" },
      "provider-version": { type: "string" },
      "provider-output-limit": { type: "string" },
      "provider-timeout-ms": { type: "string" },
      approval: { type: "string" },
      "approval-command": { type: "string" },
      "approval-arg": { type: "string", multiple: true },
      "approval-env": { type: "string", multiple: true },
      "approval-gate-id": { type: "string" },
      "approval-snapshot-digest": { type: "string" },
      "approval-runtime-identity": { type: "string" },
      "approval-runtime-digest": { type: "string" },
      "approval-scope-identity": { type: "string" },
      "approval-scope-digest": { type: "string" },
      "approval-phase": { type: "string" },
      "approval-timeout-ms": { type: "string" },
      "approval-output-limit": { type: "string" },
      sanitizer: { type: "string" },
      "sanitizer-command": { type: "string" },
      "sanitizer-arg": { type: "string", multiple: true },
      "sanitizer-env": { type: "string", multiple: true },
      "sanitizer-id": { type: "string" },
      "sanitizer-policy": { type: "string" },
      "sanitizer-policy-version": { type: "string" },
      "sanitizer-policy-digest": { type: "string" },
      "sanitizer-case-input-digest": { type: "string" },
      "sanitizer-binding-digest": { type: "string" },
      "sanitizer-timeout-ms": { type: "string" },
      "sanitizer-output-limit": { type: "string" },
      "sanitizer-finding-path": { type: "string", multiple: true },
      "sanitizer-failure-code": { type: "string", multiple: true },
      "requirement-verifier-id": { type: "string" },
      "requirement-verifier-version": { type: "string" },
      "requirement-consumer-source-commit": { type: "string" },
      "requirement-reason": { type: "string" },
      "requirement-decision-digest": { type: "string" },
      json: { type: "boolean", default: false },
    },
    allowPositionals: true,
    strict: true,
  });
  if (
    positionals.length !== 0 ||
    typeof values.bundle !== "string" ||
    typeof values.provider !== "string" ||
    values.bundle.length === 0
  ) {
    throw new Error();
  }
  const phase =
    values.phase === undefined
      ? DEFAULT_EXECUTION_PHASE
      : requiredSafeLabel(values.phase);
  const model = optionalNonEmptyString(values.model);
  const effort = optionalNonEmptyString(values.effort);
  const maxTokens = parseMaxTokens(values["max-tokens"]);
  const providerTimeoutMs =
    values["provider-timeout-ms"] === undefined
      ? undefined
      : parseTimeoutMs(values["provider-timeout-ms"]);
  const attemptRoot =
    typeof values["attempt-root"] === "string" && values["attempt-root"].length > 0
      ? values["attempt-root"]
      : path.resolve("attempts");
  const sanitizerPlan = parseCommandSanitizer({
    mode: values.sanitizer,
    executable: values["sanitizer-command"],
    argv: values["sanitizer-arg"],
    envAllowlist: values["sanitizer-env"],
    sanitizerId: values["sanitizer-id"],
    policyPath: values["sanitizer-policy"],
    policyVersion: values["sanitizer-policy-version"],
    policyDigest: values["sanitizer-policy-digest"],
    caseInputIdentityDigest: values["sanitizer-case-input-digest"],
    policyBindingDigest: values["sanitizer-binding-digest"],
    timeoutMs: values["sanitizer-timeout-ms"],
    outputLimitBytes: values["sanitizer-output-limit"],
    allowedFindingPathPatterns: values["sanitizer-finding-path"],
    allowedFailureCodes: values["sanitizer-failure-code"],
    requirementVerifierId: values["requirement-verifier-id"],
    requirementVerifierVersion: values["requirement-verifier-version"],
    requirementConsumerSourceCommit: values["requirement-consumer-source-commit"],
    requirementReason: values["requirement-reason"],
    requirementDecisionDigest: values["requirement-decision-digest"],
  });
  const approvalPlan = parseCommandApproval(
    {
      mode: values.approval,
      executable: values["approval-command"],
      argv: values["approval-arg"],
      envAllowlist: values["approval-env"],
      gateId: values["approval-gate-id"],
      snapshotDigest: values["approval-snapshot-digest"],
      runtimeBindingIdentity: values["approval-runtime-identity"],
      runtimeBindingDigest: values["approval-runtime-digest"],
      approvedScopeIdentity: values["approval-scope-identity"],
      approvedScopeDigest: values["approval-scope-digest"],
      phase: values["approval-phase"],
      timeoutMs: values["approval-timeout-ms"],
      outputLimitBytes: values["approval-output-limit"],
    },
    sanitizerPlan.requirement,
  );
  if (approvalPlan.settings?.phase !== undefined && approvalPlan.settings.phase !== phase) {
    throw new Error();
  }
  const provider = parseProvider(
    {
      kind: values.provider,
      executable: values["provider-command"],
      argv: values["provider-arg"],
      envAllowlist: values["provider-env"],
      codexHome: values["provider-codex-home"],
      providerId: values["provider-id"],
      route: values["provider-route"],
      implementationVersion: values["provider-version"],
      outputLimitBytes: values["provider-output-limit"],
    },
    {
      model,
      effort,
      maxTokens,
      timeoutMs: providerTimeoutMs,
      revalidateTransport: approvalPlan.revalidateTransport,
    },
  );
  return {
    bundle: values.bundle,
    provider,
    phase,
    model,
    effort,
    maxTokens,
    attemptKey: parseAttemptKey(values["attempt-key"]),
    attemptRoot,
    providerTimeoutMs,
    approval: approvalPlan.settings,
    sanitizerRequirement: sanitizerPlan.requirement,
    sanitizer: sanitizerPlan.settings,
  };
}

function parseProvider(input: {
  kind: string;
  executable: string | undefined;
  argv: string[] | undefined;
  envAllowlist: string[] | undefined;
  codexHome: string | undefined;
  providerId: string | undefined;
  route: string | undefined;
  implementationVersion: string | undefined;
  outputLimitBytes: string | undefined;
}, run: {
  model: string | null;
  effort: string | null;
  maxTokens: number | null;
  timeoutMs: number | undefined;
  revalidateTransport: CodexAppServerTransportRevalidator | undefined;
}): Provider {
  const hasCommandConfiguration = Object.entries(input).some(
    ([key, value]) => key !== "kind" && value !== undefined,
  );
  if (input.kind === "mock") {
    if (hasCommandConfiguration) throw new Error();
    return createMockProvider();
  }
  if (input.kind === "codex-app-server") {
    if (
      input.executable === undefined ||
      !path.isAbsolute(input.executable) ||
      input.providerId !== undefined ||
      input.route !== undefined ||
      input.implementationVersion !== undefined ||
      (input.codexHome !== undefined &&
        (!path.isAbsolute(input.codexHome) ||
          Buffer.byteLength(input.codexHome, "utf8") > 4096 ||
          input.codexHome.includes("\0"))) ||
      run.revalidateTransport === undefined ||
      run.model === null ||
      run.maxTokens !== null ||
      (run.effort !== null && !CODEX_APP_SERVER_EFFORTS.has(run.effort))
    ) {
      throw new Error();
    }
    requiredSafeLabel(run.model);
    const executableArguments = input.argv ?? [];
    const envAllowlist = input.envAllowlist ?? [];
    if (
      executableArguments.length > 8 ||
      executableArguments.some(
        (value) => Buffer.byteLength(value, "utf8") > 4096 || value.includes("\0"),
      ) ||
      envAllowlist.length > 64
    ) {
      throw new Error();
    }
    return createCodexAppServerProvider({
      process: {
        executable: input.executable,
        executableArguments,
        envAllowlist,
        ...(input.codexHome === undefined ? {} : { codexHome: input.codexHome }),
        ...(run.timeoutMs === undefined ? {} : { timeoutMs: run.timeoutMs }),
        ...(input.outputLimitBytes === undefined
          ? {}
          : {
              outputLimitBytes: parseCodexAppServerOutputLimit(
                input.outputLimitBytes,
              ),
            }),
      },
      revalidateTransport: run.revalidateTransport,
    });
  }
  if (input.kind !== "command" || input.executable === undefined) throw new Error();
  if (
    input.codexHome !== undefined ||
    input.executable.length === 0 ||
    input.executable.length > 240 ||
    !path.isAbsolute(input.executable)
  ) {
    throw new Error();
  }
  const argv = input.argv ?? [];
  const envAllowlist = input.envAllowlist ?? [];
  const normalizedEnvironmentNames = new Set<string>();
  const environmentInvalid = envAllowlist.some((value) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(value)) return true;
    const normalized = value.toUpperCase();
    if (
      normalized === COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV ||
      normalized === COMMAND_PROVIDER_OPERATION_ENV ||
      normalizedEnvironmentNames.has(normalized)
    ) {
      return true;
    }
    normalizedEnvironmentNames.add(normalized);
    return false;
  });
  if (
    argv.length > 64 ||
    argv.some((value) => value.length > 240) ||
    envAllowlist.length > 64 ||
    environmentInvalid
  ) {
    throw new Error();
  }
  const options: CommandProviderOptions = {
    executable: input.executable,
    argv,
    envAllowlist,
    providerId: requiredSafeLabel(input.providerId),
    route: requiredSafeLabel(input.route),
    implementationVersion: requiredSafeLabel(input.implementationVersion),
    ...(input.outputLimitBytes === undefined
      ? {}
      : { outputLimitBytes: parseProviderOutputLimit(input.outputLimitBytes) }),
  };
  return createCommandProvider(options);
}

function parseCommandApproval(
  input: {
    mode: string | undefined;
    executable: string | undefined;
    argv: string[] | undefined;
    envAllowlist: string[] | undefined;
    gateId: string | undefined;
    snapshotDigest: string | undefined;
    runtimeBindingIdentity: string | undefined;
    runtimeBindingDigest: string | undefined;
    approvedScopeIdentity: string | undefined;
    approvedScopeDigest: string | undefined;
    phase: string | undefined;
    timeoutMs: string | undefined;
    outputLimitBytes: string | undefined;
  },
  sanitizerRequirement: SanitizerRequirementSettings,
): ParsedApprovalPlan {
  const hasConfiguration = Object.entries(input).some(
    ([key, value]) => key !== "mode" && value !== undefined,
  );
  if (input.mode === undefined) {
    if (hasConfiguration) throw new Error();
    return { settings: undefined, revalidateTransport: undefined };
  }
  if (input.mode !== "required" && input.mode !== "optional") throw new Error();
  if (input.executable === undefined) {
    if (input.mode === "required" || hasConfiguration) throw new Error();
    return {
      settings: { required: false },
      revalidateTransport: undefined,
    };
  }
  if (
    input.executable.length === 0 ||
    input.executable.length > 240 ||
    !path.isAbsolute(input.executable)
  ) {
    throw new Error();
  }
  const argv = input.argv ?? [];
  const envAllowlist = input.envAllowlist ?? [];
  if (
    argv.length > 64 ||
    argv.some((value) => value.length > 240) ||
    envAllowlist.length > 64 ||
    envAllowlist.some((value) => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(value))
  ) {
    throw new Error();
  }
  const requirement = sanitizerRequirement.decision;
  const timeoutMs =
    input.timeoutMs === undefined ? undefined : parseTimeoutMs(input.timeoutMs);
  const outputLimitBytes =
    input.outputLimitBytes === undefined
      ? DEFAULT_APPROVAL_OUTPUT_LIMIT_BYTES
      : parseApprovalOutputLimit(input.outputLimitBytes);
  const gateId = requiredSafeLabel(input.gateId);
  const commandGate = createCommandApprovalGate({
    executable: input.executable,
    argv,
    envAllowlist,
    outputLimitBytes,
    gateId,
  });
  const bridge = createApprovalRevalidationBridge(
    commandGate,
    timeoutMs ?? 30_000,
  );
  const settings: ApprovalSettings = {
    required: input.mode === "required",
    gate: bridge.gate,
    expectedGateId: gateId,
    expectedProtocolVersion: 1,
    snapshotDigest: requiredDigest(input.snapshotDigest),
    runtimeBindingIdentity: requiredSafeLabel(input.runtimeBindingIdentity),
    runtimeBindingDigest: requiredDigest(input.runtimeBindingDigest),
    approvedScopeIdentity: requiredSafeLabel(input.approvedScopeIdentity),
    approvedScopeDigest: requiredDigest(input.approvedScopeDigest),
    phase: requiredSafeLabel(input.phase),
    expectedRequirementVerifierId: requirement.requirementVerifierId,
    expectedRequirementVerifierVersion: requirement.requirementVerifierVersion,
    expectedConsumerSourceCommit: requirement.consumerSourceCommit,
    expectedRequirementDecisionDigest: requirement.requirementDecisionDigest,
    expectedSanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
    expectedSanitizerRequired: requirement.sanitizerRequired,
    expectedPolicyRequired: requirement.policyRequired,
    expectedSanitizerRequirementReason: requirement.sanitizerRequirementReason,
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
  };
  return { settings, revalidateTransport: bridge.revalidateTransport };
}

function createApprovalRevalidationBridge(
  commandGate: ApprovalGate,
  timeoutMs: number,
): Readonly<{
  gate: ApprovalGate;
  revalidateTransport: CodexAppServerTransportRevalidator;
}> {
  let request: ApprovalRequest | undefined;
  const gate = Object.freeze({
    id: commandGate.id,
    protocolVersion: commandGate.protocolVersion,
    async approve(
      requestValue: ApprovalRequest,
      signal?: AbortSignal,
    ): Promise<ApprovalResponse> {
      request = requestValue;
      return commandGate.approve(requestValue, signal);
    },
  });
  const revalidateTransport: CodexAppServerTransportRevalidator = async (
    _approval,
    signal,
  ) => {
    if (request === undefined || signal?.aborted) throw new Error();
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timer = setTimeout(abort, timeoutMs);
    try {
      return await commandGate.approve(request, controller.signal);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  };
  return Object.freeze({ gate, revalidateTransport });
}

function parseCommandSanitizer(input: {
  mode: string | undefined;
  executable: string | undefined;
  argv: string[] | undefined;
  envAllowlist: string[] | undefined;
  sanitizerId: string | undefined;
  policyPath: string | undefined;
  policyVersion: string | undefined;
  policyDigest: string | undefined;
  caseInputIdentityDigest: string | undefined;
  policyBindingDigest: string | undefined;
  timeoutMs: string | undefined;
  outputLimitBytes: string | undefined;
  allowedFindingPathPatterns: string[] | undefined;
  allowedFailureCodes: string[] | undefined;
  requirementVerifierId: string | undefined;
  requirementVerifierVersion: string | undefined;
  requirementConsumerSourceCommit: string | undefined;
  requirementReason: string | undefined;
  requirementDecisionDigest: string | undefined;
}): {
  requirement: SanitizerRequirementSettings;
  settings: ParsedSanitizerSettings | undefined;
} {
  const configured = Object.entries(input).some(
    ([key, value]) => key !== "mode" && value !== undefined,
  );
  if (input.mode === undefined) {
    if (configured) throw new Error();
    return { requirement: cliSanitizerRequirement(false), settings: undefined };
  }
  if (input.mode !== "required") throw new Error();
  if (
    input.executable === undefined ||
    !path.isAbsolute(input.executable) ||
    input.policyPath === undefined ||
    input.policyPath.length === 0
  ) {
    throw new Error();
  }
  const sanitizerId = requiredSafeLabel(input.sanitizerId);
  const policyVersion = parsePositiveSafeInteger(input.policyVersion ?? "");
  const policyDigest = requiredDigest(input.policyDigest);
  const caseInputIdentityDigest = requiredDigest(input.caseInputIdentityDigest);
  const policyBindingDigest = requiredDigest(input.policyBindingDigest);
  const requirementVerifierId = requiredSafeLabel(input.requirementVerifierId);
  const requirementVerifierVersion = requiredSafeLabel(input.requirementVerifierVersion);
  const requirementReason = requiredSafeLabel(input.requirementReason);
  const consumerSourceCommit =
    input.requirementConsumerSourceCommit === undefined
      ? null
      : requiredSafeLabel(input.requirementConsumerSourceCommit);
  const requirement = cliSanitizerRequirement(true, {
    verifierId: requirementVerifierId,
    verifierVersion: requirementVerifierVersion,
    reason: requirementReason,
    consumerSourceCommit,
    expectedDecisionDigest: requiredDigest(input.requirementDecisionDigest),
  });
  const commandOptions: CommandSanitizerOptions = {
    executable: input.executable,
    argv: input.argv ?? [],
    envAllowlist: input.envAllowlist ?? [],
    sanitizerId,
    allowedFailureCodes: snapshotSafeLabels(input.allowedFailureCodes ?? []),
    ...(input.outputLimitBytes === undefined
      ? {}
      : { outputLimitBytes: parseSanitizerOutputLimit(input.outputLimitBytes) }),
  };
  const sanitizer = createCommandSanitizer(commandOptions);
  return {
    requirement,
    settings: {
      required: true,
      sanitizer,
      policyPath: input.policyPath,
      expectedSanitizerId: sanitizerId,
      expectedProtocolVersion: 1,
      expectedPolicyVersion: policyVersion,
      expectedPolicyDigest: policyDigest,
      expectedCaseInputIdentityVersion: 1,
      expectedCaseInputIdentityDigest: caseInputIdentityDigest,
      expectedPolicyBindingDigest: policyBindingDigest,
      allowedFindingPathPatterns: snapshotSanitizerFindingPathPatterns(
        input.allowedFindingPathPatterns ?? [],
      ),
      ...(input.timeoutMs === undefined ? {} : { timeoutMs: parseTimeoutMs(input.timeoutMs) }),
    },
  };
}

function snapshotSafeLabels(values: readonly string[]): string[] {
  if (values.length > MAX_COMMAND_SANITIZER_FAILURE_CODES) throw new Error();
  const snapshot: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const label = requiredSafeLabel(value);
    if (seen.has(label)) throw new Error();
    seen.add(label);
    snapshot.push(label);
  }
  return snapshot.sort();
}

function parseCompareArguments(): CompareArguments {
  const { positionals, values } = parseArgs({
    args: process.argv.slice(3),
    options: {
      bundle: { type: "string" },
      attempt: { type: "string" },
      rescore: { type: "boolean", default: false },
      "rescore-reason": { type: "string" },
      json: { type: "boolean", default: false },
    },
    allowPositionals: true,
    strict: true,
  });
  if (
    positionals.length !== 0 ||
    typeof values.bundle !== "string" ||
    values.bundle.length === 0 ||
    typeof values.attempt !== "string" ||
    values.attempt.length === 0
  ) {
    throw new Error();
  }
  const rescoreReason = parseSafeReason(values["rescore-reason"]);
  if (values.rescore !== true && rescoreReason !== undefined) throw new Error();
  if (values.rescore === true && rescoreReason === undefined) throw new Error();
  return {
    bundle: values.bundle,
    attempt: values.attempt,
    mode: values.rescore === true ? "rescore" : "normal",
    rescoreReason,
  };
}

function cliSanitizerRequirement(
  required: boolean,
  identity?: {
    verifierId: string;
    verifierVersion: string;
    reason: string;
    consumerSourceCommit: string | null;
    expectedDecisionDigest: string;
  },
): SanitizerRequirementSettings {
  const verifier = {
    id: identity?.verifierId ?? "svbench-cli",
    version: identity?.verifierVersion ?? "v1",
    derive: (_documentKind: string) => ({
      sanitizerRequired: required,
      policyRequired: required,
      sanitizerRequirementReason: identity?.reason ?? "cli_policy_not_required",
      consumerSourceCommit: identity?.consumerSourceCommit ?? null,
    }),
  };
  const core = verifier.derive("");
  const decision = createSanitizerRequirementDecision(core, verifier);
  if (
    identity !== undefined &&
    decision.requirementDecisionDigest !== identity.expectedDecisionDigest
  ) {
    throw new Error();
  }
  return {
    verifier,
    decision,
  };
}

function optionalNonEmptyString(value: string | undefined): string | null {
  if (value === undefined) return null;
  if (value.length === 0) throw new Error();
  return value;
}

function parseAttemptKey(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!/^[A-Za-z0-9._-]{1,64}$/u.test(value)) throw new Error();
  return value;
}

function parseSafeReason(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!/^[A-Za-z0-9._-]{1,64}$/u.test(value)) throw new Error();
  return value;
}

function requiredSafeLabel(value: string | undefined): string {
  if (value === undefined || !/^[A-Za-z0-9._-]{1,64}$/u.test(value)) throw new Error();
  return value;
}

function requiredDigest(value: string | undefined): string {
  if (value === undefined || !/^[a-f0-9]{64}$/u.test(value)) throw new Error();
  return value;
}

function parsePositiveSafeInteger(value: string): number {
  if (!/^[1-9][0-9]*$/u.test(value)) throw new Error();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error();
  return parsed;
}

function parseApprovalOutputLimit(value: string): number {
  const parsed = parsePositiveSafeInteger(value);
  if (parsed > 16 * 1024 * 1024) throw new Error();
  return parsed;
}

function parseProviderOutputLimit(value: string): number {
  const parsed = parsePositiveSafeInteger(value);
  if (parsed > MAX_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES) throw new Error();
  return parsed;
}

function parseCodexAppServerOutputLimit(value: string): number {
  const parsed = parsePositiveSafeInteger(value);
  if (parsed < 1024 || parsed > MAX_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES) {
    throw new Error();
  }
  return parsed;
}

function parseSanitizerOutputLimit(value: string): number {
  const parsed = parsePositiveSafeInteger(value);
  if (parsed > MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES) throw new Error();
  return parsed;
}

function parseTimeoutMs(value: string): number {
  const parsed = parsePositiveSafeInteger(value);
  if (parsed > MAX_TIMEOUT_MS) throw new Error();
  return parsed;
}

function parseMaxTokens(value: string | undefined): number | null {
  if (value === undefined) return null;
  return parsePositiveSafeInteger(value);
}

function reportFailure(failure: Failure): void {
  if (asJson) {
    console.log(
      JSON.stringify({
        ok: false,
        error: { code: failure.code, message: failure.message, details: failure.details },
      }),
    );
  } else {
    console.error(`${failure.code}: ${failure.message}`);
    for (const detail of failure.details) console.error(`  ${detail}`);
  }
  process.exitCode = failure.exitCode;
}
