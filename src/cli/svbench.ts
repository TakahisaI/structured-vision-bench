import { parseArgs } from "node:util";
import path from "node:path";

import {
  compareAttempt,
  ComparisonError,
  renderComparisonMarkdown,
} from "../comparison/compare.js";
import { createMockProvider } from "../provider/mock.js";
import { RunnerError } from "../runner/errors.js";
import {
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../runner/identity.js";
import { MAX_TIMEOUT_MS, runBundle } from "../runner/run.js";
import { BundleValidationError } from "../bundle/validate-bundle.js";
import type { ApprovalSettings } from "../runner/types.js";

const RUN_USAGE =
  "usage: svbench run --bundle <bundle-directory> --provider mock [--model <id>] [--effort <level>] [--max-tokens <n>] [--attempt-key <label>] [--attempt-root <directory>] [--approval required|optional --approval-command <executable> <approval identity options>] [--json]";
const COMPARE_USAGE =
  "usage: svbench compare --bundle <bundle-directory> --attempt <attempt-directory> [--rescore --rescore-reason <code>] [--json]";
const asJson = process.argv.slice(2).includes("--json");

type RunArguments = {
  bundle: string;
  provider: string;
  model: string | null;
  effort: string | null;
  maxTokens: number | null;
  attemptKey: string | undefined;
  attemptRoot: string;
  approval: ApprovalSettings | undefined;
};

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
  const result = await runBundle({
    bundleDirectory: runArguments.bundle,
    attemptRoot: runArguments.attemptRoot,
    provider: createMockProvider(),
    requestedModel: runArguments.model,
    requestedEffort: runArguments.effort,
    maxTokens: runArguments.maxTokens,
    ...(runArguments.attemptKey === undefined ? {} : { attemptKey: runArguments.attemptKey }),
    sanitizerRequirement: cliSanitizerRequirement(),
    ...(runArguments.approval === undefined ? {} : { approval: runArguments.approval }),
  });
  if (asJson) {
    console.log(
      JSON.stringify({
        ok: true,
        caseId: result.caseId,
        attemptKey: result.attemptKey,
        attemptId: result.attemptId,
        runId: result.runId,
      }),
    );
  } else {
    console.log(
      `run complete: ${result.caseId} (key ${result.attemptKey}, attempt ${result.attemptId}, run ${result.runId})`,
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
      json: { type: "boolean", default: false },
    },
    allowPositionals: true,
    strict: true,
  });
  if (
    positionals.length !== 0 ||
    typeof values.bundle !== "string" ||
    typeof values.provider !== "string" ||
    values.bundle.length === 0 ||
    values.provider !== "mock"
  ) {
    throw new Error();
  }
  const maxTokens = parseMaxTokens(values["max-tokens"]);
  const attemptRoot =
    typeof values["attempt-root"] === "string" && values["attempt-root"].length > 0
      ? values["attempt-root"]
      : path.resolve("attempts");
  const approval = parseCommandApproval({
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
  });
  return {
    bundle: values.bundle,
    provider: values.provider,
    model: optionalNonEmptyString(values.model),
    effort: optionalNonEmptyString(values.effort),
    maxTokens,
    attemptKey: parseAttemptKey(values["attempt-key"]),
    attemptRoot,
    approval,
  };
}

function parseCommandApproval(input: {
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
}): ApprovalSettings | undefined {
  const hasConfiguration = Object.entries(input).some(
    ([key, value]) => key !== "mode" && value !== undefined,
  );
  if (input.mode === undefined) {
    if (hasConfiguration) throw new Error();
    return undefined;
  }
  if (input.mode !== "required" && input.mode !== "optional") throw new Error();
  if (input.executable === undefined) {
    if (input.mode === "required" || hasConfiguration) throw new Error();
    return { required: false };
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
  const requirement = cliSanitizerRequirement().decision;
  return {
    required: input.mode === "required",
    executable: input.executable,
    argv,
    envAllowlist,
    expectedGateId: requiredSafeLabel(input.gateId),
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
    ...(input.timeoutMs === undefined
      ? {}
      : { timeoutMs: parseTimeoutMs(input.timeoutMs) }),
    ...(input.outputLimitBytes === undefined
      ? {}
      : { outputLimitBytes: parseApprovalOutputLimit(input.outputLimitBytes) }),
  };
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

function cliSanitizerRequirement(): SanitizerRequirementSettings {
  const verifier = {
    id: "svbench-cli",
    version: "v1",
    derive: (_documentKind: string) => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "mock_provider_policy_not_required",
      consumerSourceCommit: null,
    }),
  };
  const core = verifier.derive("");
  return {
    verifier,
    decision: createSanitizerRequirementDecision(core, verifier),
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
