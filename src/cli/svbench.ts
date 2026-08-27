import { parseArgs } from "node:util";
import path from "node:path";

import { createMockProvider } from "../provider/mock.js";
import { RunnerError } from "../runner/errors.js";
import {
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../runner/identity.js";
import { runBundle } from "../runner/run.js";
import { BundleValidationError } from "../bundle/validate-bundle.js";

const USAGE =
  "usage: svbench run --bundle <bundle-directory> --provider mock [--model <id>] [--effort <level>] [--max-tokens <n>] [--attempt-key <label>] [--attempt-root <directory>] [--json]";
const asJson = process.argv.slice(2).includes("--json");

type RunArguments = {
  bundle: string;
  provider: string;
  model: string | null;
  effort: string | null;
  maxTokens: number | null;
  attemptKey: string | undefined;
  attemptRoot: string;
};

type Failure = {
  code: string;
  message: string;
  details: string[];
  exitCode: 1 | 2;
};

let runArguments: RunArguments | undefined;
try {
  runArguments = parseRunArguments();
} catch {
  reportFailure({ code: "invalid_arguments", message: USAGE, details: [], exitCode: 2 });
}

if (runArguments !== undefined) {
  try {
    const result = await runBundle({
      bundleDirectory: runArguments.bundle,
      attemptRoot: runArguments.attemptRoot,
      provider: createMockProvider(),
      requestedModel: runArguments.model,
      requestedEffort: runArguments.effort,
      maxTokens: runArguments.maxTokens,
      ...(runArguments.attemptKey === undefined ? {} : { attemptKey: runArguments.attemptKey }),
      sanitizerRequirement: cliSanitizerRequirement(),
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
  } catch (error) {
    if (error instanceof BundleValidationError || error instanceof RunnerError) {
      reportFailure({
        code: error.code,
        message: error.message,
        details: error.details,
        exitCode: 1,
      });
    } else {
      reportFailure({
        code: "internal_error",
        message: "run failed unexpectedly",
        details: [],
        exitCode: 2,
      });
    }
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
  return {
    bundle: values.bundle,
    provider: values.provider,
    model: optionalNonEmptyString(values.model),
    effort: optionalNonEmptyString(values.effort),
    maxTokens,
    attemptKey: parseAttemptKey(values["attempt-key"]),
    attemptRoot,
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

function parseMaxTokens(value: string | undefined): number | null {
  if (value === undefined) return null;
  if (!/^[1-9][0-9]*$/u.test(value)) throw new Error();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error();
  return parsed;
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
