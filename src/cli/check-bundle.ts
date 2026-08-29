import { parseArgs } from "node:util";

import { BundleValidationError, validateBundle } from "../bundle/validate-bundle.js";

const USAGE = "usage: npm run bundle:check -- <bundle-directory> [--json]";

// Output format is decided before parsing so that even a failing argument parse
// can honor an explicit --json request.
const asJson = process.argv.slice(2).includes("--json");

type CliFailure = {
  code: string;
  message: string;
  details: string[];
  exitCode: number;
};

let positionals: string[];

try {
  // Only argument parsing maps to invalid_arguments. Everything after this
  // block has its own error boundary below.
  ({ positionals } = parseArgs({
    options: { json: { type: "boolean", default: false } },
    allowPositionals: true,
    strict: true,
  }));
} catch {
  reportFailure({ code: "invalid_arguments", message: USAGE, details: [], exitCode: 2 });
  // reportFailure sets process.exitCode; keep going so the module ends cleanly.
  process.exit(process.exitCode || 2);
}

try {
  if (positionals!.length !== 1) {
    reportFailure({ code: "invalid_arguments", message: USAGE, details: [], exitCode: 2 });
  } else {
    const result = await validateBundle(positionals![0]!);
    if (asJson) console.log(JSON.stringify({ ok: true, ...result }));
    else console.log(`bundle valid: ${result.caseId} (${result.referencedFiles} files)`);
  }
} catch (error) {
  if (error instanceof BundleValidationError) {
    if (error.code === "bundle_io_error") {
      reportFailure({
        code: "internal_error",
        message: "bundle validation failed unexpectedly",
        details: [],
        exitCode: 2,
      });
    } else {
      reportFailure({
        code: error.code,
        message: error.message,
        details: error.details,
        exitCode: 1,
      });
    }
  } else {
    // Unexpected failures (filesystem races, permission errors, internal bugs)
    // must not masquerade as bad arguments and must never leak a stack trace
    // or internal paths.
    console.error("internal_error: bundle validation failed unexpectedly");
    if (asJson) {
      console.log(
        JSON.stringify({
          ok: false,
          error: { code: "internal_error", message: "bundle validation failed unexpectedly", details: [] },
        }),
      );
    }
    process.exitCode = 2;
  }
}

function reportFailure(failure: CliFailure): void {
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
