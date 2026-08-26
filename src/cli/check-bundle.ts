import { parseArgs } from "node:util";

import { BundleValidationError, validateBundle } from "../bundle/validate-bundle.js";

const { positionals, values } = parseArgs({
  options: { json: { type: "boolean", default: false } },
  allowPositionals: true,
  strict: true,
});

if (positionals.length !== 1) {
  console.error("usage: npm run bundle:check -- <bundle-directory> [--json]");
  process.exitCode = 2;
} else {
  try {
    const result = await validateBundle(positionals[0]!);
    if (values.json) console.log(JSON.stringify({ ok: true, ...result }));
    else console.log(`bundle valid: ${result.caseId} (${result.referencedFiles} files)`);
  } catch (error) {
    if (error instanceof BundleValidationError) {
      if (values.json) {
        console.log(
          JSON.stringify({ ok: false, error: { code: error.code, message: error.message, details: error.details } }),
        );
      } else {
        console.error(`${error.code}: ${error.message}`);
        for (const detail of error.details) console.error(`  ${detail}`);
      }
      process.exitCode = 1;
    } else {
      console.error("internal_error: bundle validation failed unexpectedly");
      process.exitCode = 2;
    }
  }
}
