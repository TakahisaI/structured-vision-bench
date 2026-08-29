import { stat } from "node:fs/promises";
import path from "node:path";

const mode = process.argv[2] ?? "approve";

if (mode === "nonzero") {
  process.exitCode = 7;
} else if (mode === "malformed") {
  process.stdout.write("{synthetic-invalid-json");
} else if (mode === "huge") {
  process.stdout.write("x".repeat(128 * 1024));
} else if (mode === "hang") {
  setInterval(() => undefined, 1_000);
} else {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const forbidden = [
    "caseId",
    "image",
    "schema",
    "system",
    "instruction",
    "truth",
    "comparison",
    "caseInputIdentity",
    "policy",
    "attemptKey",
    "attemptId",
    "runId",
    "bundleDirectory",
    "attemptRoot",
  ];
  const boundaryIsSafe = forbidden.every((key) => !(key in request));
  const environmentIsSafe =
    process.env.SYNTHETIC_ALLOWED_MARKER === "synthetic-allowed" &&
    process.env.SYNTHETIC_BLOCKED_MARKER === undefined;
  const literalArgumentIsSafe = process.argv[3] === "$(synthetic-not-executed)";
  const cwdInfo = await stat(process.cwd());
  const privateWorkingDirectoryIsSafe =
    path.basename(process.cwd()).startsWith("svbench-approval-") &&
    (process.platform === "win32" || (cwdInfo.mode & 0o077) === 0);
  const approved =
    mode !== "deny" &&
    (mode !== "scope" ||
      (request.documentKind === "synthetic_invoice" && request.phase === "development")) &&
    (mode !== "request-boundary" || boundaryIsSafe) &&
    (mode !== "codex-stable" || boundaryIsSafe) &&
    (mode !== "env" || environmentIsSafe) &&
    (mode !== "cwd" || privateWorkingDirectoryIsSafe) &&
    (mode !== "literal-arg" || literalArgumentIsSafe);
  const response = {
    responseVersion: 1,
    approved,
    gateId: request.expected.gateId,
    protocolVersion: request.expected.protocolVersion,
    snapshotDigest: request.expected.snapshotDigest,
    runtimeBindingDigest: request.expected.runtimeBindingDigest,
    runtimeBindingIdentity: request.expected.runtimeBindingIdentity,
    approvedScopeDigest: request.expected.approvedScopeDigest,
    approvedScopeIdentity: request.expected.approvedScopeIdentity,
    phase: request.phase,
    requirementVerifierId: request.expected.requirementVerifierId,
    requirementVerifierVersion: request.expected.requirementVerifierVersion,
    consumerSourceCommit: request.expected.consumerSourceCommit,
    requirementDecisionDigest: request.expected.requirementDecisionDigest,
    sanitizerRequirementVersion: request.sanitizerRequirement.sanitizerRequirementVersion,
    sanitizerRequired: request.sanitizerRequirement.sanitizerRequired,
    policyRequired: request.sanitizerRequirement.policyRequired,
    sanitizerRequirementReason: request.sanitizerRequirement.sanitizerRequirementReason,
    checkedAt:
      mode === "codex-stable" ? "2020-01-01T00:00:00.000Z" : new Date().toISOString(),
    expiresAt:
      mode === "codex-stable"
        ? "2099-01-01T00:00:00.000Z"
        : new Date(Date.now() + 60_000).toISOString(),
    ...(approved ? {} : { reasonCode: "synthetic_denied" }),
  };
  if (mode === "mismatch-scope") response.approvedScopeDigest = "f".repeat(64);
  if (mode === "mutate-requirement") response.sanitizerRequired = !response.sanitizerRequired;
  if (mode === "expired") response.expiresAt = "2020-01-01T00:00:00Z";
  if (mode === "unexpected") response.syntheticUnexpected = true;
  process.stdout.write(`${JSON.stringify(response)}\n`);
}
