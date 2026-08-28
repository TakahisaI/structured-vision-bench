import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  compareAttempt,
  ComparisonError,
  computeComparisonResultDigest,
  computeScoringRevision,
  renderComparisonMarkdown,
  type ComparisonResultCore,
} from "../src/comparison/compare.js";
import { createMockProvider } from "../src/provider/mock.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../src/runner/identity.js";
import { runBundle } from "../src/runner/run.js";
import { createSanitizerPolicyEnvelope, type Sanitizer } from "../src/runner/sanitizer.js";
import { decodeUtf8Strict, parseJson, type JsonValue } from "../src/bundle/json.js";
import {
  validateJsonSchema,
  validateJsonSchemaDefinition,
} from "../src/bundle/schema-validator.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const IMAGE_SHA256 = "dda43d98857bc0977a1bdc67e8005428c3af95ca73cddda69c9e8737eee03cc9";

const COMPLETE_DOCUMENT = {
  documentKind: "synthetic_invoice",
  invoiceNumber: "INV-SYNTH-001",
  issuedAt: "2030-01-15",
  currency: "JPY",
  lines: [
    {
      lineNo: 1,
      description: "Widget Alpha",
      quantity: 2,
      unitPrice: 500,
      amount: 1000,
    },
    {
      lineNo: 2,
      description: "Service Beta",
      quantity: 1,
      unitPrice: 234,
      amount: 234,
    },
  ],
  totalAmount: 1234,
} satisfies JsonValue;

test("computes the scoring revision v1 fixed vector", () => {
  assert.equal(
    computeScoringRevision("0".repeat(64)),
    "c3ebfccb8858224cc0987b0b59e65d0aff2b2136a7225a20884c2579326384d1",
  );
});

test("compares a complete match and renders value-free Markdown", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    const attemptDirectory = await runDocument(bundle, attempts, COMPLETE_DOCUMENT);
    const result = await compareAttempt({ bundleDirectory: bundle, attemptDirectory });

    assert.deepEqual(result.summary.fields, {
      total: 13,
      matched: 13,
      missed: 0,
      fabricated: 0,
      wrong: 0,
      comparisonErrors: 0,
    });
    assert.deepEqual(result.summary.arrays, {
      expected: 2,
      actual: 2,
      matched: 2,
      missing: 0,
      extra: 0,
      comparisonErrors: 0,
    });
    assert.equal(result.summary.hardGate.passed, true);
    assert.equal(result.warnings.length, 0);
    assert.match(result.scoringRevision, /^[a-f0-9]{64}$/u);
    assert.match(result.resultDigest, /^[a-f0-9]{64}$/u);
    const { resultDigest: _resultDigest, ...core } = result;
    assert.equal(computeComparisonResultDigest(core), result.resultDigest);
    const reordered = Object.fromEntries(Object.entries(core).reverse()) as ComparisonResultCore;
    assert.equal(computeComparisonResultDigest(reordered), result.resultDigest);
    const resultSchema = parseJson(
      decodeUtf8Strict(
        await readFile("schemas/comparison-v1.schema.json"),
        "comparison result schema",
      ),
      "comparison result schema",
    );
    assert.deepEqual(validateJsonSchemaDefinition(resultSchema), []);
    assert.deepEqual(validateJsonSchema(resultSchema, result as unknown as JsonValue), []);
    const mislabeledNormalResult = structuredClone(result) as Record<string, any>;
    mislabeledNormalResult.identity.rescoreReason = "synthetic-reason";
    assert.notDeepEqual(
      validateJsonSchema(resultSchema, mislabeledNormalResult as JsonValue),
      [],
    );
    const reasonlessRescoreResult = structuredClone(result) as Record<string, any>;
    reasonlessRescoreResult.identity.rescored = true;
    assert.notDeepEqual(validateJsonSchema(resultSchema, reasonlessRescoreResult as JsonValue), []);

    const markdown = renderComparisonMarkdown(result);
    assert.match(markdown, /Field matched\/total: 13\/13/u);
    assert.equal(markdown.includes("INV-SYNTH-001"), false);
    assert.equal(markdown.includes("synthetic-invoice-basic"), false);
  });
});

test("classifies null, empty, wrong, missing, and extra values with exact denominators", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    await rewriteTruth(bundle, (truth) => {
      truth.currency = null;
    });
    await rewriteOutputSchema(bundle, (schema) => {
      const properties = schema.properties as Record<string, any>;
      properties.invoiceNumber.type = ["null", "string"];
      properties.currency = { type: ["null", "string"] };
      const lineProperties = properties.lines.items.properties as Record<string, any>;
      lineProperties.quantity.type = ["null", "number"];
    });
    const document = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    document.invoiceNumber = null;
    document.currency = "";
    document.totalAmount = 999;
    document.lines = [
      {
        lineNo: 1,
        description: "Widget Alpha",
        quantity: 2,
        unitPrice: 500,
        amount: 1000,
      },
      {
        lineNo: 3,
        description: "Synthetic Extra",
        quantity: null,
        unitPrice: 20,
        amount: 20,
      },
    ];
    const attemptDirectory = await runDocument(bundle, attempts, document as JsonValue);
    const result = await compareAttempt({ bundleDirectory: bundle, attemptDirectory });

    assert.deepEqual(result.summary.outcomes, {
      missed: 5,
      fabricated: 4,
      wrong: 1,
      missingItem: 1,
      extraItem: 1,
      comparisonError: 0,
    });
    assert.deepEqual(result.summary.fields, {
      total: 16,
      matched: 6,
      missed: 5,
      fabricated: 4,
      wrong: 1,
      comparisonErrors: 0,
    });
    assert.equal(result.summary.arrays.missing, 1);
    assert.equal(result.summary.arrays.extra, 1);
    assert.equal(result.summary.hardGate.passed, false);
  });
});

test("keeps null-null and missing or extra null fields out of the denominator", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    await rewriteTruth(bundle, (truth) => {
      truth.currency = null;
      truth.lines[1]!.description = null;
    });
    await rewriteOutputSchema(bundle, (schema) => {
      const properties = schema.properties as Record<string, any>;
      properties.currency = { type: ["null", "string"] };
      const lineProperties = properties.lines.items.properties as Record<string, any>;
      lineProperties.description.type = ["null", "string"];
      lineProperties.quantity.type = ["null", "number"];
    });
    const document = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    document.currency = null;
    document.lines = [
      COMPLETE_DOCUMENT.lines[0]!,
      {
        lineNo: 3,
        description: null,
        quantity: null,
        unitPrice: 1,
        amount: 1,
      },
    ];
    const attemptDirectory = await runDocument(bundle, attempts, document as JsonValue);
    const result = await compareAttempt({ bundleDirectory: bundle, attemptDirectory });

    assert.equal(result.summary.fields.total, 13);
    assert.equal(result.summary.outcomes.missed, 3);
    assert.equal(result.summary.outcomes.fabricated, 2);
    assert.equal(result.summary.outcomes.missingItem, 1);
    assert.equal(result.summary.outcomes.extraItem, 1);
  });
});

test("keeps field-critical mismatches separate from membership-critical failures", async () => {
  await withBundle(async ({ temporary, bundle, attempts }) => {
    const missingItemDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    missingItemDocument.lines = [COMPLETE_DOCUMENT.lines[0]!];
    const fieldOnlyAttempt = await runDocument(bundle, attempts, missingItemDocument as JsonValue);
    const fieldOnly = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: fieldOnlyAttempt,
    });
    assert.equal(fieldOnly.summary.outcomes.missingItem, 1);
    assert.equal(fieldOnly.summary.hardGate.passed, true);

    const fieldMismatchDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, any>;
    fieldMismatchDocument.lines[0].amount = 999;
    const fieldMismatchAttempt = await runDocument(
      bundle,
      path.join(temporary, "field-mismatch-attempts"),
      fieldMismatchDocument as JsonValue,
    );
    const fieldMismatch = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: fieldMismatchAttempt,
    });
    assert.equal(fieldMismatch.summary.outcomes.wrong, 1);
    assert.equal(fieldMismatch.summary.hardGate.passed, false);

    const membershipBundle = path.join(temporary, "membership-bundle");
    const membershipAttempts = path.join(temporary, "membership-attempts");
    await cp(bundle, membershipBundle, { recursive: true });
    await rewriteManifest(membershipBundle, (manifest) => {
      const comparison = manifest.comparison as { critical: string[] };
      comparison.critical = ["/lines/*/lineNo"];
    });
    await rewriteOutputSchema(membershipBundle, (schema) => {
      const properties = schema.properties as Record<string, any>;
      const lineProperties = properties.lines.items.properties as Record<string, any>;
      lineProperties.lineNo.type = ["null", "integer"];
    });
    const membershipAttempt = await runDocument(
      membershipBundle,
      membershipAttempts,
      missingItemDocument as JsonValue,
    );
    const membership = await compareAttempt({
      bundleDirectory: membershipBundle,
      attemptDirectory: membershipAttempt,
    });
    assert.equal(membership.summary.outcomes.missingItem, 1);
    assert.equal(membership.summary.hardGate.passed, false);
    assert.equal(membership.summary.hardGate.criticalFailures, 1);

    const invalidKeyDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, any>;
    invalidKeyDocument.lines[0].lineNo = null;
    const invalidKeyAttempt = await runDocument(
      membershipBundle,
      path.join(temporary, "invalid-key-attempts"),
      invalidKeyDocument as JsonValue,
    );
    const invalidKey = await compareAttempt({
      bundleDirectory: membershipBundle,
      attemptDirectory: invalidKeyAttempt,
    });
    assert.equal(invalidKey.summary.outcomes.comparisonError, 1);
    assert.equal(invalidKey.summary.hardGate.passed, false);
    assert.equal(invalidKey.summary.hardGate.criticalFailures, 2);
  });
});

test("reports unresolved paths and invalid keys as comparison errors without pairing them", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    await rewriteOutputSchema(bundle, (schema) => {
      schema.required = (schema.required as string[]).filter(
        (field) => field !== "invoiceNumber" && field !== "lines",
      );
      const properties = schema.properties as Record<string, any>;
      properties.lines.items.required = (properties.lines.items.required as string[]).filter(
        (field) => field !== "lineNo",
      );
      const lineProperties = properties.lines.items.properties as Record<string, any>;
      lineProperties.lineNo.type = ["null", "integer", "string"];
      lineProperties.description.type = ["string", "object"];
    });
    const document = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    delete document.invoiceNumber;
    document.lines = [
      {
        lineNo: null,
        description: "Synthetic Invalid",
        quantity: 1,
        unitPrice: 1,
        amount: 1,
      },
      {
        description: "Synthetic Missing Key",
        quantity: 1,
        unitPrice: 1,
        amount: 1,
      },
      {
        lineNo: "",
        description: "Synthetic Empty Key",
        quantity: 1,
        unitPrice: 1,
        amount: 1,
      },
      {
        lineNo: 2,
        description: { invalid: true },
        quantity: 1,
        unitPrice: 234,
        amount: 234,
      },
    ];
    const attemptDirectory = await runDocument(bundle, attempts, document as JsonValue);
    const result = await compareAttempt({ bundleDirectory: bundle, attemptDirectory });

    assert.equal(result.summary.outcomes.comparisonError, 5);
    assert.equal(result.summary.arrays.missing, 1);
    assert.equal(result.summary.arrays.matched, 1);
    assert.equal(result.summary.hardGate.passed, false);
    assert.equal(JSON.stringify(result).includes("Synthetic Invalid"), false);

    const missingArrayDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    delete missingArrayDocument.lines;
    const missingArrayAttempt = await runDocument(
      bundle,
      path.join(path.dirname(attempts), "missing-array-attempts"),
      missingArrayDocument as JsonValue,
    );
    const missingArray = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: missingArrayAttempt,
    });
    assert.equal(missingArray.summary.arrays.actual, null);
    assert.equal(missingArray.summary.arrays.comparisonErrors, 1);
    assert.equal(missingArray.summary.outcomes.comparisonError, 1);
  });
});

test("does not coerce key types or pair duplicate normalized keys", async () => {
  await withBundle(async ({ temporary, bundle, attempts }) => {
    await rewriteOutputSchema(bundle, (schema) => {
      const properties = schema.properties as Record<string, any>;
      properties.totalAmount.type = ["integer", "string"];
      const lineProperties = properties.lines.items.properties as Record<string, any>;
      lineProperties.lineNo.type = ["integer", "string"];
    });
    const stringKeyDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, any>;
    stringKeyDocument.lines[0].lineNo = "1";
    stringKeyDocument.lines[1].lineNo = "2";
    const stringKeyAttempt = await runDocument(
      bundle,
      attempts,
      stringKeyDocument as JsonValue,
    );
    const stringKeys = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: stringKeyAttempt,
    });
    assert.equal(stringKeys.summary.arrays.matched, 0);
    assert.equal(stringKeys.summary.outcomes.missingItem, 2);
    assert.equal(stringKeys.summary.outcomes.extraItem, 2);

    const duplicateDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, any>;
    duplicateDocument.lines[0].lineNo = "1";
    duplicateDocument.lines[1].lineNo = "１";
    const duplicateAttempt = await runDocument(
      bundle,
      path.join(temporary, "duplicate-attempts"),
      duplicateDocument as JsonValue,
    );
    const duplicates = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: duplicateAttempt,
    });
    assert.equal(duplicates.summary.arrays.matched, 0);
    assert.equal(duplicates.summary.arrays.comparisonErrors, 2);
    assert.equal(duplicates.summary.outcomes.comparisonError, 2);

    const formattedNumberDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    formattedNumberDocument.totalAmount = "1,234";
    const formattedNumberAttempt = await runDocument(
      bundle,
      path.join(temporary, "formatted-number-attempts"),
      formattedNumberDocument as JsonValue,
    );
    const formattedNumber = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: formattedNumberAttempt,
    });
    assert.equal(formattedNumber.summary.outcomes.wrong, 1);
  });
});

test("applies only declared string normalization in canonical order", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    const normalizedDocument = structuredClone(COMPLETE_DOCUMENT) as Record<string, JsonValue>;
    normalizedDocument.invoiceNumber = "  ＩＮＶ－ＳＹＮＴＨ－００１  ";
    const normalizedAttempt = await runDocument(bundle, attempts, normalizedDocument as JsonValue);
    const normalized = await compareAttempt({ bundleDirectory: bundle, attemptDirectory: normalizedAttempt });
    assert.equal(normalized.fields[1]!.statistics.matched, 1);

    const noNfkcBundle = path.join(path.dirname(bundle), "bundle-no-nfkc");
    await cp(bundle, noNfkcBundle, { recursive: true });
    await rewriteManifest(noNfkcBundle, (manifest) => {
      const comparison = manifest.comparison as { normalization: { strings: string[] } };
      comparison.normalization.strings = ["trim", "collapse-whitespace"];
    });
    await assert.rejects(
      compareAttempt({ bundleDirectory: noNfkcBundle, attemptDirectory: normalizedAttempt }),
      (error: unknown) =>
        error instanceof ComparisonError && error.code === "comparison_bundle_identity_mismatch",
    );
    const rescored = await compareAttempt({
      bundleDirectory: noNfkcBundle,
      attemptDirectory: normalizedAttempt,
      mode: "rescore",
      rescoreReason: "synthetic-policy-revision",
    });
    assert.equal(rescored.fields[1]!.statistics.wrong, 1);
  });
});

test("allows explicit truth rescoring but rejects provider-input identity changes", async () => {
  await withBundle(async ({ bundle, attempts, temporary }) => {
    const attemptDirectory = await runDocument(bundle, attempts, COMPLETE_DOCUMENT);
    const scoringBundle = path.join(temporary, "scoring-bundle");
    await cp(bundle, scoringBundle, { recursive: true });
    await rewriteTruth(scoringBundle, (truth) => {
      truth.totalAmount = 999;
    });

    await assert.rejects(
      compareAttempt({ bundleDirectory: scoringBundle, attemptDirectory }),
      (error: unknown) =>
        error instanceof ComparisonError && error.code === "comparison_bundle_identity_mismatch",
    );
    const rescored = await compareAttempt({
      bundleDirectory: scoringBundle,
      attemptDirectory,
      mode: "rescore",
      rescoreReason: "synthetic-truth-correction",
    });
    assert.equal(rescored.identity.rescored, true);
    assert.equal(rescored.summary.outcomes.wrong, 1);
    assert.notEqual(rescored.identity.executionBundleDigest, rescored.identity.scoringBundleDigest);

    const systemPath = path.join(scoringBundle, "system.txt");
    const system = `${await readFile(systemPath, "utf8")}synthetic changed input\n`;
    await writeFile(systemPath, system, "utf8");
    await rewriteManifest(scoringBundle, (manifest) => {
      const inputs = manifest.inputs as { system: { sha256: string } };
      inputs.system.sha256 = createHash("sha256").update(system).digest("hex");
    });
    await assert.rejects(
      compareAttempt({
        bundleDirectory: scoringBundle,
        attemptDirectory,
        mode: "rescore",
        rescoreReason: "synthetic-input-change",
      }),
      (error: unknown) =>
        error instanceof ComparisonError && error.code === "comparison_bundle_identity_mismatch",
    );
  });
});

test("rejects unknown comparison modes without relaxing bundle identity", async () => {
  await withBundle(async ({ bundle, attempts, temporary }) => {
    const attemptDirectory = await runDocument(bundle, attempts, COMPLETE_DOCUMENT);
    const scoringBundle = path.join(temporary, "unknown-mode-scoring-bundle");
    await cp(bundle, scoringBundle, { recursive: true });
    await rewriteTruth(scoringBundle, (truth) => {
      truth.totalAmount = 999;
    });

    await assert.rejects(
      compareAttempt({
        bundleDirectory: scoringBundle,
        attemptDirectory,
        mode: "rescroe" as never,
        rescoreReason: "synthetic-truth-fix",
      }),
      (error: unknown) =>
        error instanceof ComparisonError &&
        error.code === "comparison_configuration_invalid" &&
        error.message === "comparison mode is invalid",
    );
  });
});

test("rejects comparison when the validated bundle has no truth projection", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    await rewriteManifest(bundle, (manifest) => {
      const inputs = manifest.inputs as Record<string, unknown>;
      delete inputs.truth;
    });
    const attemptDirectory = await runDocument(bundle, attempts, COMPLETE_DOCUMENT);
    await assert.rejects(
      compareAttempt({ bundleDirectory: bundle, attemptDirectory }),
      (error: unknown) =>
        error instanceof ComparisonError && error.code === "comparison_truth_missing",
    );
  });
});

test("keeps sanitizer hard-gate findings outside field averages", async () => {
  await withBundle(async ({ bundle, attempts }) => {
    const identity = computeCaseInputIdentity({
      caseId: "synthetic-invoice-basic",
      documentKind: "synthetic_invoice",
      preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
    });
    const policyBytes = createSanitizerPolicyEnvelope({
      target: identity,
      policyVersion: 1,
      policy: { syntheticRule: "hard-gate" },
    });
    const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
    const policyBindingDigest = computePolicyBindingDigest({
      caseInputIdentityDigest: identity.digest,
      policyVersion: 1,
      policyDigest,
    });
    const sanitizer: Sanitizer = {
      id: "synthetic-sanitizer",
      protocolVersion: 1,
      sanitize: async () => ({
        sanitizedDocument: COMPLETE_DOCUMENT,
        sanitizerId: "synthetic-sanitizer",
        protocolVersion: 1,
        policyVersion: 1,
        policyDigest,
        caseInputIdentityVersion: 1,
        caseInputIdentityDigest: identity.digest,
        policyTargetIdentityDigest: identity.digest,
        policyBindingDigest,
        findings: [
          {
            code: "synthetic-hard-gate",
            severity: "error",
            classification: "synthetic-policy",
            hardGate: true,
            path: "/invoiceNumber",
          },
        ],
      }),
    };
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider({ document: COMPLETE_DOCUMENT }),
      sanitizerRequirement: syntheticRequirement(true),
      sanitizer: {
        required: true,
        sanitizer,
        policyEnvelopeBytes: policyBytes,
        expectedSanitizerId: sanitizer.id,
        expectedProtocolVersion: 1,
        expectedPolicyVersion: 1,
        expectedPolicyDigest: policyDigest,
        expectedCaseInputIdentityVersion: 1,
        expectedCaseInputIdentityDigest: identity.digest,
        expectedPolicyBindingDigest: policyBindingDigest,
        allowedFindingPathPatterns: ["/invoiceNumber"],
      },
    });
    const comparison = await compareAttempt({
      bundleDirectory: bundle,
      attemptDirectory: result.attemptDirectory,
    });
    assert.equal(comparison.summary.fields.matched, 13);
    assert.equal(comparison.summary.hardGate.sanitizerFailures, 1);
    assert.equal(comparison.summary.hardGate.passed, false);
    assert.equal(comparison.identity.sanitizer?.findings[0]?.path, "/invoiceNumber");
    assert.equal(renderComparisonMarkdown(comparison).includes("/invoiceNumber"), false);
    const resultSchema = parseJson(
      decodeUtf8Strict(
        await readFile("schemas/comparison-v1.schema.json"),
        "comparison result schema",
      ),
      "comparison result schema",
    );
    assert.deepEqual(validateJsonSchema(resultSchema, comparison as unknown as JsonValue), []);
  });
});

async function withBundle(
  callback: (context: {
    temporary: string;
    bundle: string;
    attempts: string;
  }) => Promise<void>,
): Promise<void> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-comparison-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await callback({ temporary, bundle, attempts });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function runDocument(bundle: string, attempts: string, document: JsonValue): Promise<string> {
  const result = await runBundle({
    bundleDirectory: bundle,
    attemptRoot: attempts,
    provider: createMockProvider({ document }),
    sanitizerRequirement: syntheticRequirement(false),
  });
  return result.attemptDirectory;
}

function syntheticRequirement(required: boolean): SanitizerRequirementSettings {
  const verifier = {
    id: "synthetic-comparison-consumer",
    version: "v1",
    derive: (_documentKind: string) => ({
      sanitizerRequired: required,
      policyRequired: required,
      sanitizerRequirementReason: required
        ? "synthetic_policy_required"
        : "synthetic_policy_not_required",
      consumerSourceCommit: null,
    }),
  };
  const core = verifier.derive("synthetic_invoice");
  return { verifier, decision: createSanitizerRequirementDecision(core, verifier) };
}

async function rewriteTruth(
  bundle: string,
  mutate: (truth: Record<string, any>) => void,
): Promise<void> {
  const truthPath = path.join(bundle, "truth.json");
  const truth = JSON.parse(await readFile(truthPath, "utf8")) as Record<string, any>;
  mutate(truth);
  const bytes = `${JSON.stringify(truth, null, 2)}\n`;
  await writeFile(truthPath, bytes, "utf8");
  await rewriteManifest(bundle, (manifest) => {
    const inputs = manifest.inputs as { truth: { sha256: string } };
    inputs.truth.sha256 = createHash("sha256").update(bytes).digest("hex");
  });
}

async function rewriteManifest(
  bundle: string,
  mutate: (manifest: Record<string, unknown>) => void,
): Promise<void> {
  const manifestPath = path.join(bundle, "bundle.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<string, unknown>;
  mutate(manifest);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function rewriteOutputSchema(
  bundle: string,
  mutate: (schema: Record<string, any>) => void,
): Promise<void> {
  const schemaPath = path.join(bundle, "schema.json");
  const schema = JSON.parse(await readFile(schemaPath, "utf8")) as Record<string, any>;
  mutate(schema);
  const bytes = `${JSON.stringify(schema, null, 2)}\n`;
  await writeFile(schemaPath, bytes, "utf8");
  await rewriteManifest(bundle, (manifest) => {
    const inputs = manifest.inputs as { schema: { sha256: string } };
    inputs.schema.sha256 = createHash("sha256").update(bytes).digest("hex");
  });
}
