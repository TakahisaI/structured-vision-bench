import { createHash } from "node:crypto";

import type { JsonValue } from "../bundle/json.js";
import { isJsonObject } from "../bundle/json.js";
import {
  JSON_POINTER_NOT_FOUND,
  boundDetails,
  decodePointerSegments,
  loadBundleForComparison,
  normalizeKeyForComparison,
  resolvePointer,
  type LoadedBundleForComparison,
} from "../bundle/validate-bundle.js";
import { readAttempt, type AttemptManifest, type AttemptReadResult } from "../runner/attempt.js";
import type { SanitizerRequirementVerifier } from "../runner/identity.js";

export const COMPARISON_VERSION = 1 as const;
export const SCORING_REVISION_VERSION = 1 as const;

export type ComparisonErrorCode =
  | "comparison_configuration_invalid"
  | "comparison_truth_missing"
  | "comparison_bundle_identity_mismatch";

export class ComparisonError extends Error {
  readonly code: ComparisonErrorCode;
  readonly details: string[];

  constructor(code: ComparisonErrorCode, message: string, details: string[] = []) {
    super(message.length <= 240 ? message : `${message.slice(0, 239)}…`);
    this.name = "ComparisonError";
    this.code = code;
    this.details = boundDetails(details);
  }
}

export type CompareAttemptOptions = {
  bundleDirectory: string;
  attemptDirectory: string;
  mode?: "normal" | "rescore";
  rescoreReason?: string;
  contractSchemaPath?: string;
  requirementVerifier?: SanitizerRequirementVerifier;
};

export type FieldStatistics = {
  total: number;
  matched: number;
  missed: number;
  fabricated: number;
  wrong: number;
  comparisonErrors: number;
};

export type ComparisonFieldResult = {
  kind: "scalar" | "array_field";
  scalarIndex: number | null;
  arrayIndex: number | null;
  fieldIndex: number | null;
  statistics: FieldStatistics;
};

export type ArrayStatistics = {
  arrayIndex: number;
  expected: number;
  actual: number | null;
  matched: number;
  missing: number;
  extra: number;
  comparisonErrors: number;
};

export type ComparisonWarning = {
  code:
    | "missed"
    | "fabricated"
    | "wrong"
    | "missing_item"
    | "extra_item"
    | "comparison_error"
    | "sanitizer_hard_gate";
  kind: "scalar" | "array" | "array_field" | "sanitizer";
  scalarIndex: number | null;
  arrayIndex: number | null;
  fieldIndex: number | null;
  count: number;
};

export type ComparisonResultCore = {
  comparisonVersion: typeof COMPARISON_VERSION;
  scoringRevisionVersion: typeof SCORING_REVISION_VERSION;
  scoringRevision: string;
  identity: {
    attemptId: string;
    artifactIdentityVersion: number;
    artifactId: string;
    runId: string;
    suite?: AttemptManifest["suite"];
    caseInputIdentityDigest: string;
    executionBundleDigest: string;
    scoringBundleDigest: string;
    providerInputs: AttemptManifest["inputs"];
    documentDigest: string;
    rescored: boolean;
    rescoreReason: string | null;
    sanitizer: null | {
      id: string | null;
      protocolVersion: 1 | null;
      policyBindingDigest: string | null;
      findings: Array<{
        code: string;
        severity: string;
        classification: string;
        hardGate: boolean;
        path: string | null;
      }>;
    };
  };
  fields: ComparisonFieldResult[];
  arrays: ArrayStatistics[];
  summary: {
    fields: FieldStatistics;
    arrays: {
      expected: number;
      actual: number | null;
      matched: number;
      missing: number;
      extra: number;
      comparisonErrors: number;
    };
    outcomes: {
      missed: number;
      fabricated: number;
      wrong: number;
      missingItem: number;
      extraItem: number;
      comparisonError: number;
    };
    hardGate: {
      passed: boolean;
      criticalFailures: number;
      sanitizerFailures: number;
    };
  };
  warnings: ComparisonWarning[];
};

export type ComparisonResult = ComparisonResultCore & {
  resultDigest: string;
};

type ComparisonPolicy = {
  scalars: string[];
  arrays: Array<{ path: string; key: string; fields: string[] }>;
  critical: string[];
  normalization: { strings: string[]; numbers: "exact" };
};

type MutableOutcomeSummary = ComparisonResultCore["summary"]["outcomes"];

type MutableState = {
  fields: ComparisonFieldResult[];
  arrays: ArrayStatistics[];
  outcomes: MutableOutcomeSummary;
  criticalFailures: number;
};

export async function compareAttempt(options: CompareAttemptOptions): Promise<ComparisonResult> {
  if (
    options.mode !== undefined &&
    options.mode !== "normal" &&
    options.mode !== "rescore"
  ) {
    throw new ComparisonError(
      "comparison_configuration_invalid",
      "comparison mode is invalid",
    );
  }
  const mode = options.mode ?? "normal";
  const rescoreReason = normalizeRescoreReason(mode, options.rescoreReason);
  const [bundle, attempt] = await Promise.all([
    loadBundleForComparison(options.bundleDirectory, options.contractSchemaPath),
    readAttempt(options.attemptDirectory, {
      ...(options.requirementVerifier === undefined
        ? {}
        : { requirementVerifier: options.requirementVerifier }),
    }),
  ]);
  assertComparisonIdentity(bundle, attempt, mode);
  const truth = bundle.inputs.truth?.value;
  if (truth === undefined) {
    throw new ComparisonError("comparison_truth_missing", "comparison truth is required");
  }
  const policy = parsePolicy(bundle.comparison);
  const state: MutableState = {
    fields: [],
    arrays: [],
    outcomes: {
      missed: 0,
      fabricated: 0,
      wrong: 0,
      missingItem: 0,
      extraItem: 0,
      comparisonError: 0,
    },
    criticalFailures: 0,
  };

  compareScalars(truth, attempt.document, policy, state);
  compareArrays(truth, attempt.document, policy, state);
  const fieldSummary = sumFieldStatistics(state.fields.map((field) => field.statistics));
  const arraySummary = sumArrayStatistics(state.arrays);
  const sanitizerFindings = attempt.manifest.sanitizer?.findings ?? [];
  const sanitizerFailures = sanitizerFindings.filter((finding) => finding.hardGate).length;
  const scoringRevision = computeScoringRevision(bundle.manifestDigest);
  const core: ComparisonResultCore = {
    comparisonVersion: COMPARISON_VERSION,
    scoringRevisionVersion: SCORING_REVISION_VERSION,
    scoringRevision,
    identity: {
      attemptId: attempt.manifest.attemptId,
      artifactIdentityVersion: attempt.manifest.artifactIdentityVersion,
      artifactId: attempt.manifest.artifactId,
      runId: attempt.manifest.runId,
      ...(attempt.manifest.suite === undefined ? {} : { suite: { ...attempt.manifest.suite } }),
      caseInputIdentityDigest: attempt.manifest.caseInputIdentity.digest,
      executionBundleDigest: attempt.manifest.bundleManifestDigest,
      scoringBundleDigest: bundle.manifestDigest,
      providerInputs: attempt.manifest.inputs,
      documentDigest: attempt.manifest.document.sha256,
      rescored: mode === "rescore",
      rescoreReason,
      sanitizer:
        attempt.manifest.sanitizer === undefined
          ? null
          : {
              id: attempt.manifest.sanitizer.id,
              protocolVersion: attempt.manifest.sanitizer.protocolVersion,
              policyBindingDigest: attempt.manifest.sanitizer.policyBindingDigest,
              findings: attempt.manifest.sanitizer.findings.map((finding) => ({
                code: finding.code,
                severity: finding.severity,
                classification: finding.classification,
                hardGate: finding.hardGate,
                path: finding.path ?? null,
              })),
            },
    },
    fields: state.fields,
    arrays: state.arrays,
    summary: {
      fields: fieldSummary,
      arrays: arraySummary,
      outcomes: state.outcomes,
      hardGate: {
        passed: state.criticalFailures === 0 && sanitizerFailures === 0,
        criticalFailures: state.criticalFailures,
        sanitizerFailures,
      },
    },
    warnings: buildWarnings(state.fields, state.arrays, sanitizerFailures),
  };
  return {
    ...core,
    resultDigest: computeComparisonResultDigest(core),
  };
}

export function computeScoringRevision(scoringBundleDigest: string): string {
  if (!/^[a-f0-9]{64}$/u.test(scoringBundleDigest)) {
    throw new ComparisonError(
      "comparison_configuration_invalid",
      "scoring bundle identity is invalid",
    );
  }
  return hashIdentity("svbench-scoring-revision-v1", [scoringBundleDigest]);
}

export function computeComparisonResultDigest(result: ComparisonResultCore): string {
  return hashIdentity("svbench-comparison-result-v1", [canonicalJson(result)]);
}

export function renderComparisonMarkdown(result: ComparisonResult): string {
  const lines = [
    "# Single-case comparison",
    "",
    `- Hard gate: ${result.summary.hardGate.passed ? "PASS" : "FAIL"}`,
    `- Scoring mode: ${result.identity.rescored ? "explicit rescore" : "execution bundle"}`,
    `- Field matched/total: ${result.summary.fields.matched}/${result.summary.fields.total}`,
    `- Membership matched/expected: ${result.summary.arrays.matched}/${result.summary.arrays.expected}`,
    "",
    "## Outcomes",
    "",
    "| Outcome | Count |",
    "| --- | ---: |",
    `| missed | ${result.summary.outcomes.missed} |`,
    `| fabricated | ${result.summary.outcomes.fabricated} |`,
    `| wrong | ${result.summary.outcomes.wrong} |`,
    `| missing_item | ${result.summary.outcomes.missingItem} |`,
    `| extra_item | ${result.summary.outcomes.extraItem} |`,
    `| comparison_error | ${result.summary.outcomes.comparisonError} |`,
    "",
    "## Hard gates",
    "",
    "| Source | Failures |",
    "| --- | ---: |",
    `| critical comparison | ${result.summary.hardGate.criticalFailures} |`,
    `| sanitizer finding | ${result.summary.hardGate.sanitizerFailures} |`,
    "",
    "## Warnings",
    "",
  ];
  if (result.warnings.length === 0) {
    lines.push("None.");
  } else {
    lines.push("| Code | Location | Count |", "| --- | --- | ---: |");
    for (const warning of result.warnings) {
      lines.push(
        `| ${warning.code} | ${formatWarningLocation(warning)} | ${warning.count} |`,
      );
    }
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function normalizeRescoreReason(
  mode: "normal" | "rescore",
  reason: string | undefined,
): string | null {
  if (mode === "normal") {
    if (reason !== undefined) {
      throw new ComparisonError(
        "comparison_configuration_invalid",
        "a rescore reason requires explicit rescore mode",
      );
    }
    return null;
  }
  if (typeof reason !== "string" || !/^[A-Za-z0-9._-]{1,64}$/u.test(reason)) {
    throw new ComparisonError(
      "comparison_configuration_invalid",
      "explicit rescore mode requires a safe reason code",
    );
  }
  return reason;
}

function assertComparisonIdentity(
  bundle: LoadedBundleForComparison,
  attempt: AttemptReadResult,
  mode: "normal" | "rescore",
): void {
  const manifest = attempt.manifest;
  const commonMatches =
    manifest.bundleVersion === bundle.bundleVersion &&
    manifest.caseId === bundle.caseId &&
    manifest.documentKind === bundle.documentKind &&
    manifest.provenance.promptVersion === bundle.metadata.promptVersion &&
    manifest.provenance.preprocessVersion === bundle.metadata.preprocessVersion &&
    manifest.provenance.sourceCommit === bundle.metadata.sourceCommit &&
    inputsMatch(manifest.inputs, bundle.inputs);
  const bundleMatches = manifest.bundleManifestDigest === bundle.manifestDigest;
  if (!commonMatches || (mode === "normal" && !bundleMatches)) {
    throw new ComparisonError(
      "comparison_bundle_identity_mismatch",
      mode === "normal"
        ? "attempt does not match the execution bundle"
        : "attempt is not eligible for explicit rescoring",
    );
  }
}

function inputsMatch(
  attemptInputs: AttemptManifest["inputs"],
  bundleInputs: LoadedBundleForComparison["inputs"],
): boolean {
  for (const key of ["image", "schema", "system", "instruction"] as const) {
    if (
      attemptInputs[key].sha256 !== bundleInputs[key].sha256 ||
      attemptInputs[key].mediaType !== bundleInputs[key].mediaType
    ) {
      return false;
    }
  }
  return true;
}

function parsePolicy(value: JsonValue): ComparisonPolicy {
  if (!isJsonObject(value)) {
    throw new ComparisonError("comparison_configuration_invalid", "comparison policy is invalid");
  }
  return value as unknown as ComparisonPolicy;
}

function compareScalars(
  truth: JsonValue,
  actual: JsonValue,
  policy: ComparisonPolicy,
  state: MutableState,
): void {
  const critical = new Set(policy.critical);
  for (const [scalarIndex, pointer] of policy.scalars.entries()) {
    const statistics = emptyFieldStatistics();
    const truthValue = resolvePointer(truth, decodePointerSegments(pointer));
    const actualValue = resolvePointer(actual, decodePointerSegments(pointer));
    if (truthValue === JSON_POINTER_NOT_FOUND) {
      throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
    }
    recordComparedValue(
      truthValue,
      actualValue,
      policy.normalization.strings,
      statistics,
      state,
      critical.has(pointer),
    );
    state.fields.push({
      kind: "scalar",
      scalarIndex,
      arrayIndex: null,
      fieldIndex: null,
      statistics,
    });
  }
}

function compareArrays(
  truth: JsonValue,
  actual: JsonValue,
  policy: ComparisonPolicy,
  state: MutableState,
): void {
  const critical = new Set(policy.critical);
  for (const [arrayIndex, declaration] of policy.arrays.entries()) {
    const truthValue = resolvePointer(truth, decodePointerSegments(declaration.path));
    if (!Array.isArray(truthValue)) {
      throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
    }
    const actualValue = resolvePointer(actual, decodePointerSegments(declaration.path));
    const membershipCritical = critical.has(`${declaration.path}/*${declaration.key}`);
    const arrayStatistics: ArrayStatistics = {
      arrayIndex,
      expected: truthValue.length,
      actual: Array.isArray(actualValue) ? actualValue.length : null,
      matched: 0,
      missing: 0,
      extra: 0,
      comparisonErrors: 0,
    };
    const fieldResults = declaration.fields.map((_, fieldIndex) => ({
      kind: "array_field" as const,
      scalarIndex: null,
      arrayIndex,
      fieldIndex,
      statistics: emptyFieldStatistics(),
    }));
    state.fields.push(...fieldResults);
    state.arrays.push(arrayStatistics);

    if (!Array.isArray(actualValue)) {
      recordArrayError(arrayStatistics, state, membershipCritical);
      continue;
    }
    const truthEntries = collectKeyedElements(
      truthValue,
      declaration.key,
      policy.normalization.strings,
      false,
      arrayStatistics,
      state,
      membershipCritical,
    );
    const actualEntries = collectKeyedElements(
      actualValue,
      declaration.key,
      policy.normalization.strings,
      true,
      arrayStatistics,
      state,
      membershipCritical,
    );

    for (const [key, truthElement] of truthEntries) {
      const actualElement = actualEntries.get(key);
      if (actualElement === undefined) {
        arrayStatistics.missing += 1;
        state.outcomes.missingItem += 1;
        if (membershipCritical) state.criticalFailures += 1;
        for (const [fieldIndex, fieldPointer] of declaration.fields.entries()) {
          const truthField = resolvePointer(truthElement, decodePointerSegments(fieldPointer));
          if (truthField === JSON_POINTER_NOT_FOUND) {
            throw new ComparisonError(
              "comparison_configuration_invalid",
              "validated truth is incomplete",
            );
          }
          recordMissingItemField(truthField, fieldResults[fieldIndex]!.statistics, state);
        }
        continue;
      }
      arrayStatistics.matched += 1;
      actualEntries.delete(key);
      for (const [fieldIndex, fieldPointer] of declaration.fields.entries()) {
        const truthField = resolvePointer(truthElement, decodePointerSegments(fieldPointer));
        if (truthField === JSON_POINTER_NOT_FOUND) {
          throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
        }
        const actualField = resolvePointer(actualElement, decodePointerSegments(fieldPointer));
        recordComparedValue(
          truthField,
          actualField,
          policy.normalization.strings,
          fieldResults[fieldIndex]!.statistics,
          state,
          critical.has(`${declaration.path}/*${fieldPointer}`),
        );
      }
    }

    for (const actualElement of actualEntries.values()) {
      arrayStatistics.extra += 1;
      state.outcomes.extraItem += 1;
      if (membershipCritical) state.criticalFailures += 1;
      for (const [fieldIndex, fieldPointer] of declaration.fields.entries()) {
        const actualField = resolvePointer(actualElement, decodePointerSegments(fieldPointer));
        recordExtraItemField(actualField, fieldResults[fieldIndex]!.statistics, state);
      }
    }
  }
}

function collectKeyedElements(
  elements: JsonValue[],
  keyPointer: string,
  normalization: string[],
  untrusted: boolean,
  arrayStatistics: ArrayStatistics,
  state: MutableState,
  membershipCritical: boolean,
): Map<string, Record<string, JsonValue>> {
  const candidates = new Map<string, Array<Record<string, JsonValue>>>();
  for (const element of elements) {
    if (!isJsonObject(element)) {
      if (!untrusted) {
        throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
      }
      recordArrayError(arrayStatistics, state, membershipCritical);
      continue;
    }
    const key = resolvePointer(element, decodePointerSegments(keyPointer));
    const encoded = encodeComparisonKey(key, normalization);
    if (encoded === undefined) {
      if (!untrusted) {
        throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
      }
      recordArrayError(arrayStatistics, state, membershipCritical);
      continue;
    }
    const group = candidates.get(encoded) ?? [];
    group.push(element);
    candidates.set(encoded, group);
  }
  const unique = new Map<string, Record<string, JsonValue>>();
  for (const [key, group] of candidates) {
    if (group.length !== 1) {
      if (!untrusted) {
        throw new ComparisonError("comparison_configuration_invalid", "validated truth is incomplete");
      }
      for (const _element of group) recordArrayError(arrayStatistics, state, membershipCritical);
      continue;
    }
    unique.set(key, group[0]!);
  }
  return unique;
}

function encodeComparisonKey(value: JsonValue | typeof JSON_POINTER_NOT_FOUND, ops: string[]): string | undefined {
  if (typeof value === "string") {
    const normalized = normalizeKeyForComparison(value, ops);
    return normalized.length === 0 ? undefined : `s:${normalized}`;
  }
  if (typeof value === "number") return `n:${value}`;
  return undefined;
}

function recordComparedValue(
  truth: JsonValue,
  actual: JsonValue | typeof JSON_POINTER_NOT_FOUND,
  normalization: string[],
  statistics: FieldStatistics,
  state: MutableState,
  critical: boolean,
): void {
  if (actual === JSON_POINTER_NOT_FOUND || (actual !== null && typeof actual === "object")) {
    statistics.comparisonErrors += 1;
    state.outcomes.comparisonError += 1;
    if (critical) state.criticalFailures += 1;
    return;
  }
  if (truth === null && actual === null) return;
  statistics.total += 1;
  if (truth === null) {
    statistics.fabricated += 1;
    state.outcomes.fabricated += 1;
    if (critical) state.criticalFailures += 1;
    return;
  }
  if (actual === null) {
    statistics.missed += 1;
    state.outcomes.missed += 1;
    if (critical) state.criticalFailures += 1;
    return;
  }
  if (valuesEqual(truth, actual, normalization)) {
    statistics.matched += 1;
    return;
  }
  statistics.wrong += 1;
  state.outcomes.wrong += 1;
  if (critical) state.criticalFailures += 1;
}

function recordMissingItemField(
  truth: JsonValue,
  statistics: FieldStatistics,
  state: MutableState,
): void {
  if (truth === null) return;
  statistics.total += 1;
  statistics.missed += 1;
  state.outcomes.missed += 1;
}

function recordExtraItemField(
  actual: JsonValue | typeof JSON_POINTER_NOT_FOUND,
  statistics: FieldStatistics,
  state: MutableState,
): void {
  if (actual === JSON_POINTER_NOT_FOUND || (actual !== null && typeof actual === "object")) {
    statistics.comparisonErrors += 1;
    state.outcomes.comparisonError += 1;
    return;
  }
  if (actual === null) return;
  statistics.total += 1;
  statistics.fabricated += 1;
  state.outcomes.fabricated += 1;
}

function recordArrayError(
  statistics: ArrayStatistics,
  state: MutableState,
  membershipCritical: boolean,
): void {
  statistics.comparisonErrors += 1;
  state.outcomes.comparisonError += 1;
  if (membershipCritical) state.criticalFailures += 1;
}

function valuesEqual(truth: JsonValue, actual: JsonValue, normalization: string[]): boolean {
  if (typeof truth === "string" && typeof actual === "string") {
    return (
      normalizeKeyForComparison(truth, normalization) ===
      normalizeKeyForComparison(actual, normalization)
    );
  }
  return typeof truth === typeof actual && truth === actual;
}

function emptyFieldStatistics(): FieldStatistics {
  return { total: 0, matched: 0, missed: 0, fabricated: 0, wrong: 0, comparisonErrors: 0 };
}

function sumFieldStatistics(values: FieldStatistics[]): FieldStatistics {
  const result = emptyFieldStatistics();
  for (const value of values) {
    result.total += value.total;
    result.matched += value.matched;
    result.missed += value.missed;
    result.fabricated += value.fabricated;
    result.wrong += value.wrong;
    result.comparisonErrors += value.comparisonErrors;
  }
  return result;
}

function sumArrayStatistics(values: ArrayStatistics[]): ComparisonResultCore["summary"]["arrays"] {
  const result = {
    expected: 0,
    actual: 0 as number | null,
    matched: 0,
    missing: 0,
    extra: 0,
    comparisonErrors: 0,
  };
  for (const value of values) {
    result.expected += value.expected;
    result.actual =
      result.actual === null || value.actual === null ? null : result.actual + value.actual;
    result.matched += value.matched;
    result.missing += value.missing;
    result.extra += value.extra;
    result.comparisonErrors += value.comparisonErrors;
  }
  return result;
}

function buildWarnings(
  fields: ComparisonFieldResult[],
  arrays: ArrayStatistics[],
  sanitizerFailures: number,
): ComparisonWarning[] {
  const warnings: ComparisonWarning[] = [];
  for (const field of fields) {
    for (const code of ["missed", "fabricated", "wrong"] as const) {
      if (field.statistics[code] > 0) {
        warnings.push({
          code,
          kind: field.kind,
          scalarIndex: field.scalarIndex,
          arrayIndex: field.arrayIndex,
          fieldIndex: field.fieldIndex,
          count: field.statistics[code],
        });
      }
    }
    if (field.statistics.comparisonErrors > 0) {
      warnings.push({
        code: "comparison_error",
        kind: field.kind,
        scalarIndex: field.scalarIndex,
        arrayIndex: field.arrayIndex,
        fieldIndex: field.fieldIndex,
        count: field.statistics.comparisonErrors,
      });
    }
  }
  for (const array of arrays) {
    for (const [code, count] of [
      ["missing_item", array.missing],
      ["extra_item", array.extra],
      ["comparison_error", array.comparisonErrors],
    ] as const) {
      if (count > 0) {
        warnings.push({
          code,
          kind: "array",
          scalarIndex: null,
          arrayIndex: array.arrayIndex,
          fieldIndex: null,
          count,
        });
      }
    }
  }
  if (sanitizerFailures > 0) {
    warnings.push({
      code: "sanitizer_hard_gate",
      kind: "sanitizer",
      scalarIndex: null,
      arrayIndex: null,
      fieldIndex: null,
      count: sanitizerFailures,
    });
  }
  return warnings;
}

function formatWarningLocation(warning: ComparisonWarning): string {
  if (warning.kind === "scalar") return `scalar ${warning.scalarIndex}`;
  if (warning.kind === "array") return `array ${warning.arrayIndex}`;
  if (warning.kind === "array_field") {
    return `array ${warning.arrayIndex}, field ${warning.fieldIndex}`;
  }
  return "sanitizer";
}

function hashIdentity(domain: string, values: string[]): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(domain, "ascii"));
  for (const value of values) {
    const bytes = Buffer.from(value, "utf8");
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(bytes.length, 0);
    hash.update(prefix);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}
