import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

import { parseJson, type JsonValue } from "../src/bundle/json.js";
import { validateJsonSchema } from "../src/bundle/schema-validator.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  computeSanitizerFindingPathAllowlistDigest,
  createSanitizerRequirementDecision,
  type SanitizerRequirementVerifier,
} from "../src/runner/identity.js";
import {
  computeCasePolicyMapDigest,
  computeSuitePlanDigest,
  deriveSuiteAttemptKey,
  type SuiteCasePlan,
  type SuitePreflightPlan,
} from "../src/suite/preflight.js";
import {
  MAX_SUITE_RUN_MANIFEST_BYTES,
  SuiteRunManifestError,
  computeSuiteRunIdentity,
  createSuiteRunManifest,
  encodeSuiteRunManifest,
  readSuiteRunManifest,
  type SuiteRunManifest,
} from "../src/suite/run-manifest.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const DIGEST_D = "d".repeat(64);
const PRIVATE_IMAGE_DIGEST_A = "1".repeat(64);
const PRIVATE_IMAGE_DIGEST_B = "2".repeat(64);

test("builds deterministic value-free suite run bytes and validates the schema", async () => {
  const plan = syntheticPlan();
  const first = createSuiteRunManifest(plan);
  const second = createSuiteRunManifest(structuredClone(plan));
  const firstBytes = encodeSuiteRunManifest(first);
  const secondBytes = encodeSuiteRunManifest(second);

  assert.deepEqual(second, first);
  assert.deepEqual(secondBytes, firstBytes);
  assert.equal(first.suiteRunId, "2b16533842fe5a7a56b78c32dd61dac28fc4840646a5c750b5b61e0bf5cba2b7");
  assert.deepEqual(
    first.slots.map(({ runId, attemptId }) => ({ runId, attemptId })),
    [
      {
        runId: "507e4b2d9343d3c8c16d72d05d13f3f74e883dc1562a7b019df4269bbb2d9b9a",
        attemptId: "b2116be2b819a98426c26aa45263318b8500dddc6dd38f612d81929bb6e672b3",
      },
      {
        runId: "507e4b2d9343d3c8c16d72d05d13f3f74e883dc1562a7b019df4269bbb2d9b9a",
        attemptId: "ea21c3a8668ceef3ca26320c9e8d92cf09121b2809d7677b826748b1a4ff8a59",
      },
      {
        runId: "6f8576ac3249f8936316cf2b010ba3c522aae6417959910d67f2a6adbe69d745",
        attemptId: "4639844bfd88268d2d9139f9307d059a53bd8e7d91b80396d77ed43e37101910",
      },
      {
        runId: "6f8576ac3249f8936316cf2b010ba3c522aae6417959910d67f2a6adbe69d745",
        attemptId: "0f29ee02ea2a2aadc06b07119db04cf1abb0bd006ae75bd3d9356cd38792a97d",
      },
    ],
  );
  assert.equal(computeSuiteRunIdentity(first), first.suiteRunId);
  assert.deepEqual(readSuiteRunManifest(firstBytes), first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.provider.requested), true);
  assert.equal(Object.isFrozen(first.cases[0]!.sanitizerRequirement), true);
  assert.equal(Object.isFrozen(first.slots), true);
  assert.equal(Object.isFrozen(first.slots[0]), true);

  const schema = parseJson(
    await readFile("schemas/suite-run-v1.schema.json", "utf8"),
    "suite run schema",
  );
  assert.deepEqual(validateJsonSchema(schema, first as unknown as JsonValue), []);

  const source = firstBytes.toString("utf8");
  for (const marker of [
    "synthetic-private-case-a",
    "synthetic-private-kind",
    "SYNTHETIC_PRIVATE_BUNDLE_A",
    "SYNTHETIC_PRIVATE_POLICY",
    "/SYNTHETIC_PRIVATE_APPROVAL",
    "/SYNTHETIC_PRIVATE_SANITIZER",
    "SYNTHETIC_PRIVATE_ARG",
    PRIVATE_IMAGE_DIGEST_A,
    PRIVATE_IMAGE_DIGEST_B,
  ]) {
    assert.equal(source.includes(marker), false);
  }
});

test("represents an approval-free policy-free suite without placeholder identities", () => {
  const plan = structuredClone(syntheticPlan()) as Mutable<SuitePreflightPlan>;
  const verifier: SanitizerRequirementVerifier = {
    id: plan.requirementVerifier.id,
    version: plan.requirementVerifier.version,
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: plan.requirementVerifier.consumerSourceCommit,
    }),
  };
  const notRequired = createSanitizerRequirementDecision(
    {
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: plan.requirementVerifier.consumerSourceCommit,
    },
    verifier,
  );
  for (const entry of plan.cases) {
    entry.sanitizerRequirement = structuredClone(notRequired);
    delete entry.policy;
  }
  delete plan.approval;
  delete plan.sanitizer;
  plan.suiteDigest = "e".repeat(64);
  plan.casePolicyMapDigest = computeCasePolicyMapDigest(plan.cases);
  plan.suitePlanDigest = computeSuitePlanDigest(plan.suiteDigest, plan.casePolicyMapDigest);

  const manifest = createSuiteRunManifest(plan);
  assert.equal(manifest.approval, null);
  assert.equal(manifest.sanitizer, null);
  assert.equal(manifest.cases.every((entry) => entry.policy === null), true);
  assert.deepEqual(readSuiteRunManifest(encodeSuiteRunManifest(manifest)), manifest);
});

test("fixes case run identities and separates repeat attempt identities", () => {
  const manifest = createSuiteRunManifest(syntheticPlan());
  assert.equal(manifest.slots.length, 4);
  assert.equal(manifest.slots[0]!.runId, manifest.slots[1]!.runId);
  assert.notEqual(manifest.slots[0]!.attemptId, manifest.slots[1]!.attemptId);
  assert.notEqual(manifest.slots[0]!.runId, manifest.slots[2]!.runId);
  assert.equal(manifest.slots[0]!.attemptKey, "c0-r0");
  assert.equal(manifest.slots[1]!.attemptKey, "c0-r1");
  assert.equal(manifest.slots[2]!.attemptKey, "c1-r0");
  assert.equal(manifest.slots[3]!.attemptKey, "c1-r1");
  assert.equal(manifest.cases[0]!.policy, null);
  assert.notEqual(manifest.cases[1]!.policy, null);
});

test("rejects immutable field, derived slot, and outer identity tampering", () => {
  const manifest = createSuiteRunManifest(syntheticPlan());

  const providerTamper = cloneManifest(manifest);
  providerTamper.provider.id = "synthetic-provider-changed";
  expectManifestError(providerTamper, "suite_run_manifest_invalid");

  const bundleTamper = cloneManifest(manifest);
  bundleTamper.cases[0]!.bundleManifestDigest = DIGEST_D;
  expectManifestError(bundleTamper, "suite_run_manifest_invalid");

  const attemptTamper = cloneManifest(manifest);
  attemptTamper.slots[0]!.attemptId = DIGEST_D;
  expectManifestError(attemptTamper, "suite_run_manifest_invalid");

  const idTamper = cloneManifest(manifest);
  idTamper.suiteRunId = DIGEST_D;
  expectManifestError(idTamper, "suite_run_identity_mismatch");

  const patternOrderTamper = cloneManifest(manifest);
  patternOrderTamper.sanitizer!.allowedFindingPathPatterns = ["/z", "/a"];
  patternOrderTamper.sanitizer!.findingPathAllowlistDigest =
    computeSanitizerFindingPathAllowlistDigest(["/a", "/z"]);
  expectManifestError(patternOrderTamper, "suite_run_manifest_invalid");
});

test("supports an external suite run identity anchor for coordinated replacement", () => {
  const original = createSuiteRunManifest(syntheticPlan());
  const changedPlan = structuredClone(syntheticPlan()) as Mutable<SuitePreflightPlan>;
  changedPlan.provider = {
    ...changedPlan.provider,
    id: "synthetic-provider-changed",
  };
  const changed = createSuiteRunManifest(changedPlan);
  assert.notEqual(changed.suiteRunId, original.suiteRunId);
  assert.deepEqual(readSuiteRunManifest(encodeSuiteRunManifest(changed)), changed);
  assert.throws(
    () =>
      readSuiteRunManifest(encodeSuiteRunManifest(changed), {
        expectedSuiteRunId: original.suiteRunId,
      }),
    isManifestError("suite_run_identity_mismatch"),
  );
});

test("strict reader rejects malformed, duplicate, unknown, and oversized bytes", () => {
  const manifest = createSuiteRunManifest(syntheticPlan());
  const bytes = encodeSuiteRunManifest(manifest);
  const source = bytes.toString("utf8");

  assert.throws(() => readSuiteRunManifest(Buffer.alloc(0)), isManifestError("suite_run_manifest_invalid"));
  assert.throws(
    () => readSuiteRunManifest(Buffer.from([0xff])),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.throws(
    () => readSuiteRunManifest(Buffer.from([0xef, 0xbb, 0xbf, ...bytes])),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.throws(
    () => readSuiteRunManifest(Buffer.from(source.slice(0, -4), "utf8")),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.throws(
    () => readSuiteRunManifest(Buffer.concat([bytes, bytes])),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.throws(
    () =>
      readSuiteRunManifest(
        Buffer.from(source.replace('{"suiteRunManifestVersion":1', '{"suiteRunManifestVersion":1,"suiteRunManifestVersion":1'), "utf8"),
      ),
    isManifestError("suite_run_manifest_invalid"),
  );

  const unknown = cloneManifest(manifest) as unknown as Record<string, unknown>;
  unknown.syntheticUnknown = true;
  assert.throws(
    () => readSuiteRunManifest(Buffer.from(JSON.stringify(unknown), "utf8")),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.throws(
    () => readSuiteRunManifest(Buffer.alloc(MAX_SUITE_RUN_MANIFEST_BYTES + 1, 0x20)),
    isManifestError("suite_run_manifest_invalid"),
  );

  const disguisedOversize = new Uint8Array(MAX_SUITE_RUN_MANIFEST_BYTES + 1);
  Object.defineProperty(disguisedOversize, "byteLength", { value: 1 });
  assert.throws(
    () => readSuiteRunManifest(disguisedOversize),
    isManifestError("suite_run_manifest_invalid"),
  );

  const crossRealmSharedView = runInNewContext(
    "new Uint8Array(new SharedArrayBuffer(16))",
  ) as Uint8Array;
  Object.setPrototypeOf(crossRealmSharedView, Uint8Array.prototype);
  assert.equal(crossRealmSharedView instanceof Uint8Array, true);
  assert.throws(
    () => readSuiteRunManifest(crossRealmSharedView),
    isManifestError("suite_run_manifest_invalid"),
  );
});

test("builder rejects accessors without executing private values", () => {
  const plan = syntheticPlan() as SuitePreflightPlan & Record<string, unknown>;
  let reads = 0;
  Object.defineProperty(plan.provider, "id", {
    enumerable: true,
    get() {
      reads += 1;
      return "SYNTHETIC_PRIVATE_PROVIDER";
    },
  });
  assert.throws(() => createSuiteRunManifest(plan), isManifestError("suite_run_manifest_invalid"));
  assert.equal(reads, 0);
  assert.equal(JSON.stringify(captureError(() => createSuiteRunManifest(plan))).includes("SYNTHETIC_PRIVATE"), false);

  const manifest = createSuiteRunManifest(syntheticPlan());
  const bytes = encodeSuiteRunManifest(manifest);
  let optionReads = 0;
  const options = Object.defineProperty({}, "expectedSuiteRunId", {
    enumerable: true,
    get() {
      optionReads += 1;
      return "SYNTHETIC_PRIVATE_EXPECTED_ID";
    },
  });
  assert.throws(
    () => readSuiteRunManifest(bytes, options),
    isManifestError("suite_run_manifest_invalid"),
  );
  assert.equal(optionReads, 0);

  const marker = "SYNTHETIC_PRIVATE_ENCODER_PATH";
  const hostileManifest = new Proxy(manifest, {
    ownKeys() {
      throw new Error(marker);
    },
  });
  const encoderError = captureError(() => encodeSuiteRunManifest(hostileManifest));
  assert.equal(encoderError instanceof SuiteRunManifestError, true);
  assert.equal(JSON.stringify(encoderError).includes(marker), false);

  const hidden = syntheticPlan() as SuitePreflightPlan & Record<string, unknown>;
  Object.defineProperty(hidden, "syntheticHidden", {
    enumerable: false,
    value: "SYNTHETIC_PRIVATE_HIDDEN",
  });
  assert.throws(
    () => createSuiteRunManifest(hidden),
    isManifestError("suite_run_manifest_invalid"),
  );
});

test("rejects a self-consistent approval phase mismatch", () => {
  const plan = structuredClone(syntheticPlan()) as Mutable<SuitePreflightPlan>;
  plan.approval!.phase = "synthetic-other-phase";
  assert.throws(
    () => createSuiteRunManifest(plan),
    isManifestError("suite_run_manifest_invalid"),
  );

  const manifest = cloneManifest(createSuiteRunManifest(syntheticPlan()));
  manifest.approval!.phase = "synthetic-other-phase";
  expectManifestError(manifest, "suite_run_manifest_invalid");
});

function syntheticPlan(): SuitePreflightPlan {
  const verifier: SanitizerRequirementVerifier = {
    id: "synthetic-verifier",
    version: "v1",
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: "synthetic-commit",
    }),
  };
  const firstIdentity = computeCaseInputIdentity({
    caseId: "synthetic-private-case-a",
    documentKind: "synthetic-private-kind",
    preparedImage: { mediaType: "image/png", sha256: PRIVATE_IMAGE_DIGEST_A },
  });
  const secondIdentity = computeCaseInputIdentity({
    caseId: "synthetic-private-case-b",
    documentKind: "synthetic-private-kind",
    preparedImage: { mediaType: "image/png", sha256: PRIVATE_IMAGE_DIGEST_B },
  });
  const firstRequirement = createSanitizerRequirementDecision(
    {
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: "synthetic-commit",
    },
    verifier,
  );
  const secondRequirement = createSanitizerRequirementDecision(
    {
      sanitizerRequired: true,
      policyRequired: true,
      sanitizerRequirementReason: "synthetic-required",
      consumerSourceCommit: "synthetic-commit",
    },
    verifier,
  );
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: secondIdentity.digest,
    policyVersion: 1,
    policyDigest: DIGEST_C,
  });
  const cases: SuiteCasePlan[] = [
    {
      caseIndex: 0,
      bundlePath: "SYNTHETIC_PRIVATE_BUNDLE_A",
      bundleManifestDigest: DIGEST_B,
      caseInputIdentity: firstIdentity,
      sanitizerRequirement: firstRequirement,
    },
    {
      caseIndex: 1,
      bundlePath: "SYNTHETIC_PRIVATE_BUNDLE_B",
      bundleManifestDigest: DIGEST_C,
      caseInputIdentity: secondIdentity,
      sanitizerRequirement: secondRequirement,
      policy: {
        path: "SYNTHETIC_PRIVATE_POLICY",
        policyVersion: 1,
        policyDigest: DIGEST_C,
        policyTargetIdentityDigest: secondIdentity.digest,
        policyBindingDigest,
      },
    },
  ];
  const casePolicyMapDigest = computeCasePolicyMapDigest(cases);
  const suiteDigest = DIGEST_D;
  const repeat = 2;
  return {
    suiteVersion: 1,
    suiteId: "synthetic-suite",
    suiteDigest,
    suitePlanDigest: computeSuitePlanDigest(suiteDigest, casePolicyMapDigest),
    casePolicyMapDigest,
    provider: {
      id: "synthetic-provider",
      route: "synthetic-route",
      implementationVersion: "v1",
      protocolVersion: "v1",
      requested: { model: "synthetic-model", effort: "medium", maxTokens: 512 },
    },
    phase: "synthetic-phase",
    repeat,
    requirementVerifier: {
      id: verifier.id,
      version: verifier.version,
      consumerSourceCommit: "synthetic-commit",
    },
    approval: {
      required: true,
      command: {
        executable: "/SYNTHETIC_PRIVATE_APPROVAL",
        argv: ["SYNTHETIC_PRIVATE_ARG"],
        envAllowlist: [],
        timeoutMs: 1000,
        outputLimitBytes: 4096,
      },
      expectedGateId: "synthetic-gate",
      expectedProtocolVersion: 1,
      snapshotDigest: DIGEST_A,
      runtimeBindingIdentity: "synthetic-runtime",
      runtimeBindingDigest: DIGEST_B,
      approvedScopeIdentity: "synthetic-scope",
      approvedScopeDigest: DIGEST_C,
      phase: "synthetic-phase",
    },
    sanitizer: {
      command: {
        executable: "/SYNTHETIC_PRIVATE_SANITIZER",
        argv: ["SYNTHETIC_PRIVATE_ARG"],
        envAllowlist: [],
        timeoutMs: 1000,
        outputLimitBytes: 4096,
      },
      expectedSanitizerId: "synthetic-sanitizer",
      expectedProtocolVersion: 1,
      allowedFindingPathPatterns: ["/total"],
      failureCodes: ["synthetic-failure"],
    },
    cases,
    slots: cases.flatMap((_, caseIndex) =>
      Array.from({ length: repeat }, (_unused, repeatIndex) => ({
        caseIndex,
        repeatIndex,
        attemptKey: deriveSuiteAttemptKey(caseIndex, repeatIndex),
      })),
    ),
  };
}

function cloneManifest(manifest: SuiteRunManifest): MutableManifest {
  return structuredClone(manifest) as MutableManifest;
}

type MutableManifest = {
  -readonly [Key in keyof SuiteRunManifest]: Mutable<SuiteRunManifest[Key]>;
};

type Mutable<Value> = Value extends readonly (infer Entry)[]
  ? Mutable<Entry>[]
  : Value extends object
    ? { -readonly [Key in keyof Value]: Mutable<Value[Key]> }
    : Value;

function expectManifestError(
  manifest: MutableManifest,
  code: SuiteRunManifestError["code"],
): void {
  assert.throws(
    () => readSuiteRunManifest(Buffer.from(JSON.stringify(manifest), "utf8")),
    isManifestError(code),
  );
}

function isManifestError(code: SuiteRunManifestError["code"]): (error: unknown) => boolean {
  return (error: unknown) => error instanceof SuiteRunManifestError && error.code === code;
}

function captureError(operation: () => unknown): unknown {
  try {
    operation();
  } catch (error) {
    return error;
  }
  throw new Error("expected operation to throw");
}
