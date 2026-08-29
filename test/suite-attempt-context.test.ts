import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { parseJson, type JsonValue } from "../src/bundle/json.js";
import { validateJsonSchema } from "../src/bundle/schema-validator.js";
import { compareAttempt } from "../src/comparison/compare.js";
import { createMockProvider } from "../src/provider/mock.js";
import { readAttempt, type AttemptManifest } from "../src/runner/attempt.js";
import { RunnerError } from "../src/runner/errors.js";
import {
  computeArtifactIdentity,
  computeAttemptIdentity,
  computeRunIdentity,
  createSanitizerRequirementDecision,
} from "../src/runner/identity.js";
import { runBundle } from "../src/runner/run.js";
import {
  computeSuitePlanDigest,
  snapshotSuiteAttemptContext,
  type SuiteAttemptContext,
} from "../src/suite/context.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const SUITE_DIGEST = "a".repeat(64);
const CASE_POLICY_MAP_DIGEST = "b".repeat(64);
type MutableSuiteContext = {
  -readonly [Key in keyof SuiteAttemptContext]: SuiteAttemptContext[Key];
};

const REQUIREMENT_VERIFIER = {
  id: "synthetic-suite-consumer",
  version: "v1",
  derive: (_documentKind: string) => ({
    sanitizerRequired: false,
    policyRequired: false,
    sanitizerRequirementReason: "synthetic_policy_not_required",
    consumerSourceCommit: null,
  }),
} as const;

const SANITIZER_REQUIREMENT = {
  verifier: REQUIREMENT_VERIFIER,
  decision: createSanitizerRequirementDecision(
    REQUIREMENT_VERIFIER.derive("synthetic_invoice"),
    REQUIREMENT_VERIFIER,
  ),
};

function suiteContext(repeatIndex: number): SuiteAttemptContext {
  return snapshotSuiteAttemptContext({
    suiteVersion: 1,
    suiteId: "synthetic-suite",
    suiteDigest: SUITE_DIGEST,
    suitePlanDigest: computeSuitePlanDigest(SUITE_DIGEST, CASE_POLICY_MAP_DIGEST),
    casePolicyMapDigest: CASE_POLICY_MAP_DIGEST,
    caseIndex: 0,
    repeatIndex,
  });
}

test("computes a fixed suite plan and suite-bound run identity", () => {
  const context = suiteContext(0);
  const directInput = {
    caseInputIdentityDigest: "c".repeat(64),
    bundleManifestDigest: "d".repeat(64),
    phase: "development",
    providerId: "mock",
    providerRoute: "mock",
  };
  assert.equal(
    context.suitePlanDigest,
    "94c0fbc55f3961b2959f4a1e9f2bc18f2b671ede56d5269822312fd37aae3ede",
  );
  assert.equal(
    computeRunIdentity({
      ...directInput,
      suiteContext: context,
    }),
    "850d589ebe879a52447c63997ffe70384230d218417eec131bb9dbd7e5d10ce6",
  );
  assert.equal(
    computeRunIdentity({
      ...directInput,
      suiteContext: suiteContext(1),
    }),
    "850d589ebe879a52447c63997ffe70384230d218417eec131bb9dbd7e5d10ce6",
  );
  assert.equal(
    computeRunIdentity(directInput),
    "7c4266cf1e860c5b280f3a97ca35fff81123ddcfef91237e58c92247b815e6e4",
  );
  for (const changedContext of [
    snapshotSuiteAttemptContext({ ...context, suiteId: "synthetic-suite-v2" }),
    snapshotSuiteAttemptContext({ ...context, caseIndex: 1 }),
    snapshotSuiteAttemptContext({
      ...context,
      suiteDigest: "e".repeat(64),
      suitePlanDigest: computeSuitePlanDigest("e".repeat(64), context.casePolicyMapDigest),
    }),
    snapshotSuiteAttemptContext({
      ...context,
      suitePlanDigest: computeSuitePlanDigest(context.suiteDigest, "f".repeat(64)),
      casePolicyMapDigest: "f".repeat(64),
    }),
  ]) {
    assert.notEqual(
      computeRunIdentity({ ...directInput, suiteContext: changedContext }),
      computeRunIdentity({ ...directInput, suiteContext: context }),
    );
  }
});

test("persists verified suite slots while direct runs remain suite-free", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-suite-attempt-"));
  const attempts = path.join(temporary, "attempts");
  try {
    const provider = createMockProvider();
    const first = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: attempts,
      provider,
      sanitizerRequirement: SANITIZER_REQUIREMENT,
      suiteContext: suiteContext(0),
    });
    const second = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: attempts,
      provider,
      sanitizerRequirement: SANITIZER_REQUIREMENT,
      suiteContext: suiteContext(1),
    });
    const direct = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: attempts,
      provider,
      sanitizerRequirement: SANITIZER_REQUIREMENT,
    });

    assert.equal(first.runId, second.runId);
    assert.notEqual(first.attemptId, second.attemptId);
    assert.equal(first.attemptKey, "c0-r0");
    assert.equal(second.attemptKey, "c0-r1");
    assert.deepEqual((await readAttempt(first.attemptDirectory)).manifest.suite, suiteContext(0));
    assert.deepEqual((await readAttempt(second.attemptDirectory)).manifest.suite, suiteContext(1));
    const directManifest = (await readAttempt(direct.attemptDirectory)).manifest;
    assert.equal(Object.hasOwn(directManifest, "suite"), false);

    const schema = parseJson(
      await readFile(path.resolve("schemas/attempt-v1.schema.json"), "utf8"),
      "attempt schema",
    );
    const suiteManifest = JSON.parse(
      await readFile(path.join(first.artifactDirectory, "attempt.json"), "utf8"),
    ) as JsonValue;
    assert.deepEqual(
      validateJsonSchema(
        schema,
        suiteManifest,
      ),
      [],
    );
    assert.deepEqual(
      validateJsonSchema(
        schema,
        JSON.parse(
          await readFile(path.join(direct.artifactDirectory, "attempt.json"), "utf8"),
        ) as JsonValue,
      ),
      [],
    );
    const unknownMember = structuredClone(suiteManifest) as Record<string, unknown>;
    (unknownMember.suite as Record<string, unknown>).syntheticUnknown = true;
    assert.notDeepEqual(validateJsonSchema(schema, unknownMember as JsonValue), []);
    const invalidIndex = structuredClone(suiteManifest) as Record<string, unknown>;
    (invalidIndex.suite as Record<string, unknown>).caseIndex = 1000;
    assert.notDeepEqual(validateJsonSchema(schema, invalidIndex as JsonValue), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects malformed suite contexts before provider work", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-suite-attempt-"));
  let providerCalls = 0;
  try {
    const provider = createMockProvider({ onInvoke: () => { providerCalls += 1; } });
    await assert.rejects(
      runBundle({
        bundleDirectory: FIXTURE,
        attemptRoot: path.join(temporary, "attempts-a"),
        provider,
        sanitizerRequirement: SANITIZER_REQUIREMENT,
        attemptKey: "c0-r1",
        suiteContext: suiteContext(0),
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "run_configuration_invalid",
    );
    await assert.rejects(
      runBundle({
        bundleDirectory: FIXTURE,
        attemptRoot: path.join(temporary, "attempts-b"),
        provider,
        sanitizerRequirement: SANITIZER_REQUIREMENT,
        suiteContext: {
          ...suiteContext(0),
          suitePlanDigest: "f".repeat(64),
        },
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "run_configuration_invalid",
    );
    const malformed = {
      ...suiteContext(0),
      suiteId: ["synthetic-suite"],
      suiteDigest: [SUITE_DIGEST],
      suitePlanDigest: [computeSuitePlanDigest(SUITE_DIGEST, CASE_POLICY_MAP_DIGEST)],
      casePolicyMapDigest: [CASE_POLICY_MAP_DIGEST],
    } as never;
    await assert.rejects(
      runBundle({
        bundleDirectory: FIXTURE,
        attemptRoot: path.join(temporary, "attempts-c"),
        provider,
        sanitizerRequirement: SANITIZER_REQUIREMENT,
        suiteContext: malformed,
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "run_configuration_invalid",
    );
    for (const [suiteDigest, casePolicyMapDigest] of [
      [[SUITE_DIGEST], [CASE_POLICY_MAP_DIGEST]],
      [new String(SUITE_DIGEST), CASE_POLICY_MAP_DIGEST],
      [{ synthetic: SUITE_DIGEST }, CASE_POLICY_MAP_DIGEST],
    ]) {
      assert.throws(() => computeSuitePlanDigest(suiteDigest as never, casePolicyMapDigest as never));
    }
    let accessorReads = 0;
    const accessorContext = { ...suiteContext(0) };
    Object.defineProperty(accessorContext, "suiteId", {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        return "synthetic-suite";
      },
    });
    assert.throws(() => snapshotSuiteAttemptContext(accessorContext));
    assert.equal(accessorReads, 0);
    assert.equal(providerCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("reader rejects suite tampering and coordinated identity rehashing", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-suite-attempt-"));
  try {
    const result = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: path.join(temporary, "attempts"),
      provider: createMockProvider(),
      sanitizerRequirement: SANITIZER_REQUIREMENT,
      suiteContext: suiteContext(0),
    });

    const mutations: Array<(manifest: AttemptManifest) => void> = [
      (manifest) => { (manifest.suite! as MutableSuiteContext).suiteId = "synthetic-suite-changed"; },
      (manifest) => { (manifest.suite! as MutableSuiteContext).suiteDigest = "c".repeat(64); },
      (manifest) => { (manifest.suite! as MutableSuiteContext).casePolicyMapDigest = "d".repeat(64); },
      (manifest) => { (manifest.suite! as MutableSuiteContext).caseIndex = 1; },
      (manifest) => { (manifest.suite! as MutableSuiteContext).repeatIndex = 1; },
      (manifest) => { (manifest.suite! as MutableSuiteContext).suitePlanDigest = "e".repeat(64); },
      (manifest) => {
        (manifest.suite! as unknown as Record<string, unknown>).suiteId = ["synthetic-suite"];
      },
    ];
    for (const [index, mutate] of mutations.entries()) {
      const copyRoot = path.join(temporary, `tampered-${index}`);
      const copyAttempt = path.join(copyRoot, result.attemptId);
      await mkdir(copyRoot);
      await cp(result.attemptDirectory, copyAttempt, { recursive: true });
      const manifestPath = path.join(copyAttempt, result.artifactId, "attempt.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as AttemptManifest;
      mutate(manifest);
      await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`, { mode: 0o600 });
      await assert.rejects(
        readAttempt(copyAttempt),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "attempt_identity_mismatch",
      );
      if (index === mutations.length - 1) {
        await assert.rejects(
          compareAttempt({ bundleDirectory: FIXTURE, attemptDirectory: copyAttempt }),
          (error: unknown) =>
            error instanceof RunnerError && error.code === "attempt_identity_mismatch",
        );
      }
    }

    const coordinatedRoot = path.join(temporary, "coordinated");
    const coordinatedAttempt = path.join(coordinatedRoot, result.attemptId);
    await mkdir(coordinatedRoot);
    await cp(result.attemptDirectory, coordinatedAttempt, { recursive: true });
    const coordinatedManifestPath = path.join(
      coordinatedAttempt,
      result.artifactId,
      "attempt.json",
    );
    const coordinated = JSON.parse(
      await readFile(coordinatedManifestPath, "utf8"),
    ) as AttemptManifest;
    (coordinated.suite! as MutableSuiteContext).repeatIndex = 1;
    coordinated.attemptKey = "c0-r1";
    coordinated.attemptId = computeAttemptIdentity({
      runId: coordinated.runId,
      attemptKey: coordinated.attemptKey,
    }).attemptId;
    const artifactIdentity = computeArtifactIdentity({
      attemptId: coordinated.attemptId,
      documentSha256: coordinated.document.sha256,
      sanitizer: null,
    });
    coordinated.artifactIdentityVersion = artifactIdentity.artifactIdentityVersion;
    coordinated.artifactId = artifactIdentity.artifactId;
    await writeFile(coordinatedManifestPath, `${JSON.stringify(coordinated)}\n`, { mode: 0o600 });
    await assert.rejects(
      readAttempt(coordinatedAttempt),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("comparison propagates only the verified suite context", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-suite-attempt-"));
  try {
    const suiteRun = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: path.join(temporary, "suite-attempts"),
      provider: createMockProvider(),
      sanitizerRequirement: SANITIZER_REQUIREMENT,
      suiteContext: suiteContext(0),
    });
    const directRun = await runBundle({
      bundleDirectory: FIXTURE,
      attemptRoot: path.join(temporary, "direct-attempts"),
      provider: createMockProvider(),
      sanitizerRequirement: SANITIZER_REQUIREMENT,
    });
    const suiteComparison = await compareAttempt({
      bundleDirectory: FIXTURE,
      attemptDirectory: suiteRun.attemptDirectory,
    });
    const directComparison = await compareAttempt({
      bundleDirectory: FIXTURE,
      attemptDirectory: directRun.attemptDirectory,
    });
    assert.deepEqual(suiteComparison.identity.suite, suiteContext(0));
    assert.equal(Object.hasOwn(directComparison.identity, "suite"), false);

    const schema = parseJson(
      await readFile(path.resolve("schemas/comparison-v1.schema.json"), "utf8"),
      "comparison schema",
    );
    assert.deepEqual(validateJsonSchema(schema, suiteComparison as unknown as JsonValue), []);
    assert.deepEqual(validateJsonSchema(schema, directComparison as unknown as JsonValue), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
