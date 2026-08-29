import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { prepareBundleForRunner } from "../src/bundle/validate-bundle.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  createSanitizerRequirementDecision,
  type SanitizerRequirementVerifier,
} from "../src/runner/identity.js";
import { createSanitizerPolicyEnvelope } from "../src/runner/sanitizer.js";
import {
  computeCasePolicyMapDigest,
  computeSuitePlanDigest,
  deriveSuiteAttemptKey,
  preflightSuite,
  SuitePreflightError,
} from "../src/suite/preflight.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const DIGEST_D = "d".repeat(64);

type CaseEntry = {
  bundlePath: string;
  expectedBundleManifestDigest: string;
  expectedCaseInputIdentityVersion: 1;
  expectedCaseInputIdentityDigest: string;
  sanitizerRequirementVersion: 1;
  sanitizerRequired: boolean;
  policyRequired: boolean;
  sanitizerRequirementReason: string;
  requirementDecisionDigest: string;
  policy?: {
    path: string;
    expectedPolicyVersion: number;
    expectedPolicyDigest: string;
    expectedPolicyTargetIdentityDigest: string;
    expectedPolicyBindingDigest: string;
  };
};

type SuiteManifest = {
  suiteVersion: 1;
  suiteId: string;
  provider: {
    id: string;
    route: string;
    implementationVersion: string | null;
    protocolVersion: string | null;
    requested: { model: string | null; effort: string | null; maxTokens: number | null };
  };
  phase: string;
  repeat: number;
  requirementVerifier: {
    id: string;
    version: string;
    consumerSourceCommit: string | null;
  };
  approval: {
    required: boolean;
    command: CommandConfig;
    expectedGateId: string;
    expectedProtocolVersion: 1;
    snapshotDigest: string;
    runtimeBindingIdentity: string;
    runtimeBindingDigest: string;
    approvedScopeIdentity: string;
    approvedScopeDigest: string;
    phase: string;
  };
  sanitizer?: {
    command: CommandConfig;
    expectedSanitizerId: string;
    expectedProtocolVersion: 1;
    allowedFindingPathPatterns: string[];
    failureCodes: string[];
  };
  cases: CaseEntry[];
  syntheticUnknown?: string;
};

type CommandConfig = {
  executable: string;
  argv: string[];
  envAllowlist: string[];
  timeoutMs: number;
  outputLimitBytes: number;
};

type SuiteFixture = {
  root: string;
  manifest: SuiteManifest;
  verifier: SanitizerRequirementVerifier;
  write: () => Promise<void>;
  cleanup: () => Promise<void>;
};

test("preflights a mixed suite and derives an immutable ordered plan", async () => {
  await withSuite(async (fixture) => {
    const plan = await preflightFixture(fixture);
    assert.equal(plan.suiteId, "synthetic-suite");
    assert.equal(plan.repeat, 2);
    assert.equal(plan.cases.length, 3);
    assert.equal(plan.slots.length, 6);
    assert.deepEqual(
      plan.slots.map(({ caseIndex, repeatIndex, attemptKey }) => ({
        caseIndex,
        repeatIndex,
        attemptKey,
      })),
      [
        { caseIndex: 0, repeatIndex: 0, attemptKey: "c0-r0" },
        { caseIndex: 0, repeatIndex: 1, attemptKey: "c0-r1" },
        { caseIndex: 1, repeatIndex: 0, attemptKey: "c1-r0" },
        { caseIndex: 1, repeatIndex: 1, attemptKey: "c1-r1" },
        { caseIndex: 2, repeatIndex: 0, attemptKey: "c2-r0" },
        { caseIndex: 2, repeatIndex: 1, attemptKey: "c2-r1" },
      ],
    );
    assert.equal(plan.cases[0]!.policy, undefined);
    assert.match(plan.cases[1]!.policy!.policyBindingDigest, /^[a-f0-9]{64}$/u);
    assert.match(plan.casePolicyMapDigest, /^[a-f0-9]{64}$/u);
    assert.match(plan.suitePlanDigest, /^[a-f0-9]{64}$/u);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.cases), true);
    assert.equal(Object.isFrozen(plan.slots[0]), true);
    assert.equal(Object.isFrozen(plan.provider.requested), true);
    assert.equal(Object.isFrozen(plan.sanitizer?.allowedFindingPathPatterns), true);
  });
});

test("does not open provider input contents during all-case preflight", async (t) => {
  await withSuite(async (fixture) => {
    const providerInputs = new Set(
      fixture.manifest.cases.flatMap((entry) =>
        ["prepared-image.png", "schema.json", "system.txt", "instruction.txt", "truth.json"].map(
          (name) => path.resolve(fixture.root, entry.bundlePath, name),
        ),
      ),
    );
    const originalOpenSync = fs.openSync;
    let providerInputOpens = 0;
    t.mock.method(fs, "openSync", (...args: Parameters<typeof fs.openSync>) => {
      const [file] = args;
      if (typeof file === "string" && providerInputs.has(path.resolve(file))) {
        providerInputOpens += 1;
        throw new Error("provider input opened during suite preflight");
      }
      return originalOpenSync(...args);
    });
    syncBuiltinESMExports();
    try {
      const plan = await preflightFixture(fixture);
      assert.equal(plan.cases.length, 3);
      assert.equal(providerInputOpens, 0);
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
    }
  });
});

test("rejects a bundle manifest swapped after reference capture", async () => {
  await withSuite(async (fixture) => {
    const manifestPath = path.resolve(fixture.root, fixture.manifest.cases[0]!.bundlePath, "bundle.json");
    const heldPath = `${manifestPath}.synthetic-held`;
    const originalDerive = fixture.verifier.derive;
    let swapped = false;
    fixture.verifier.derive = (documentKind) => {
      if (!swapped) {
        swapped = true;
        fs.renameSync(manifestPath, heldPath);
        fs.copyFileSync(heldPath, manifestPath);
      }
      return originalDerive(documentKind);
    };
    try {
      await expectSuiteError(fixture, "suite_case_bundle_invalid", 0);
      assert.equal(swapped, true);
    } finally {
      if (swapped) {
        fs.rmSync(manifestPath, { force: true });
        fs.renameSync(heldPath, manifestPath);
      }
    }
  });
});

test("suite plan identities cover order, repeat, and case-policy mapping", async () => {
  await withSuite(async (fixture) => {
    const original = await preflightFixture(fixture);

    fixture.manifest.cases = [
      fixture.manifest.cases[1]!,
      fixture.manifest.cases[0]!,
      fixture.manifest.cases[2]!,
    ];
    await fixture.write();
    const reordered = await preflightFixture(fixture);
    assert.notEqual(reordered.suiteDigest, original.suiteDigest);
    assert.notEqual(reordered.casePolicyMapDigest, original.casePolicyMapDigest);
    assert.notEqual(reordered.suitePlanDigest, original.suitePlanDigest);

    fixture.manifest.repeat = 3;
    await fixture.write();
    const repeated = await preflightFixture(fixture);
    assert.equal(repeated.casePolicyMapDigest, reordered.casePolicyMapDigest);
    assert.notEqual(repeated.suitePlanDigest, reordered.suitePlanDigest);
    assert.equal(repeated.slots.length, 9);
  });
});

test("rejects bundle, requirement, target, and binding mutations at their case position", async () => {
  await withSuite(async (fixture) => {
    fixture.manifest.cases[0]!.expectedBundleManifestDigest = DIGEST_A;
    await fixture.write();
    await expectSuiteError(fixture, "suite_case_identity_mismatch", 0);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.cases[0]!.requirementDecisionDigest = DIGEST_B;
    await fixture.write();
    await expectSuiteError(fixture, "suite_requirement_mismatch", 0);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.cases[1]!.policy!.expectedPolicyTargetIdentityDigest = DIGEST_C;
    await fixture.write();
    await expectSuiteError(fixture, "suite_policy_target_mismatch", 1);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.cases[1]!.policy!.expectedPolicyBindingDigest = DIGEST_D;
    await fixture.write();
    await expectSuiteError(fixture, "suite_policy_binding_mismatch", 1);
  });
});

test("rejects a self-consistent required-to-not-required downgrade", async () => {
  await withSuite(async (fixture) => {
    const entry = fixture.manifest.cases[1]!;
    const forged = createSanitizerRequirementDecision(
      {
        sanitizerRequired: false,
        policyRequired: false,
        sanitizerRequirementReason: "synthetic_not_required",
        consumerSourceCommit: fixture.manifest.requirementVerifier.consumerSourceCommit,
      },
      fixture.verifier,
    );
    entry.sanitizerRequired = false;
    entry.policyRequired = false;
    entry.sanitizerRequirementReason = forged.sanitizerRequirementReason;
    entry.requirementDecisionDigest = forged.requirementDecisionDigest;
    delete entry.policy;
    await fixture.write();
    await expectSuiteError(fixture, "suite_requirement_mismatch", 1);
  });
});

test("rejects swapping policies between required cases before provider work", async () => {
  await withSuite(async (fixture) => {
    const secondPolicy = fixture.manifest.cases[1]!.policy!;
    const thirdPolicy = fixture.manifest.cases[2]!.policy!;
    fixture.manifest.cases[1]!.policy = thirdPolicy;
    fixture.manifest.cases[2]!.policy = secondPolicy;
    await fixture.write();
    await expectSuiteError(fixture, "suite_policy_target_mismatch", 1);
  });
});

test("rejects policy state on a not-required case and inconsistent suite sanitizer state", async () => {
  await withSuite(async (fixture) => {
    fixture.manifest.cases[0]!.policy = { ...fixture.manifest.cases[1]!.policy! };
    await fixture.write();
    await expectSuiteError(fixture, "suite_invalid", null);
  });

  await withSuite(async (fixture) => {
    delete fixture.manifest.sanitizer;
    await fixture.write();
    await expectSuiteError(fixture, "suite_sanitizer_configuration_invalid", null);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.cases = [fixture.manifest.cases[0]!];
    await fixture.write();
    await expectSuiteError(fixture, "suite_sanitizer_configuration_invalid", null);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.approval.phase = "synthetic-other-phase";
    await fixture.write();
    await expectSuiteError(fixture, "suite_invalid", null);
  });

  await withSuite(async (fixture) => {
    fixture.manifest.sanitizer!.command = {
      ...fixture.manifest.sanitizer!.command,
      envAllowlist: ["PATH", "Path"],
    };
    await fixture.write();
    await expectSuiteError(fixture, "suite_invalid", null);
  });
});

test("rejects unsafe references and non-private policy files without exposing values", async () => {
  await withSuite(async (fixture) => {
    const marker = "synthetic-local-secret-marker";
    fixture.manifest.cases[0]!.bundlePath = `../${marker}`;
    await fixture.write();
    const error = await captureSuiteError(fixture);
    assert.equal(error.code, "suite_reference_invalid");
    assert.equal(error.caseIndex, 0);
    assert.ok(!JSON.stringify(error).includes(marker));
    assert.ok(!error.message.includes(marker));
  });

  await withSuite(async (fixture) => {
    await chmod(path.join(fixture.root, fixture.manifest.cases[1]!.policy!.path), 0o644);
    await expectSuiteError(fixture, "suite_policy_invalid", 1);
  });

  await withSuite(async (fixture) => {
    await chmod(path.join(fixture.root, "suite.json"), 0o644);
    await expectSuiteError(fixture, "suite_invalid", null);
  });
});

test("schema failures do not echo unknown keys, values, paths, or digests", async () => {
  await withSuite(async (fixture) => {
    const marker = "SYNTHETIC_PROHIBITED_VALUE";
    fixture.manifest.syntheticUnknown = marker;
    await fixture.write();
    const error = await captureSuiteError(fixture);
    assert.equal(error.code, "suite_invalid");
    const rendered = JSON.stringify({
      code: error.code,
      message: error.message,
      caseIndex: error.caseIndex,
      repeatIndex: error.repeatIndex,
    });
    assert.ok(!rendered.includes(marker));
    assert.ok(!rendered.includes(fixture.root));
  });

  await withSuite(async (fixture) => {
    fixture.manifest.provider.requested.model = "synthetic invalid model";
    await fixture.write();
    await expectSuiteError(fixture, "suite_invalid", null);
  });
});

test("attempt keys are deterministic and reject invalid slot positions", () => {
  assert.equal(deriveSuiteAttemptKey(35, 71), "cz-r1z");
  for (const [caseIndex, repeatIndex] of [
    [-1, 0],
    [0, -1],
    [0.5, 0],
  ]) {
    assert.throws(
      () => deriveSuiteAttemptKey(caseIndex!, repeatIndex!),
      (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_slot_invalid",
    );
  }
});

test("case policy map identity uses the v1 fixed vector", () => {
  const verifier = {
    id: "synthetic-verifier",
    version: "v1",
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "synthetic_not_required",
      consumerSourceCommit: null,
    }),
  };
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-case",
    documentKind: "synthetic-document",
    preparedImage: { mediaType: "image/png", sha256: "1".repeat(64) },
  });
  const secondIdentity = computeCaseInputIdentity({
    caseId: "synthetic-case-two",
    documentKind: "synthetic-document",
    preparedImage: { mediaType: "image/png", sha256: "2".repeat(64) },
  });
  const notRequired = createSanitizerRequirementDecision(verifier.derive(), verifier);
  const required = createSanitizerRequirementDecision(
    {
      sanitizerRequired: true,
      policyRequired: true,
      sanitizerRequirementReason: "synthetic_required",
      consumerSourceCommit: "synthetic-commit",
    },
    verifier,
  );
  const policyDigest = "8".repeat(64);
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: secondIdentity.digest,
    policyVersion: 1,
    policyDigest,
  });
  assert.equal(
    computeCasePolicyMapDigest([
      {
        caseIndex: 0,
        bundlePath: "cases/alpha",
        bundleManifestDigest: "5".repeat(64),
        caseInputIdentity: identity,
        sanitizerRequirement: notRequired,
      },
      {
        caseIndex: 1,
        bundlePath: "cases/bravo",
        bundleManifestDigest: "6".repeat(64),
        caseInputIdentity: secondIdentity,
        sanitizerRequirement: required,
        policy: {
          path: "policies/bravo.json",
          policyVersion: 1,
          policyDigest,
          policyTargetIdentityDigest: secondIdentity.digest,
          policyBindingDigest,
        },
      },
    ]),
    "65cf207d0e2c3e525ffd358bde2316f1e82d86c77b4983dc8cb7f50f66ccacce",
  );
});

test("suite plan identity uses the v1 fixed vector", () => {
  assert.equal(
    computeSuitePlanDigest("a".repeat(64), "b".repeat(64)),
    "94c0fbc55f3961b2959f4a1e9f2bc18f2b671ede56d5269822312fd37aae3ede",
  );
  assert.throws(
    () => computeSuitePlanDigest("synthetic-invalid", "b".repeat(64)),
    (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
  );
});

test("case policy map rejects malformed runtime input with a stable suite error", () => {
  const computeUntrusted = computeCasePolicyMapDigest as (cases: unknown) => string;
  for (const cases of [
    [null],
    [{ caseIndex: 0 }],
    [{ caseIndex: 0, syntheticUnexpected: true }],
  ]) {
    assert.throws(
      () => computeUntrusted(cases),
      (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
    );
  }

  let getterReads = 0;
  const accessor = Object.defineProperty({}, "caseIndex", {
    enumerable: true,
    get: () => {
      getterReads += 1;
      throw new Error("synthetic accessor must not run");
    },
  });
  assert.throws(
    () => computeUntrusted([accessor]),
    (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
  );
  assert.equal(getterReads, 0);

  const oversizedCases = new Array(1001);
  Object.defineProperty(oversizedCases, "0", {
    enumerable: true,
    get: () => {
      getterReads += 1;
      throw new Error("synthetic oversized accessor must not run");
    },
  });
  assert.throws(
    () => computeUntrusted(oversizedCases),
    (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
  );
  assert.equal(getterReads, 0);

  const tooManyKeys = Object.fromEntries(
    Array.from({ length: 9 }, (_, index) => [`synthetic${index}`, index]),
  );
  assert.throws(
    () => computeUntrusted([tooManyKeys]),
    (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
  );

  const verifier = {
    id: "synthetic-verifier",
    version: "v1",
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "synthetic_not_required",
      consumerSourceCommit: null,
    }),
  };
  const invalidMediaIdentity = computeCaseInputIdentity({
    caseId: "synthetic-case",
    documentKind: "synthetic-document",
    preparedImage: { mediaType: "text/plain", sha256: "1".repeat(64) },
  });
  assert.throws(
    () =>
      computeUntrusted([
        {
          caseIndex: 0,
          bundlePath: "cases/alpha",
          bundleManifestDigest: "2".repeat(64),
          caseInputIdentity: invalidMediaIdentity,
          sanitizerRequirement: createSanitizerRequirementDecision(verifier.derive(), verifier),
        },
      ]),
    (error: unknown) => error instanceof SuitePreflightError && error.code === "suite_invalid",
  );
});

async function withSuite(run: (fixture: SuiteFixture) => Promise<void>): Promise<void> {
  const fixture = await createSuiteFixture();
  try {
    await run(fixture);
  } finally {
    await fixture.cleanup();
  }
}

async function createSuiteFixture(): Promise<SuiteFixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), "svbench-suite-synthetic-"));
  await mkdir(path.join(root, "cases"));
  await mkdir(path.join(root, "policies"));
  const caseNames = ["alpha", "bravo", "charlie"];
  const caseIds = ["synthetic-suite-alpha", "synthetic-suite-bravo", "synthetic-suite-charlie"];
  const caseEntries: CaseEntry[] = [];
  const verifier = {
    id: "synthetic-requirement-verifier",
    version: "v1",
    derive: (documentKind: string) => ({
      sanitizerRequired: documentKind !== "synthetic_invoice",
      policyRequired: documentKind !== "synthetic_invoice",
      sanitizerRequirementReason:
        documentKind === "synthetic_invoice" ? "synthetic_not_required" : "synthetic_required",
      consumerSourceCommit: "synthetic-source-v1",
    }),
  };

  for (const [index, name] of caseNames.entries()) {
    const bundleDirectory = path.join(root, "cases", name!);
    await cp(FIXTURE, bundleDirectory, { recursive: true });
    const bundleManifestPath = path.join(bundleDirectory, "bundle.json");
    const bundleManifest = JSON.parse(await readFile(bundleManifestPath, "utf8")) as {
      caseId: string;
      metadata: { documentKind: string };
    };
    bundleManifest.caseId = caseIds[index]!;
    bundleManifest.metadata.documentKind = index === 0 ? "synthetic_invoice" : `synthetic_sensitive_${index}`;
    await writeFile(bundleManifestPath, `${JSON.stringify(bundleManifest, null, 2)}\n`, "utf8");

    const prepared = await prepareBundleForRunner(bundleDirectory);
    const identity = computeCaseInputIdentity({
      caseId: prepared.caseId,
      documentKind: prepared.documentKind,
      preparedImage: prepared.image,
    });
    const requirement = createSanitizerRequirementDecision(
      verifier.derive(prepared.documentKind),
      verifier,
    );
    const entry: CaseEntry = {
      bundlePath: `cases/${name}`,
      expectedBundleManifestDigest: prepared.manifestDigest,
      expectedCaseInputIdentityVersion: 1,
      expectedCaseInputIdentityDigest: identity.digest,
      sanitizerRequirementVersion: 1,
      sanitizerRequired: requirement.sanitizerRequired,
      policyRequired: requirement.policyRequired,
      sanitizerRequirementReason: requirement.sanitizerRequirementReason,
      requirementDecisionDigest: requirement.requirementDecisionDigest,
    };
    if (requirement.policyRequired) {
      const policyBytes = createSanitizerPolicyEnvelope({
        target: identity,
        policyVersion: 1,
        policy: { syntheticRule: `synthetic-rule-${index}` },
      });
      const policyPath = path.join(root, "policies", `${name}.json`);
      await writeFile(policyPath, policyBytes, { mode: 0o600 });
      await chmod(policyPath, 0o600);
      const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
      entry.policy = {
        path: `policies/${name}.json`,
        expectedPolicyVersion: 1,
        expectedPolicyDigest: policyDigest,
        expectedPolicyTargetIdentityDigest: identity.digest,
        expectedPolicyBindingDigest: computePolicyBindingDigest({
          caseInputIdentityDigest: identity.digest,
          policyVersion: 1,
          policyDigest,
        }),
      };
    }
    caseEntries.push(entry);
  }

  const command: CommandConfig = {
    executable: path.join(root, "synthetic-command"),
    argv: ["--synthetic"],
    envAllowlist: ["SYNTHETIC_ENV"],
    timeoutMs: 1000,
    outputLimitBytes: 4096,
  };
  const manifest: SuiteManifest = {
    suiteVersion: 1,
    suiteId: "synthetic-suite",
    provider: {
      id: "synthetic-provider",
      route: "synthetic-route",
      implementationVersion: "v1",
      protocolVersion: "v1",
      requested: { model: "synthetic-model", effort: "medium", maxTokens: 512 },
    },
    phase: "synthetic-phase",
    repeat: 2,
    requirementVerifier: {
      id: verifier.id,
      version: verifier.version,
      consumerSourceCommit: "synthetic-source-v1",
    },
    approval: {
      required: true,
      command,
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
      command,
      expectedSanitizerId: "synthetic-sanitizer",
      expectedProtocolVersion: 1,
      allowedFindingPathPatterns: ["/summary/code", "/lines/*/code"],
      failureCodes: ["synthetic_rejected"],
    },
    cases: caseEntries,
  };
  const write = async (): Promise<void> => {
    const suitePath = path.join(root, "suite.json");
    await writeFile(suitePath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await chmod(suitePath, 0o600);
  };
  await write();
  return {
    root,
    manifest,
    verifier,
    write,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

async function expectSuiteError(
  fixture: SuiteFixture,
  code: string,
  caseIndex: number | null,
): Promise<void> {
  const error = await captureSuiteError(fixture);
  assert.equal(error.code, code);
  assert.equal(error.caseIndex, caseIndex);
}

async function preflightFixture(fixture: SuiteFixture) {
  return preflightSuite(fixture.root, { requirementVerifier: fixture.verifier });
}

async function captureSuiteError(fixture: SuiteFixture): Promise<SuitePreflightError> {
  try {
    await preflightFixture(fixture);
  } catch (error) {
    assert.ok(error instanceof SuitePreflightError);
    return error;
  }
  assert.fail("expected suite preflight to fail");
}
