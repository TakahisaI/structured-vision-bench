import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../src/bundle/json.js";
import { validateJsonSchemaDefinition } from "../src/bundle/schema-validator.js";
import { validateJsonSchema } from "../src/bundle/schema-validator.js";
import { createMockProvider } from "../src/provider/mock.js";
import {
  computeAttemptIdentity,
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  computeRunIdentity,
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../src/runner/identity.js";
import {
  claimAttemptDirectory,
  cleanupAttemptClaim,
  readAttempt,
  writeAttemptFiles,
} from "../src/runner/attempt.js";
import { RunnerError } from "../src/runner/errors.js";
import {
  BundleValidationError,
  loadBundleForRunner,
  MAX_PROVIDER_INPUT_BYTES,
} from "../src/bundle/validate-bundle.js";
import { runBundle as runBundleImplementation } from "../src/runner/run.js";
import {
  createSanitizerPolicyEnvelope,
  type Sanitizer,
} from "../src/runner/sanitizer.js";
import type {
  ApprovalGate,
  Provider,
  ProviderModelRequest,
  RunBundleOptions,
} from "../src/runner/types.js";

const IMAGE_SHA256 = "dda43d98857bc0977a1bdc67e8005428c3af95ca73cddda69c9e8737eee03cc9";
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

type TestRunOptions = Omit<RunBundleOptions, "sanitizerRequirement"> & {
  sanitizerRequirement?: SanitizerRequirementSettings;
};

function syntheticRequirement(required: boolean): SanitizerRequirementSettings {
  const verifier = {
    id: "synthetic-consumer",
    version: "v1",
    derive: (_documentKind: string) => ({
      sanitizerRequired: required,
      policyRequired: required,
      sanitizerRequirementReason: required ? "synthetic_policy_required" : "synthetic_policy_not_required",
      consumerSourceCommit: null,
    }),
  };
  const core = verifier.derive("synthetic_invoice");
  return {
    verifier,
    decision: createSanitizerRequirementDecision(core, verifier),
  };
}

function runBundle(options: TestRunOptions) {
  return runBundleImplementation({
    ...options,
    sanitizerRequirement:
      options.sanitizerRequirement ?? syntheticRequirement(options.sanitizer?.required === true),
  });
}

const CASE_INPUT = {
  caseId: "synthetic-invoice-basic",
  documentKind: "synthetic_invoice",
  preparedImage: {
    mediaType: "image/png",
    sha256: IMAGE_SHA256,
  },
} as const;

test("computes the caseInputIdentity v1 fixed vector", () => {
  assert.deepEqual(computeCaseInputIdentity(CASE_INPUT), {
    identityVersion: 1,
    caseId: CASE_INPUT.caseId,
    documentKind: CASE_INPUT.documentKind,
    preparedImage: CASE_INPUT.preparedImage,
    digest: "3d8d562479e1a99f4119e8ff5e70fc4e9a09602a8a082a56ee0a72713e0b5be0",
  });
});

test("caseInputIdentity changes only for its declared inputs", () => {
  const base = computeCaseInputIdentity(CASE_INPUT).digest;
  assert.notEqual(
    computeCaseInputIdentity({ ...CASE_INPUT, caseId: "synthetic-invoice-other" }).digest,
    base,
  );
  assert.notEqual(
    computeCaseInputIdentity({ ...CASE_INPUT, documentKind: "synthetic_receipt" }).digest,
    base,
  );
  assert.notEqual(
    computeCaseInputIdentity({
      ...CASE_INPUT,
      preparedImage: { ...CASE_INPUT.preparedImage, mediaType: "image/webp" },
    }).digest,
    base,
  );
  assert.notEqual(
    computeCaseInputIdentity({
      ...CASE_INPUT,
      preparedImage: { ...CASE_INPUT.preparedImage, sha256: "0".repeat(64) },
    }).digest,
    base,
  );
});

test("policyBindingDigest uses the v1 fixed vector", () => {
  assert.equal(
    computePolicyBindingDigest({
      caseInputIdentityDigest: "3d8d562479e1a99f4119e8ff5e70fc4e9a09602a8a082a56ee0a72713e0b5be0",
      policyVersion: 1,
      policyDigest: "bc57d67ac57d3947717e8a4858356af81969a2d5a2e533e4722be3fc4ca18569",
    }),
    "315fe3576fc69fda19be1d4e0338214f3c39a6a75506073a035cb6d6249a20cf",
  );
});

test("computes the attempt identity v1 fixed vector", () => {
  assert.deepEqual(
    computeAttemptIdentity({ runId: "0".repeat(64), attemptKey: "single" }),
    {
      attemptIdentityVersion: 1,
      runId: "0".repeat(64),
      attemptKey: "single",
      attemptId: "fdfb37c2c6f5a51a8fca6ed03aeaea452aca82cc501396074b35bd04e008e3b0",
    },
  );
});

test("run identity changes when requested execution settings change", () => {
  const base = {
    caseInputIdentityDigest: "3d8d562479e1a99f4119e8ff5e70fc4e9a09602a8a082a56ee0a72713e0b5be0",
    providerId: "mock",
    providerRoute: "mock",
    requestedModel: "mock-v1",
    requestedEffort: "medium",
    maxTokens: 512,
  } as const;
  const run = computeRunIdentity(base);
  assert.match(run, /^[a-f0-9]{64}$/u);
  assert.equal(computeRunIdentity(base), run);
  assert.notEqual(computeRunIdentity({ ...base, requestedModel: "mock-v2" }), run);
  assert.notEqual(computeRunIdentity({ ...base, requestedEffort: "high" }), run);
  assert.notEqual(computeRunIdentity({ ...base, maxTokens: 1024 }), run);
  assert.notEqual(computeRunIdentity({ ...base, approvalGateId: "synthetic-gate" }), run);
  assert.notEqual(computeRunIdentity({ ...base, approvalSnapshotDigest: "a".repeat(64) }), run);
  assert.notEqual(computeRunIdentity({ ...base, sanitizerId: "synthetic-sanitizer" }), run);
  assert.notEqual(
    computeRunIdentity({ ...base, requirementDecisionDigest: "b".repeat(64) }),
    run,
  );
  assert.notEqual(computeRunIdentity({ ...base, requestedModel: null }), computeRunIdentity(base));
});

test("run identity distinguishes absent optional values from explicit null", () => {
  const base = {
    caseInputIdentityDigest: CASE_INPUT.preparedImage.sha256,
    providerId: "mock",
    providerRoute: "mock",
  };
  assert.notEqual(
    computeRunIdentity(base),
    computeRunIdentity({ ...base, requestedModel: null }),
  );
  assert.notEqual(
    computeRunIdentity(base),
    computeRunIdentity({ ...base, maxTokens: null }),
  );
  assert.notEqual(
    computeRunIdentity(base),
    computeRunIdentity({ ...base, approvalBindingDigest: null }),
  );
});

test("stages verified provider inputs away from the mutable bundle", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const staging = path.join(temporary, "staging");
  let retainedImageReader: (() => Promise<Buffer>) | undefined;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const loaded = await loadBundleForRunner(bundle, staging);
    try {
      const manifestBytes = await readFile(path.join(bundle, "bundle.json"));
      assert.equal(
        loaded.manifestDigest,
        createHash("sha256").update(manifestBytes).digest("hex"),
      );
      assert.equal(loaded.caseId, "synthetic-invoice-basic");
      assert.equal(loaded.documentKind, "synthetic_invoice");
      assert.equal(loaded.inputs.image.mediaType, "image/png");
      retainedImageReader = loaded.inputs.image.readBytes;
      assert.equal(await loaded.inputs.system.readText(), await readFile(path.join(bundle, "system.txt"), "utf8"));
      const stagedImage = await loaded.inputs.image.readBytes();

      await writeFile(path.join(bundle, "prepared-image.png"), Buffer.from("synthetic replacement"));
      assert.deepEqual(await loaded.inputs.image.readBytes(), stagedImage);
      assert.equal(loaded.inputs.schema.value !== null, true);
    } finally {
      await loaded.cleanup();
    }
    assert.ok(retainedImageReader);
    await assert.rejects(retainedImageReader());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("revokes retained provider callbacks after a successful run", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let retainedRequest: ProviderModelRequest | undefined;
  const provider: Provider = {
    id: "retained-success",
    route: "synthetic",
    invoke: async (request) => {
      retainedRequest = request;
      return {
        rawDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider });
    assert.ok(retainedRequest);
    await assert.rejects(retainedRequest.image.readBytes());
    await assert.rejects(retainedRequest.system.readText());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("revokes retained provider callbacks after a failed run", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let retainedRequest: ProviderModelRequest | undefined;
  const provider: Provider = {
    id: "retained-failure",
    route: "synthetic",
    invoke: async (request) => {
      retainedRequest = request;
      throw new Error("synthetic provider failure");
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.ok(retainedRequest);
    await assert.rejects(retainedRequest.image.readBytes());
    await assert.rejects(retainedRequest.instruction.readText());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("bounds staged provider input snapshots", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const staging = path.join(temporary, "staging");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const image = Buffer.alloc(MAX_PROVIDER_INPUT_BYTES + 1, 0x53);
    const imagePath = path.join(bundle, "prepared-image.png");
    await writeFile(imagePath, image);
    const manifestPath = path.join(bundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      inputs: { image: { sha256: string } };
    };
    manifest.inputs.image.sha256 = createHash("sha256").update(image).digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      loadBundleForRunner(bundle, staging),
      (error: unknown) =>
        error instanceof BundleValidationError && error.code === "runner_input_too_large",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("cleanup does not remove files it did not create", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const attempts = path.join(temporary, "attempts");
  const claimDirectory = path.join(attempts, "synthetic-claim");
  const existingDocument = Buffer.from("synthetic existing document\n", "utf8");
  try {
    await mkdir(attempts, { mode: 0o700 });
    const claim = await claimAttemptDirectory(claimDirectory);
    await writeFile(path.join(claimDirectory, "document.json"), existingDocument, {
      mode: 0o600,
    });
    await cleanupAttemptClaim(claim, async () => true);
    assert.deepEqual(await readFile(path.join(claimDirectory, "document.json")), existingDocument);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not replace a pre-existing document in a claimed directory", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const existingDocument = Buffer.from("synthetic pre-existing document\n", "utf8");
  const provider: Provider = {
    id: "pre-existing-document",
    route: "synthetic",
    invoke: async () => {
      const [attemptId] = await readdir(attempts);
      await writeFile(path.join(attempts, attemptId!, "document.json"), existingDocument, {
        mode: 0o600,
      });
      return {
        rawDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_write_failed",
    );
    const [attemptId] = await readdir(attempts);
    assert.deepEqual(
      await readFile(path.join(attempts, attemptId!, "document.json")),
      existingDocument,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("claims the final attempt directory before provider work", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const document = {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-001",
    issuedAt: "2026-01-01",
    currency: "JPY",
    lines: [],
    totalAmount: 0,
  };
  const provider: Provider = {
    id: "claim-observer",
    route: "synthetic",
    invoke: async () => {
      const runEntries = (await readdir(attempts)).sort();
      assert.equal(runEntries.length, 1);
      assert.match(runEntries[0]!, /^[a-f0-9]{64}$/u);
      const claimDirectory = path.join(attempts, runEntries[0]!);
      assert.deepEqual((await readdir(claimDirectory)).sort(), [".attempt-owner.pending"]);
      assert.match(
        await readFile(path.join(claimDirectory, ".attempt-owner.pending"), "utf8"),
        /^[0-9a-f-]{36}\n$/u,
      );
      return { rawDocument: document };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider });
    assert.deepEqual((await readdir(result.attemptDirectory)).sort(), ["attempt.json", "document.json"]);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("cleans up an owned unpublished claim after provider failure", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let sawClaim = false;
  const provider: Provider = {
    id: "claim-failure",
    route: "synthetic",
    invoke: async () => {
      const runEntries = await readdir(attempts);
      assert.equal(runEntries.length, 1);
      assert.deepEqual(
        await readdir(path.join(attempts, runEntries[0]!)),
        [".attempt-owner.pending"],
      );
      sawClaim = true;
      throw new Error("synthetic provider failure");
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.equal(sawClaim, true);
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("cleans a claim when initialization fails before opening or writing its marker", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const attempts = path.join(temporary, "attempts");
  const claimAttemptDirectoryWithHooks = claimAttemptDirectory as unknown as (
    attemptDirectory: string,
    hooks: {
      beforeDirectoryOpen?: () => Promise<void>;
      beforeOwnerMarkerWrite?: () => Promise<void>;
    },
  ) => Promise<Awaited<ReturnType<typeof claimAttemptDirectory>>>;
  try {
    await mkdir(attempts, { mode: 0o700 });
    for (const [name, hook] of [
      ["before-open", "beforeDirectoryOpen"],
      ["before-marker-write", "beforeOwnerMarkerWrite"],
    ] as const) {
      const hooks = {
        [hook]: async () => {
          throw new Error("synthetic initialization failure");
        },
      };
      await assert.rejects(
        claimAttemptDirectoryWithHooks(path.join(attempts, name), hooks),
        (error: unknown) => error instanceof RunnerError && error.code === "attempt_write_failed",
      );
      assert.deepEqual(await readdir(attempts), []);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("requires an attested consumer decision and blocks sanitizer downgrades", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({ onInvoke: () => { providerCalls += 1; } });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        sanitizerRequirement: syntheticRequirement(true),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "sanitizer_required",
    );
    assert.equal(providerCalls, 0);
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        sanitizer: { required: false },
        sanitizerRequirement: syntheticRequirement(false),
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "sanitizer_configuration_invalid",
    );
    assert.equal(providerCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs the mock provider and writes a readable sanitized attempt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let imageReads = 0;
  let capturedRequest: Record<string, unknown> | undefined;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      respondedModel: null,
      effectiveEffort: null,
      onRequest: (request) => {
        assert.deepEqual(Object.keys(request.image).sort(), ["mediaType", "readBytes"]);
        assert.deepEqual(Object.keys(request.system).sort(), ["readText"]);
        assert.deepEqual(Object.keys(request.instruction).sort(), ["readText"]);
        capturedRequest = request as unknown as Record<string, unknown>;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider,
      requestedModel: "mock-v1",
      requestedEffort: "medium",
      maxTokens: 512,
    });

    assert.equal(result.caseId, "synthetic-invoice-basic");
    assert.equal(result.attemptKey, "single");
    assert.match(result.attemptId, /^[a-f0-9]{64}$/u);
    assert.match(result.runId, /^[a-f0-9]{64}$/u);
    assert.notEqual(result.attemptId, result.runId);
    assert.equal(imageReads, 1);
    assert.ok(capturedRequest);
    assert.equal(capturedRequest!.caseId, undefined);
    assert.equal(capturedRequest!.truth, undefined);
    assert.equal(capturedRequest!.comparison, undefined);
    assert.equal(capturedRequest!.bundleRoot, undefined);
    assert.equal(capturedRequest!.attemptKey, undefined);
    assert.equal(capturedRequest!.attemptId, undefined);
    assert.equal(capturedRequest!.runId, undefined);

    const attempt = await readAttempt(result.attemptDirectory);
    const attemptSchema = parseJson(
      decodeUtf8Strict(await readFile("schemas/attempt-v1.schema.json"), "attempt schema"),
      "attempt schema",
    );
    assert.deepEqual(validateJsonSchemaDefinition(attemptSchema), []);
    assert.deepEqual(validateJsonSchema(attemptSchema, attempt.manifest), []);
    for (const stageName of ["policyTargetPreflight", "sanitizer", "targetBinding"] as const) {
      const stageOnlyManifest = {
        ...attempt.manifest,
        stages: {
          ...attempt.manifest.stages,
          [stageName]: { status: "passed", errorCode: null },
        },
      };
      assert.notDeepEqual(validateJsonSchema(attemptSchema, stageOnlyManifest), []);
    }
    await readAttempt(result.attemptDirectory, {
      requirementVerifier: syntheticRequirement(false).verifier,
    });
    assert.equal(attempt.manifest.attemptVersion, 1);
    assert.equal(attempt.manifest.attemptIdentityVersion, 1);
    assert.equal(attempt.manifest.attemptKey, "single");
    assert.equal(attempt.manifest.attemptId, result.attemptId);
    assert.equal(attempt.manifest.runId, result.runId);
    assert.equal(attempt.manifest.caseId, "synthetic-invoice-basic");
    assert.equal(attempt.manifest.run.requested.model, "mock-v1");
    assert.equal(attempt.manifest.run.requested.effort, "medium");
    assert.equal(attempt.manifest.run.requested.maxTokens, 512);
    assert.equal(attempt.manifest.run.responded.model, null);
    assert.equal(attempt.manifest.run.responded.effort, null);
    assert.equal(attempt.manifest.sanitizer, undefined);
    assert.equal(attempt.manifest.approval.applied, false);
    assert.equal(attempt.manifest.document.path, "document.json");
    assert.equal(isJsonObject(attempt.document), true);
    if (isJsonObject(attempt.document)) {
      assert.equal(attempt.document.documentKind, "synthetic_invoice");
    }
    assert.equal(await readFile(path.join(result.attemptDirectory, "attempt.json"), "utf8") !== "", true);
    const persistedManifestPath = path.join(result.attemptDirectory, "attempt.json");
    const persistedManifest = JSON.parse(await readFile(persistedManifestPath, "utf8")) as {
      sanitizerRequirement: { sanitizerRequirementReason: string };
    };
    persistedManifest.sanitizerRequirement.sanitizerRequirementReason = "synthetic_tampered";
    await writeFile(persistedManifestPath, `${JSON.stringify(persistedManifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      readAttempt(result.attemptDirectory, {
        requirementVerifier: syntheticRequirement(false).verifier,
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("separates attempt instances from stable run identity", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  let imageReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });
    const first = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      attemptKey: "dev-001",
      provider,
    });
    const second = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      attemptKey: "dev-002",
      provider,
    });

    assert.equal(first.runId, second.runId);
    assert.notEqual(first.attemptId, second.attemptId);
    assert.equal(first.attemptKey, "dev-001");
    assert.equal(second.attemptKey, "dev-002");
    assert.deepEqual(
      (await readdir(attempts)).sort(),
      [first.attemptId, second.attemptId].sort(),
    );
    const [firstAttempt, secondAttempt] = await Promise.all([
      readAttempt(first.attemptDirectory),
      readAttempt(second.attemptDirectory),
    ]);
    assert.equal(
      firstAttempt.manifest.caseInputIdentity.digest,
      secondAttempt.manifest.caseInputIdentity.digest,
    );
    assert.equal(firstAttempt.manifest.bundleManifestDigest, secondAttempt.manifest.bundleManifestDigest);
    assert.deepEqual(firstAttempt.manifest.inputs, secondAttempt.manifest.inputs);
    assert.equal(providerCalls, 2);
    assert.equal(imageReads, 2);

    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        attemptKey: "dev-001",
        provider,
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_exists",
    );
    assert.equal(providerCalls, 2);
    assert.equal(imageReads, 2);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("enforces attempt key boundaries before provider input is read", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  let imageReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });

    for (const attemptKey of ["a", "a".repeat(64)]) {
      const result = await runBundle({ bundleDirectory: bundle, attemptRoot: attempts, attemptKey, provider });
      assert.equal(result.attemptKey, attemptKey);
    }
    assert.equal(providerCalls, 2);
    assert.equal(imageReads, 2);

    for (const attemptKey of ["", "a".repeat(65), "synthetic/key", "合成"]) {
      await assert.rejects(
        runBundle({ bundleDirectory: bundle, attemptRoot: attempts, attemptKey, provider }),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "run_configuration_invalid",
      );
    }
    for (const attemptKey of [null, 1, { synthetic: true }]) {
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: attempts,
          attemptKey: attemptKey as unknown as string,
          provider,
        }),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "run_configuration_invalid",
      );
    }
    assert.equal(providerCalls, 2);
    assert.equal(imageReads, 2);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs bundle-v1 caseId boundaries without invoking the provider for 129 characters", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const manifestPath = path.join(bundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { caseId: string };
    const attemptSchema = parseJson(
      decodeUtf8Strict(await readFile("schemas/attempt-v1.schema.json"), "attempt schema"),
      "attempt schema",
    );
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
    });

    for (const [index, length] of [64, 65, 128].entries()) {
      manifest.caseId = "a".repeat(length);
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      const result = await runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider });
      const attempt = await readAttempt(result.attemptDirectory);
      assert.equal(attempt.manifest.caseId, manifest.caseId);
      assert.equal(attempt.manifest.caseInputIdentity.caseId, manifest.caseId);
      assert.deepEqual(validateJsonSchema(attemptSchema, attempt.manifest), []);
      assert.equal(providerCalls, index + 1);
    }

    manifest.caseId = "a".repeat(129);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof BundleValidationError,
    );
    assert.equal(providerCalls, 3);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("keeps provenance commit constraints aligned between the attempt schema and reader", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    const manifestPath = path.join(result.attemptDirectory, "attempt.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      provenance: { harnessCommit: string | null; sourceCommit: string | null };
    };
    const attemptSchema = parseJson(
      decodeUtf8Strict(await readFile("schemas/attempt-v1.schema.json"), "attempt schema"),
      "attempt schema",
    );

    for (const field of ["harnessCommit", "sourceCommit"] as const) {
      const original = manifest.provenance[field];
      manifest.provenance[field] = "a".repeat(65);
      assert.notDeepEqual(validateJsonSchema(attemptSchema, manifest as unknown as JsonValue), []);
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      await assert.rejects(
        readAttempt(result.attemptDirectory),
        (error: unknown) => error instanceof RunnerError && error.code === "attempt_invalid",
      );
      manifest.provenance[field] = original;
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the mock provider generates documents for the supported schema subset", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const schema = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    allOf: [
      {
        type: "object",
        required: ["kind", "choice", "items", "refined", "combined"],
        properties: {
          kind: { $ref: "#/$defs/kind" },
          choice: {
            anyOf: [
              { type: "string", const: "synthetic-choice" },
              { type: "integer", const: 7 },
            ],
          },
          items: {
            type: "array",
            minItems: 1,
            items: { $ref: "#/$defs/item" },
          },
          refined: { $ref: "#/$defs/text", minLength: 12 },
          combined: { allOf: [{ type: "string" }, { minLength: 12 }] },
        },
        additionalProperties: false,
      },
      {
        properties: {
          kind: { type: "string" },
          choice: { oneOf: [{ type: "string" }, { type: "integer" }] },
          items: { type: "array" },
        },
      },
    ],
    $defs: {
      kind: { type: "string", const: "synthetic-kind" },
      item: { type: ["null", "string"], minLength: 1, not: { type: "null" } },
      text: { type: "string" },
    },
  } satisfies JsonValue;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const schemaBytes = Buffer.from(`${JSON.stringify(schema, null, 2)}\n`, "utf8");
    await writeFile(path.join(bundle, "schema.json"), schemaBytes);
    const manifestPath = path.join(bundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      inputs: { schema: { sha256: string } };
    };
    manifest.inputs.schema.sha256 = createHash("sha256").update(schemaBytes).digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
      sanitizerRequirement: syntheticRequirement(false),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.deepEqual(validateJsonSchema(schema, attempt.document), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("makes the final link immediately readable and ignores pending-manifest cleanup failure", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const writeAttemptFilesWithHooks = writeAttemptFiles as unknown as (
    claim: Awaited<ReturnType<typeof claimAttemptDirectory>>,
    manifest: Record<string, unknown>,
    document: JsonValue,
    canCleanup: () => Promise<boolean>,
    beforePublish?: (() => Promise<void>) | undefined,
    hooks?: { removePendingManifest?: (pendingPath: string) => Promise<void> },
  ) => Promise<{ documentSha256: string }>;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const initial = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    const saved = await readAttempt(initial.attemptDirectory);
    await rm(initial.attemptDirectory, { recursive: true, force: true });
    const claim = await claimAttemptDirectory(initial.attemptDirectory);
    const { document: _document, ...manifest } = saved.manifest;
    let observedNames: string[] | undefined;
    let readableDuringCleanup = false;
    let pendingSourcePresent = false;
    let stagingDirectoryName: string | undefined;
    await writeAttemptFilesWithHooks(
      claim,
      manifest,
      saved.document,
      async () => true,
      undefined,
      {
        removePendingManifest: async (pendingPath) => {
          assert.notEqual(path.dirname(pendingPath), initial.attemptDirectory);
          stagingDirectoryName = path.basename(path.dirname(pendingPath));
          pendingSourcePresent = (await stat(pendingPath)).isFile();
          observedNames = (await readdir(initial.attemptDirectory)).sort();
          try {
            await readAttempt(initial.attemptDirectory);
            readableDuringCleanup = true;
          } catch {
            readableDuringCleanup = false;
          }
          throw new Error("synthetic pending cleanup failure");
        },
      },
    );
    assert.deepEqual(observedNames, ["attempt.json", "document.json"]);
    assert.equal(readableDuringCleanup, true);
    assert.equal(pendingSourcePresent, true);
    assert.deepEqual((await readdir(initial.attemptDirectory)).sort(), ["attempt.json", "document.json"]);
    assert.ok(stagingDirectoryName);
    assert.match(stagingDirectoryName, /^\.claim-[0-9a-f-]{36}$/u);
    assert.deepEqual((await readdir(attempts)).sort(), [
      stagingDirectoryName,
      path.basename(initial.attemptDirectory),
    ].sort());
    await readAttempt(initial.attemptDirectory);
    await cleanupAttemptClaim(claim, async () => true);
    assert.deepEqual(await readdir(attempts), [path.basename(initial.attemptDirectory)]);
    await readAttempt(initial.attemptDirectory);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("removes a failed pre-publication claim so the same run can be retried", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const initial = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    const saved = await readAttempt(initial.attemptDirectory);
    await rm(initial.attemptDirectory, { recursive: true, force: true });
    const { document: _document, ...manifest } = saved.manifest;

    const failedClaim = await claimAttemptDirectory(initial.attemptDirectory);
    await assert.rejects(
      writeAttemptFiles(
        failedClaim,
        manifest,
        saved.document,
        async () => true,
        async () => {
          throw new Error("synthetic failure before final manifest link");
        },
      ),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_write_failed",
    );
    assert.deepEqual(await readdir(attempts), []);

    const retryClaim = await claimAttemptDirectory(initial.attemptDirectory);
    await writeAttemptFiles(retryClaim, manifest, saved.document, async () => true);
    await cleanupAttemptClaim(retryClaim, async () => true);
    assert.deepEqual((await readdir(initial.attemptDirectory)).sort(), ["attempt.json", "document.json"]);
    await readAttempt(initial.attemptDirectory);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not expose mutable aliases or internal input digests to a provider", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let schemaMutationRejected = false;
  let requestedMutationRejected = false;
  let contextMutationRejected = false;
  const provider: Provider = {
    id: "boundary-provider",
    route: "synthetic",
    invoke: async (request, context) => {
      (provider as { id: string; route: string }).id = "SYNTHETIC-PRIVATE-ID";
      (provider as { id: string; route: string }).route = "/synthetic/private/route";
      assert.equal("sha256" in request.image, false);
      assert.equal("attemptKey" in request, false);
      assert.equal("attemptId" in request, false);
      assert.equal("runId" in request, false);
      assert.equal("attemptKey" in context, false);
      assert.equal("attemptId" in context, false);
      assert.equal("runId" in context, false);
      try {
        (request.schema as Record<string, unknown>).type = "string";
      } catch {
        schemaMutationRejected = true;
      }
      try {
        (request.requested as { model: string | null }).model = "synthetic-mutated";
      } catch {
        requestedMutationRejected = true;
      }
      try {
        context.caseInputIdentity.digest = "0".repeat(64);
      } catch {
        contextMutationRejected = true;
      }
      return {
        rawDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider });
    assert.equal(schemaMutationRejected, true);
    assert.equal(requestedMutationRejected, true);
    assert.equal(contextMutationRejected, true);
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(attempt.manifest.run.providerId, "boundary-provider");
    assert.equal(attempt.manifest.run.route, "synthetic");
    assert.equal(attempt.manifest.run.requested.model, null);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("canonicalizes direct provider objects before schema validation and persistence", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const document: Record<string, unknown> = {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-001",
    issuedAt: "2026-01-01",
    currency: "JPY",
    lines: [],
    totalAmount: 0,
  };
  Object.defineProperty(document, "toJSON", {
    configurable: false,
    enumerable: false,
    value: () => ({ attackerControlled: true }),
  });
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider({ document: document as never }),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(isJsonObject(attempt.document), true);
    if (isJsonObject(attempt.document)) {
      assert.equal(Object.hasOwn(attempt.document, "attackerControlled"), false);
      assert.equal(attempt.document.documentKind, "synthetic_invoice");
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("preserves an explicit null mock document", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "attempts"),
        provider: createMockProvider({ document: null }),
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "provider_document_schema_invalid",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("masks a RunnerError thrown by a provider adapter", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: {
          id: "throwing-provider",
          route: "synthetic",
          invoke: async () => {
            throw new RunnerError("provider_response_invalid", "SYNTHETIC-SECRET-MARKER");
          },
        },
      }),
      (error: unknown) =>
        error instanceof RunnerError &&
        error.code === "provider_failed" &&
        !error.message.includes("SYNTHETIC-SECRET-MARKER"),
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("masks provider errors whose prototype inspection throws", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const hostileError = new Proxy(
    {},
    {
      getPrototypeOf: () => {
        throw new Error("SYNTHETIC-SECRET");
      },
    },
  );
  const provider: Provider = {
    id: "hostile-error-provider",
    route: "synthetic",
    invoke: async () => {
      throw hostileError;
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) =>
        error instanceof RunnerError &&
        error.code === "provider_failed" &&
        !error.message.includes("SYNTHETIC-SECRET"),
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("masks malformed nested provider usage metadata", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const document = {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-001",
    issuedAt: "2026-01-01",
    currency: "JPY",
    lines: [],
    totalAmount: 0,
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    for (const [index, usage] of [
      null,
      Object.defineProperty({}, "available", {
        enumerable: true,
        get: () => {
          throw new Error("SYNTHETIC-SECRET-MARKER");
        },
      }),
    ].entries()) {
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: path.join(temporary, `attempts-${index}`),
          provider: {
            id: "usage-provider",
            route: "synthetic",
            invoke: async () => ({ rawDocument: document, usage: usage as never }),
          },
        }),
        (error: unknown) =>
          error instanceof RunnerError &&
          error.code === "provider_response_invalid" &&
          !error.message.includes("SYNTHETIC-SECRET-MARKER"),
      );
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects unsafe provider metadata instead of persisting it", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: {
          id: "unsafe-metadata-provider",
          route: "synthetic",
          invoke: async () => ({
            rawDocument: {
              documentKind: "synthetic_invoice",
              invoiceNumber: "SYNTHETIC-001",
              issuedAt: "2026-01-01",
              currency: "JPY",
              lines: [],
              totalAmount: 0,
            },
            respondedModel: "/synthetic/private/model",
          }),
        },
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_response_invalid",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not read or stage image content before approval completes", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const image = path.join(bundle, "prepared-image.png");
  const movedImage = path.join(temporary, "prepared-image-original.png");
  const outsideImage = path.join(temporary, "outside-image.png");
  let providerCalls = 0;
  const snapshotDigest = "a".repeat(64);
  const runtimeBindingDigest = "b".repeat(64);
  const gate: ApprovalGate = {
    id: "swap-gate",
    protocolVersion: 1,
    approve: async () => {
      await rename(image, movedImage);
      await writeFile(outsideImage, Buffer.from("synthetic outside image", "utf8"));
      await symlink(outsideImage, image);
      return {
        responseVersion: 1,
        approved: true,
        gateId: "swap-gate",
        protocolVersion: 1,
        snapshotDigest,
        runtimeBindingDigest,
      };
    },
  };
  const provider: Provider = {
    id: "approval-order-provider",
    route: "synthetic",
    invoke: async () => {
      providerCalls += 1;
      return {
        rawDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        approval: {
          required: true,
          gate,
          expectedGateId: "swap-gate",
          expectedProtocolVersion: 1,
          snapshotDigest,
          runtimeBindingDigest,
        },
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        (error.code === "referenced_file_symlink" || error.code === "digest_mismatch"),
    );
    assert.equal(providerCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not publish after the attempt root is replaced during provider execution", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const movedRoot = path.join(temporary, "moved-attempts");
  const replacementRoot = path.join(temporary, "replacement-attempts");
  let providerCalls = 0;
  const provider: Provider = {
    id: "root-swap-provider",
    route: "synthetic",
    invoke: async () => {
      providerCalls += 1;
      await rename(attempts, movedRoot);
      await mkdir(replacementRoot);
      await symlink(replacementRoot, attempts);
      return {
        rawDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_write_failed",
    );
    assert.equal(providerCalls, 1);
    const movedEntries = await readdir(movedRoot);
    assert.equal(movedEntries.length, 1);
    assert.match(movedEntries[0]!, /^[a-f0-9]{64}$/u);
    assert.deepEqual(
      await readdir(path.join(movedRoot, movedEntries[0]!)),
      [".attempt-owner.pending"],
    );
    assert.deepEqual(await readdir(replacementRoot), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not invoke or let a rejected approval gate reach the provider", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let imageReads = 0;
  let providerCalls = 0;
  const snapshotDigest = "a".repeat(64);
  const runtimeBindingDigest = "b".repeat(64);
  const gate: ApprovalGate = {
    id: "fake-gate",
    protocolVersion: 1,
    approve: async (request) => {
      providerCalls += 0;
      assert.equal("caseId" in request, false);
      assert.equal("truth" in request, false);
      assert.equal("comparison" in request, false);
      assert.equal("attemptKey" in request, false);
      assert.equal("attemptId" in request, false);
      assert.equal("runId" in request, false);
      return {
        responseVersion: 1,
        approved: false,
        gateId: "fake-gate",
        protocolVersion: 1,
        snapshotDigest,
        runtimeBindingDigest,
        reasonCode: "synthetic_denied",
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        approval: {
          required: true,
          gate,
          expectedGateId: "fake-gate",
          expectedProtocolVersion: 1,
          snapshotDigest,
          runtimeBindingDigest,
        },
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "approval_denied",
    );
    assert.equal(providerCalls, 0);
    assert.equal(imageReads, 0);
    assert.equal(
      await readFile(attempts, "utf8").catch(() => "missing"),
      "missing",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects an optional approval gate before invoking it", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  let approvalCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "attempts"),
        provider: createMockProvider(),
        approval: {
          required: false,
          gate: {
            id: "synthetic-gate",
            protocolVersion: 1,
            approve: async () => {
              approvalCalls += 1;
              return {
                responseVersion: 1,
                approved: true,
                gateId: "synthetic-gate",
                protocolVersion: 1,
                snapshotDigest: "a".repeat(64),
                runtimeBindingDigest: "b".repeat(64),
              };
            },
          },
          expectedGateId: "synthetic-gate",
          expectedProtocolVersion: 1,
          snapshotDigest: "a".repeat(64),
          runtimeBindingDigest: "b".repeat(64),
        },
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "approval_configuration_invalid",
    );
    assert.equal(approvalCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a non-callable approval gate before provider invocation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: createMockProvider({
          onInvoke: () => {
            providerCalls += 1;
          },
        }),
        approval: {
          required: true,
          gate: {
            id: "synthetic-gate",
            protocolVersion: 1,
            approve: "synthetic-not-callable",
          } as unknown as ApprovalGate,
          expectedGateId: "synthetic-gate",
          expectedProtocolVersion: 1,
          snapshotDigest: "a".repeat(64),
          runtimeBindingDigest: "b".repeat(64),
        },
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "approval_configuration_invalid",
    );
    assert.equal(providerCalls, 0);
    await assert.rejects(readdir(attempts), /ENOENT/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("binds sanitizer output to the current case identity and policy bytes", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: identity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest,
  });
  const sanitizer: Sanitizer = {
    id: "fake-sanitizer",
    protocolVersion: 1,
    sanitize: async (request) => {
      assert.deepEqual(request.policy, { syntheticRule: "remove-extra-fields" });
      assert.equal(request.caseInputIdentity.digest, identity.digest);
      assert.equal("attemptKey" in request, false);
      assert.equal("attemptId" in request, false);
      assert.equal("runId" in request, false);
      return {
        sanitizedDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
        sanitizerId: "fake-sanitizer",
        protocolVersion: 1,
        policyVersion: 1,
        policyDigest,
        caseInputIdentityVersion: 1,
        caseInputIdentityDigest: identity.digest,
        policyTargetIdentityDigest: identity.digest,
        policyBindingDigest,
        findings: [
          {
            code: "synthetic-extra-field",
            severity: "warning",
            classification: "synthetic-redaction",
            hardGate: false,
            path: "/forbiddenRawField",
          },
        ],
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      document: {
        documentKind: "synthetic_invoice",
        invoiceNumber: "SYNTHETIC-001",
        issuedAt: "2026-01-01",
        currency: "JPY",
        lines: [],
        totalAmount: 0,
        forbiddenRawField: "SYNTHETIC-RAW-VALUE",
      },
    });
    const sanitizerSettings = {
      required: true,
      sanitizer,
      policyEnvelopeBytes: policyBytes,
      expectedSanitizerId: sanitizer.id,
      expectedProtocolVersion: sanitizer.protocolVersion,
      expectedPolicyVersion: 1,
      expectedPolicyDigest: policyDigest,
      expectedCaseInputIdentityVersion: 1,
      expectedCaseInputIdentityDigest: identity.digest,
      expectedPolicyBindingDigest: policyBindingDigest,
    } as const;
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      attemptKey: "dev-001",
      provider,
      sanitizer: sanitizerSettings,
    });
    const attempt = await readAttempt(result.attemptDirectory);
    const sanitizerManifest = attempt.manifest.sanitizer;
    assert.ok(sanitizerManifest);
    assert.equal(sanitizerManifest.applied, true);
    assert.deepEqual(sanitizerManifest.policyBindingIdentity, {
      caseInputIdentityDigest: identity.digest,
      policyVersion: 1,
      policyDigest,
    });
    assert.deepEqual(sanitizerManifest.findings, [
      {
        code: "synthetic-extra-field",
        severity: "warning",
        classification: "synthetic-redaction",
        hardGate: false,
        path: null,
      },
    ]);
    assert.equal(isJsonObject(attempt.document) && "forbiddenRawField" in attempt.document, false);
    const storedAttempt = Buffer.concat([
      await readFile(path.join(result.attemptDirectory, "attempt.json")),
      await readFile(path.join(result.attemptDirectory, "document.json")),
    ]).toString("utf8");
    assert.equal(storedAttempt.includes("SYNTHETIC-RAW-VALUE"), false);
    for (const stage of Object.values(attempt.manifest.stages)) {
      assert.deepEqual(stage, { status: "passed", errorCode: null });
    }
    const repeated = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      attemptKey: "dev-002",
      provider,
      sanitizer: sanitizerSettings,
    });
    const repeatedAttempt = await readAttempt(repeated.attemptDirectory);
    assert.equal(result.runId, repeated.runId);
    assert.notEqual(result.attemptId, repeated.attemptId);
    assert.deepEqual(attempt.manifest.inputs, repeatedAttempt.manifest.inputs);
    assert.equal(
      attempt.manifest.sanitizer?.policyBindingDigest,
      repeatedAttempt.manifest.sanitizer?.policyBindingDigest,
    );
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "throwing-sanitizer-attempts"),
        provider: createMockProvider(),
        sanitizer: {
          required: true,
          sanitizer: {
            id: "fake-sanitizer",
            protocolVersion: 1,
            sanitize: async () => {
              throw new RunnerError("sanitizer_response_invalid", "SYNTHETIC-SECRET-MARKER");
            },
          },
          policyEnvelopeBytes: policyBytes,
          expectedSanitizerId: "fake-sanitizer",
          expectedProtocolVersion: 1,
          expectedPolicyVersion: 1,
          expectedPolicyDigest: policyDigest,
          expectedCaseInputIdentityVersion: 1,
          expectedCaseInputIdentityDigest: identity.digest,
          expectedPolicyBindingDigest: policyBindingDigest,
        },
      }),
      (error: unknown) =>
        error instanceof RunnerError &&
        error.code === "sanitizer_failed" &&
        !error.message.includes("SYNTHETIC-SECRET-MARKER"),
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("requires every expected sanitizer identity before provider invocation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: identity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest,
  });
  const sanitizer: Sanitizer = {
    id: "fake-sanitizer",
    protocolVersion: 1,
    sanitize: async () => {
      throw new Error("synthetic sanitizer must not run");
    },
  };
  const complete: NonNullable<TestRunOptions["sanitizer"]> = {
    required: true,
    sanitizer,
    policyEnvelopeBytes: policyBytes,
    expectedSanitizerId: sanitizer.id,
    expectedProtocolVersion: sanitizer.protocolVersion,
    expectedPolicyVersion: 1,
    expectedPolicyDigest: policyDigest,
    expectedCaseInputIdentityVersion: 1,
    expectedCaseInputIdentityDigest: identity.digest,
    expectedPolicyBindingDigest: policyBindingDigest,
  };
  const fields = [
    "expectedSanitizerId",
    "expectedProtocolVersion",
    "expectedPolicyVersion",
    "expectedPolicyDigest",
    "expectedCaseInputIdentityVersion",
    "expectedCaseInputIdentityDigest",
    "expectedPolicyBindingDigest",
  ] as const;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    for (const field of fields) {
      const incomplete = { ...complete };
      delete incomplete[field];
      let providerCalls = 0;
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: path.join(temporary, `attempts-${field}`),
          provider: createMockProvider({ onInvoke: () => { providerCalls += 1; } }),
          sanitizerRequirement: syntheticRequirement(true),
          sanitizer: incomplete,
        }),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "sanitizer_configuration_invalid",
      );
      assert.equal(providerCalls, 0, `${field} must be checked before provider invocation`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects non-callable sanitizer implementations before provider input access", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: identity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest,
  });
  const throwingGetter = Object.defineProperty(
    { id: "fake-sanitizer", protocolVersion: 1 },
    "sanitize",
    {
      enumerable: true,
      get: () => {
        throw new Error("SYNTHETIC-SECRET-MARKER");
      },
    },
  );
  const invalidImplementations = [
    { id: "fake-sanitizer", protocolVersion: 1 },
    { id: "fake-sanitizer", protocolVersion: 1, sanitize: "synthetic-not-callable" },
    throwingGetter,
  ];
  let providerCalls = 0;
  let imageReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    for (const [index, implementation] of invalidImplementations.entries()) {
      const attemptRoot = path.join(temporary, `attempts-${index}`);
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot,
          provider: createMockProvider({
            onInvoke: () => {
              providerCalls += 1;
            },
            onImageRead: () => {
              imageReads += 1;
            },
          }),
          sanitizerRequirement: syntheticRequirement(true),
          sanitizer: {
            required: true,
            sanitizer: implementation as Sanitizer,
            policyEnvelopeBytes: policyBytes,
            expectedSanitizerId: "fake-sanitizer",
            expectedProtocolVersion: 1,
            expectedPolicyVersion: 1,
            expectedPolicyDigest: policyDigest,
            expectedCaseInputIdentityVersion: 1,
            expectedCaseInputIdentityDigest: identity.digest,
            expectedPolicyBindingDigest: policyBindingDigest,
          },
        }),
        (error: unknown) =>
          error instanceof RunnerError &&
          error.code === "sanitizer_configuration_invalid" &&
          error.message === "sanitizer implementation is invalid",
      );
      await assert.rejects(readdir(attemptRoot), /ENOENT/u);
    }
    assert.equal(providerCalls, 0);
    assert.equal(imageReads, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("uses the validated sanitizer snapshot after the original implementation is mutated", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: identity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest,
  });
  let sanitizerCalls = 0;
  const sanitizer: Sanitizer = {
    id: "snapshot-sanitizer",
    protocolVersion: 1,
    sanitize: async function () {
      assert.equal(this, sanitizer);
      sanitizerCalls += 1;
      return {
        sanitizedDocument: {
          documentKind: "synthetic_invoice",
          invoiceNumber: "SYNTHETIC-001",
          issuedAt: "2026-01-01",
          currency: "JPY",
          lines: [],
          totalAmount: 0,
        },
        sanitizerId: "snapshot-sanitizer",
        protocolVersion: 1,
        policyVersion: 1,
        policyDigest,
        caseInputIdentityVersion: 1,
        caseInputIdentityDigest: identity.digest,
        policyTargetIdentityDigest: identity.digest,
        policyBindingDigest,
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider({
        onInvoke: () => {
          const mutable = sanitizer as unknown as {
            id: string;
            protocolVersion: number;
            sanitize: Sanitizer["sanitize"];
          };
          mutable.id = "mutated-sanitizer";
          mutable.protocolVersion = 2;
          mutable.sanitize = async () => {
            throw new Error("mutated sanitizer must not run");
          };
        },
      }),
      sanitizerRequirement: syntheticRequirement(true),
      sanitizer: {
        required: true,
        sanitizer,
        policyEnvelopeBytes: policyBytes,
        expectedSanitizerId: "snapshot-sanitizer",
        expectedProtocolVersion: 1,
        expectedPolicyVersion: 1,
        expectedPolicyDigest: policyDigest,
        expectedCaseInputIdentityVersion: 1,
        expectedCaseInputIdentityDigest: identity.digest,
        expectedPolicyBindingDigest: policyBindingDigest,
      },
    });
    assert.equal(sanitizerCalls, 1);
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(attempt.manifest.sanitizer?.id, "snapshot-sanitizer");
    assert.equal(attempt.manifest.sanitizer?.protocolVersion, 1);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a sanitizer policy targeted at another case before provider invocation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const currentIdentity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const otherIdentity = computeCaseInputIdentity({
    caseId: "synthetic-other-case",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: otherIdentity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: currentIdentity.digest,
    policyVersion: 1,
    policyDigest,
  });
  let providerCalls = 0;
  let imageReads = 0;
  const sanitizer: Sanitizer = {
    id: "fake-sanitizer",
    protocolVersion: 1,
    sanitize: async () => {
      throw new Error("sanitizer must not run");
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        sanitizer: {
          required: true,
          sanitizer,
          policyEnvelopeBytes: policyBytes,
          expectedSanitizerId: sanitizer.id,
          expectedProtocolVersion: sanitizer.protocolVersion,
          expectedPolicyVersion: 1,
          expectedPolicyDigest: policyDigest,
          expectedCaseInputIdentityVersion: 1,
          expectedCaseInputIdentityDigest: currentIdentity.digest,
          expectedPolicyBindingDigest: policyBindingDigest,
        },
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "sanitizer_policy_target_mismatch",
    );
    assert.equal(providerCalls, 0);
    assert.equal(imageReads, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("parses provider JSON bytes strictly and leaves no attempt on invalid UTF-8", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const provider: Provider = {
    id: "raw-json-provider",
    route: "synthetic",
    invoke: async () => ({ rawDocument: Buffer.from([0xff, 0xfe]) }),
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "provider_response_invalid",
    );
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects an unsupported output schema before provider invocation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const schemaPath = path.join(bundle, "schema.json");
    const schema = JSON.parse(await readFile(schemaPath, "utf8")) as Record<string, unknown>;
    schema.unevaluatedProperties = false;
    const schemaBytes = Buffer.from(`${JSON.stringify(schema, null, 2)}\n`, "utf8");
    await writeFile(schemaPath, schemaBytes);
    const manifestPath = path.join(bundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      inputs: { schema: { sha256: string } };
    };
    manifest.inputs.schema.sha256 = createHash("sha256").update(schemaBytes).digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "attempts"),
        provider: createMockProvider({ onInvoke: () => { providerCalls += 1; } }),
      }),
      (error: unknown) =>
        error instanceof Error && "code" in error && error.code === "output_schema_invalid",
    );
    assert.equal(providerCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a deep shared schema route before provider invocation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    let leaf: JsonValue = { type: "string" };
    for (let index = 0; index < 55; index += 1) leaf = { not: leaf };
    let branch: JsonValue = { $ref: "#/$defs/leaf" };
    for (let index = 0; index < 10; index += 1) branch = { not: branch };
    const schema = { $defs: { leaf }, allOf: [branch] } satisfies JsonValue;
    const schemaBytes = Buffer.from(`${JSON.stringify(schema, null, 2)}\n`, "utf8");
    await writeFile(path.join(bundle, "schema.json"), schemaBytes);
    const manifestPath = path.join(bundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      inputs: { schema: { sha256: string } };
    };
    manifest.inputs.schema.sha256 = createHash("sha256").update(schemaBytes).digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: createMockProvider({ onInvoke: () => { providerCalls += 1; } }),
      }),
      (error: unknown) =>
        error instanceof Error && "code" in error && error.code === "output_schema_invalid",
    );
    assert.equal(providerCalls, 0);
    await assert.rejects(readFile(attempts), /ENOENT/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a schema-invalid provider document without a formal attempt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const provider: Provider = {
    id: "raw-json-provider",
    route: "synthetic",
    invoke: async () => ({ rawDocument: Buffer.from('{"documentKind":"synthetic_invoice"}\n', "utf8") }),
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "provider_document_schema_invalid",
    );
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("reader hashes the exact stored document bytes and rejects identity tampering", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    const documentPath = path.join(result.attemptDirectory, "document.json");
    const originalDocument = await readFile(documentPath);
    await writeFile(documentPath, Buffer.concat([originalDocument, Buffer.from(" \n", "utf8")]));
    await assert.rejects(
      readAttempt(result.attemptDirectory),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "attempt_document_digest_mismatch",
    );
    await writeFile(documentPath, originalDocument);
    const manifestPath = path.join(result.attemptDirectory, "attempt.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      caseInputIdentity: { digest: string };
    };
    manifest.caseInputIdentity.digest = "0".repeat(64);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      readAttempt(result.attemptDirectory),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("reader rejects attempt identity tampering and directory-name mismatch", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      attemptKey: "synthetic-reader",
      provider: createMockProvider(),
    });
    const manifestPath = path.join(result.attemptDirectory, "attempt.json");
    const originalManifest = await readFile(manifestPath);
    const manifest = JSON.parse(originalManifest.toString("utf8")) as {
      attemptKey: string;
      attemptId: string;
      runId: string;
    };

    for (const mutate of [
      () => { manifest.attemptKey = "synthetic-tampered"; },
      () => { manifest.attemptId = "0".repeat(64); },
      () => { manifest.runId = "1".repeat(64); },
    ]) {
      mutate();
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      await assert.rejects(
        readAttempt(result.attemptDirectory),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "attempt_identity_mismatch",
      );
      await writeFile(manifestPath, originalManifest);
      Object.assign(manifest, JSON.parse(originalManifest.toString("utf8")));
    }

    const movedDirectory = path.join(attempts, "f".repeat(64));
    await rename(result.attemptDirectory, movedDirectory);
    await assert.rejects(
      readAttempt(movedDirectory),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects extra attempt files and invalid timestamps", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    await writeFile(path.join(result.attemptDirectory, "raw-provider-output.txt"), "synthetic raw output");
    await assert.rejects(
      readAttempt(result.attemptDirectory),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "attempt_invalid",
    );
    await rm(path.join(result.attemptDirectory, "raw-provider-output.txt"));
    const manifestPath = path.join(result.attemptDirectory, "attempt.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      timing: { finishedAt: string };
    };
    manifest.timing.finishedAt = "2024-02-30T00:00:00Z";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      readAttempt(result.attemptDirectory),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "attempt_invalid",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("binds approval snapshot metadata into the run identity", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const snapshotDigest = "c".repeat(64);
  const runtimeBindingDigest = "d".repeat(64);
  const gate: ApprovalGate = {
    id: "identity-gate",
    protocolVersion: 1,
    approve: async () => ({
      responseVersion: 1,
      approved: true,
      gateId: "identity-gate",
      protocolVersion: 1,
      snapshotDigest,
      runtimeBindingDigest,
    }),
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
      approval: {
        required: true,
        gate,
        expectedGateId: "identity-gate",
        expectedProtocolVersion: 1,
        snapshotDigest,
        runtimeBindingDigest,
      },
    });
    const manifestPath = path.join(result.attemptDirectory, "attempt.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      approval: { snapshotDigest: string };
    };
    manifest.approval.snapshotDigest = "e".repeat(64);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      readAttempt(result.attemptDirectory),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects an attempt root inside the bundle", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  let providerCalls = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(bundle, "attempts"),
        provider: createMockProvider({ onInvoke: () => { providerCalls += 1; } }),
      }),
      (error: unknown) =>
        error instanceof Error && "code" in error && error.code === "attempt_root_invalid",
    );
    assert.equal(providerCalls, 0);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("publishes attempts with private directory and file permissions", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider(),
    });
    assert.equal((await stat(attempts)).mode & 0o777, 0o700);
    assert.equal((await stat(result.attemptDirectory)).mode & 0o777, 0o700);
    assert.equal((await stat(path.join(result.attemptDirectory, "attempt.json"))).mode & 0o777, 0o600);
    assert.equal((await stat(path.join(result.attemptDirectory, "document.json"))).mode & 0o777, 0o600);
    assert.deepEqual((await readdir(result.attemptDirectory)).sort(), ["attempt.json", "document.json"]);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not treat pending or manifestless claim directories as formal attempts", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const pending = path.join(temporary, "pending");
  const manifestless = path.join(temporary, "manifestless");
  try {
    await mkdir(pending, { mode: 0o700 });
    await writeFile(path.join(pending, ".attempt-owner.pending"), `${"0".repeat(36)}\n`, {
      mode: 0o600,
    });
    await writeFile(path.join(pending, "document.json"), "{}\n", { mode: 0o600 });
    await writeFile(path.join(pending, "attempt.json.pending"), "{}\n", { mode: 0o600 });
    await assert.rejects(
      readAttempt(pending),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_invalid",
    );

    await mkdir(manifestless, { mode: 0o700 });
    await writeFile(path.join(manifestless, "document.json"), "{}\n", { mode: 0o600 });
    await assert.rejects(
      readAttempt(manifestless),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_invalid",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a FIFO attempt manifest without blocking", async () => {
  if (process.platform === "win32") return;
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const attemptDirectory = path.join(temporary, "attempt");
  const fifo = path.join(attemptDirectory, "attempt.json");
  try {
    await mkdir(attemptDirectory, { mode: 0o700 });
    const maker = spawn("mkfifo", [fifo], { stdio: "ignore" });
    const [makerCode] = (await once(maker, "close")) as [number | null];
    assert.equal(makerCode, 0);
    await writeFile(path.join(attemptDirectory, "document.json"), "{}\n", { mode: 0o600 });
    const script = [
      `import { readAttempt } from ${JSON.stringify(path.resolve(".tmp/build/src/runner/attempt.js"))};`,
      "try { await readAttempt(process.argv[1]); process.exitCode = 0; } catch { process.exitCode = 1; }",
    ].join("\n");
    const child = spawn(process.execPath, ["--input-type=module", "-e", script, attemptDirectory], {
      stdio: "ignore",
    });
    const closePromise = once(child, "close");
    const finishedBeforeTimeout = await Promise.race([
      closePromise.then(() => true),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 250)),
    ]);
    if (!finishedBeforeTimeout) {
      child.kill("SIGTERM");
      await closePromise;
    }
    assert.equal(finishedBeforeTimeout, true);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("records a matching approval result before invoking the provider", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const snapshotDigest = "c".repeat(64);
  const runtimeBindingDigest = "d".repeat(64);
  let providerCalls = 0;
  const gate: ApprovalGate = {
    id: "fake-gate",
    protocolVersion: 1,
    approve: async (request) => {
      assert.equal(request.gateId, "fake-gate");
      assert.equal(request.snapshotDigest, snapshotDigest);
      assert.equal(request.runtimeBindingDigest, runtimeBindingDigest);
      assert.equal("caseId" in request, false);
      return {
        responseVersion: 1,
        approved: true,
        gateId: "fake-gate",
        protocolVersion: 1,
        snapshotDigest,
        runtimeBindingDigest,
      };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
    });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider,
      approval: {
        required: true,
        gate,
        expectedGateId: "fake-gate",
        expectedProtocolVersion: 1,
        snapshotDigest,
        runtimeBindingDigest,
      },
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(providerCalls, 1);
    assert.equal(attempt.manifest.approval.required, true);
    assert.equal(attempt.manifest.approval.applied, true);
    assert.equal(attempt.manifest.approval.snapshotDigest, snapshotDigest);
    assert.equal(attempt.manifest.approval.runtimeBindingDigest, runtimeBindingDigest);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("times out a provider using the configured timeout without writing an attempt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerSignal: AbortSignal | undefined;
  const provider: Provider = {
    id: "hanging-provider",
    route: "synthetic",
    invoke: async (_request, _context, signal) => {
      providerSignal = signal;
      return new Promise(() => undefined);
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        providerTimeoutMs: 5,
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "provider_timeout",
    );
    assert.equal(providerSignal?.aborted, true);
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("invalidates provider reads after a timeout even if the provider continues", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let lateReadRejected = false;
  const provider: Provider = {
    id: "late-provider",
    route: "synthetic",
    invoke: async (request) => {
      await new Promise((resolve) => setTimeout(resolve, 25));
      try {
        await request.image.readBytes();
      } catch {
        lateReadRejected = true;
      }
      return { rawDocument: null };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        providerTimeoutMs: 5,
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "provider_timeout",
    );
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(lateReadRejected, true);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("claims an attempt directory before invoking a concurrent provider", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const document = {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-001",
    issuedAt: "2026-01-01",
    currency: "JPY",
    lines: [],
    totalAmount: 0,
  };
  let providerCalls = 0;
  let releaseFirst = () => {};
  let firstStartedResolve!: () => void;
  const firstStarted = new Promise<void>((resolve) => {
    firstStartedResolve = resolve;
  });
  const provider: Provider = {
    id: "race-provider",
    route: "synthetic",
    invoke: async () => {
      providerCalls += 1;
      if (providerCalls !== 1) throw new Error("synthetic second provider invocation");
      firstStartedResolve();
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
      return { rawDocument: document };
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const firstRun = runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider });
    await firstStarted;
    await assert.rejects(
      runBundle({ bundleDirectory: bundle, attemptRoot: attempts, provider }),
      (error: unknown) => error instanceof RunnerError && error.code === "attempt_exists",
    );
    assert.equal(providerCalls, 1);
    releaseFirst();
    const first = await firstRun;
    assert.deepEqual((await readdir(first.attemptDirectory)).sort(), ["attempt.json", "document.json"]);
  } finally {
    releaseFirst();
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not let concurrent runs delete each other's staging files", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  const provider = createMockProvider({
    onInvoke: async () => {
      providerCalls += 1;
      await new Promise((resolve) => setTimeout(resolve, 15));
    },
  });
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const runs = [
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        requestedModel: "synthetic-model-a",
      }),
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        requestedModel: "synthetic-model-b",
      }),
    ];
    const results = await Promise.all(runs);
    assert.equal(providerCalls, 2);
    assert.notEqual(results[0]!.runId, results[1]!.runId);
    for (const result of results) {
      assert.deepEqual((await readdir(result.attemptDirectory)).sort(), [
        "attempt.json",
        "document.json",
      ]);
      await readAttempt(result.attemptDirectory);
    }
    const entries = (await readdir(attempts)).sort();
    assert.deepEqual(entries, results.map((result) => result.attemptId).sort());
    assert.equal(entries.some((entry) => entry.startsWith(".claim-")), false);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a required sanitizer policy before provider input is read", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  let providerCalls = 0;
  let imageReads = 0;
  const sanitizer: Sanitizer = {
    id: "fake-sanitizer",
    protocolVersion: 1,
    sanitize: async () => {
      throw new Error("sanitizer must not run");
    },
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
      onImageRead: () => {
        imageReads += 1;
      },
    });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        sanitizer: { required: true, sanitizer },
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "sanitizer_configuration_invalid",
    );
    assert.equal(providerCalls, 0);
    assert.equal(imageReads, 0);
    await assert.rejects(readdir(attempts));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects a sanitizer response binding change without a formal attempt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-invoice-basic",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
  });
  const policyBytes = createSanitizerPolicyEnvelope({
    target: identity,
    policyVersion: 1,
    policy: { syntheticRule: "remove-extra-fields" },
  });
  const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest,
  });
  let providerCalls = 0;
  const sanitizer: Sanitizer = {
    id: "fake-sanitizer",
    protocolVersion: 1,
    sanitize: async () => ({
      sanitizedDocument: {
        documentKind: "synthetic_invoice",
        invoiceNumber: "SYNTHETIC-001",
        issuedAt: "2026-01-01",
        currency: "JPY",
        lines: [],
        totalAmount: 0,
      },
      sanitizerId: "fake-sanitizer",
      protocolVersion: 1,
      policyVersion: 1,
      policyDigest,
      caseInputIdentityVersion: 1,
      caseInputIdentityDigest: identity.digest,
      policyTargetIdentityDigest: identity.digest,
      policyBindingDigest: "e".repeat(64),
    }),
  };
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const provider = createMockProvider({
      onInvoke: () => {
        providerCalls += 1;
      },
    });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        sanitizer: {
          required: true,
          sanitizer,
          policyEnvelopeBytes: policyBytes,
          expectedSanitizerId: sanitizer.id,
          expectedProtocolVersion: sanitizer.protocolVersion,
          expectedPolicyVersion: 1,
          expectedPolicyDigest: policyDigest,
          expectedCaseInputIdentityVersion: 1,
          expectedCaseInputIdentityDigest: identity.digest,
          expectedPolicyBindingDigest: policyBindingDigest,
        },
      }),
      (error: unknown) =>
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "sanitizer_response_invalid",
    );
    assert.equal(providerCalls, 1);
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
