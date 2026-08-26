import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { decodeUtf8Strict, isJsonObject, parseJson } from "../src/bundle/json.js";
import { validateJsonSchema } from "../src/bundle/schema-validator.js";
import { createMockProvider } from "../src/provider/mock.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  computeRunIdentity,
} from "../src/runner/identity.js";
import { readAttempt } from "../src/runner/attempt.js";
import { loadBundleForRunner } from "../src/runner/load-bundle.js";
import { runBundle } from "../src/runner/run.js";
import {
  createSanitizerPolicyEnvelope,
  type Sanitizer,
} from "../src/runner/sanitizer.js";
import type { ApprovalGate, Provider } from "../src/runner/types.js";

const IMAGE_SHA256 = "dda43d98857bc0977a1bdc67e8005428c3af95ca73cddda69c9e8737eee03cc9";
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

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
});

test("stages verified provider inputs away from the mutable bundle", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-runner-"));
  const bundle = path.join(temporary, "bundle");
  const staging = path.join(temporary, "staging");
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
      assert.equal(await loaded.inputs.system.readText(), await readFile(path.join(bundle, "system.txt"), "utf8"));
      const stagedImage = await loaded.inputs.image.readBytes();

      await writeFile(path.join(bundle, "prepared-image.png"), Buffer.from("synthetic replacement"));
      assert.deepEqual(await loaded.inputs.image.readBytes(), stagedImage);
      assert.equal(loaded.inputs.schema.value !== null, true);
    } finally {
      await loaded.cleanup();
    }
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
      onRequest: (request) => {
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
    assert.match(result.attemptId, /^[a-f0-9]{64}$/u);
    assert.equal(imageReads, 1);
    assert.ok(capturedRequest);
    assert.equal(capturedRequest!.caseId, undefined);
    assert.equal(capturedRequest!.truth, undefined);
    assert.equal(capturedRequest!.comparison, undefined);
    assert.equal(capturedRequest!.bundleRoot, undefined);

    const attempt = await readAttempt(result.attemptDirectory);
    const attemptSchema = parseJson(
      decodeUtf8Strict(await readFile("schemas/attempt-v1.schema.json"), "attempt schema"),
      "attempt schema",
    );
    assert.deepEqual(validateJsonSchema(attemptSchema, attempt.manifest), []);
    assert.equal(attempt.manifest.attemptVersion, 1);
    assert.equal(attempt.manifest.caseId, "synthetic-invoice-basic");
    assert.equal(attempt.manifest.run.requested.model, "mock-v1");
    assert.equal(attempt.manifest.run.requested.effort, "medium");
    assert.equal(attempt.manifest.run.requested.maxTokens, 512);
    assert.equal(attempt.manifest.sanitizer.applied, false);
    assert.equal(attempt.manifest.approval.applied, false);
    assert.equal(attempt.manifest.document.path, "document.json");
    assert.equal(isJsonObject(attempt.document), true);
    if (isJsonObject(attempt.document)) {
      assert.equal(attempt.document.documentKind, "synthetic_invoice");
    }
    assert.equal(await readFile(path.join(result.attemptDirectory, "attempt.json"), "utf8") !== "", true);
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
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider,
      sanitizer: {
        required: true,
        sanitizer,
        policyEnvelopeBytes: policyBytes,
        expectedPolicyVersion: 1,
        expectedPolicyDigest: policyDigest,
        expectedCaseInputIdentityDigest: identity.digest,
        expectedPolicyBindingDigest: policyBindingDigest,
      },
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(attempt.manifest.sanitizer.applied, true);
    assert.deepEqual(attempt.manifest.sanitizer.policyBindingIdentity, {
      caseInputIdentityDigest: identity.digest,
      policyVersion: 1,
      policyDigest,
    });
    assert.deepEqual(attempt.manifest.sanitizer.findings, [
      {
        code: "synthetic-extra-field",
        severity: "warning",
        classification: "synthetic-redaction",
        hardGate: false,
        path: "/forbiddenRawField",
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
          expectedPolicyVersion: 1,
          expectedPolicyDigest: policyDigest,
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
        error.code === "sanitizer_policy_missing",
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
          expectedPolicyVersion: 1,
          expectedPolicyDigest: policyDigest,
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
