import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadBundleForRunner } from "../src/bundle/validate-bundle.js";
import {
  COMMAND_PROVIDER_PROTOCOL_VERSION,
  createCommandProvider,
} from "../src/provider/command.js";
import { readAttempt, type AttemptManifest } from "../src/runner/attempt.js";
import { RunnerError } from "../src/runner/errors.js";
import {
  computeAttemptIdentity,
  computeCaseInputIdentity,
  computeRunIdentity,
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../src/runner/identity.js";
import { runBundle } from "../src/runner/run.js";
import type {
  ApprovalGate,
  ApprovalRequest,
  ApprovalResponse,
  ApprovalSettings,
  ProviderAdapterContext,
  ProviderModelRequest,
} from "../src/runner/types.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const FAKE_COMMAND_PROVIDER = path.resolve("test/fixtures/fake-command-provider.mjs");
const PHASE = "development";

test("validates command provider configuration at the public factory boundary", () => {
  assert.throws(
    () =>
      createCommandProvider({
        executable: "./synthetic-provider",
        providerId: "synthetic-command",
        route: "local-command",
        implementationVersion: "synthetic-v1",
      }),
    (error: unknown) => error instanceof RunnerError && error.code === "provider_invalid",
  );
  assert.throws(
    () =>
      createCommandProvider({
        executable: process.execPath,
        argv: "synthetic-invalid" as never,
        providerId: "synthetic-command",
        route: "local-command",
        implementationVersion: "synthetic-v1",
      }),
    (error: unknown) => error instanceof RunnerError && error.code === "provider_invalid",
  );
  const hostile = {} as Parameters<typeof createCommandProvider>[0];
  Object.defineProperty(hostile, "executable", {
    enumerable: true,
    get: () => {
      throw new Error("synthetic getter failure");
    },
  });
  assert.throws(
    () => createCommandProvider(hostile),
    (error: unknown) =>
      error instanceof RunnerError &&
      error.code === "provider_invalid" &&
      !error.message.includes("getter"),
  );
  for (const envAllowlist of [
    ["svbench_command_request_directory"],
    ["Svbench_Command_Operation"],
    ["PATH", "Path"],
  ]) {
    assert.throws(
      () =>
        createCommandProvider({
          executable: process.execPath,
          argv: [FAKE_COMMAND_PROVIDER, "success"],
          envAllowlist,
          providerId: "synthetic-command",
          route: "local-command",
          implementationVersion: "synthetic-v1",
        }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_invalid",
    );
  }
});

test("uses the snapshotted command configuration after source mutation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  let argvReads = 0;
  let envReads = 0;
  const argv = [] as string[];
  Object.defineProperty(argv, "0", {
    enumerable: true,
    get: () => {
      argvReads += 1;
      return argvReads === 1 ? FAKE_COMMAND_PROVIDER : "synthetic-replacement";
    },
  });
  Object.defineProperty(argv, "1", {
    enumerable: true,
    get: () => "success",
  });
  argv.length = 2;
  const envAllowlist = [] as string[];
  Object.defineProperty(envAllowlist, "0", {
    enumerable: true,
    get: () => {
      envReads += 1;
      return envReads === 1 ? "SYNTHETIC_COMMAND_ALLOWED" : "SYNTHETIC_REPLACEMENT";
    },
  });
  envAllowlist.length = 1;
  const options = {
    executable: process.execPath,
    argv,
    envAllowlist,
    providerId: "synthetic-command",
    route: "local-command",
    implementationVersion: "synthetic-v1",
  };
  const provider = createCommandProvider(options);
  options.providerId = "synthetic-mutated";
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider,
      phase: PHASE,
      sanitizerRequirement: syntheticRequirement(),
    });
    assert.equal((await readAttempt(result.attemptDirectory)).manifest.run.providerId, "synthetic-command");
    assert.equal(argvReads, 1);
    assert.equal(envReads, 1);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects denied and expired approvals at the public invoke boundary", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-operation-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  let inputReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_MARKER = marker;
    const requirement = syntheticRequirement();
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
      },
    );
    try {
      const provider = commandProvider("success", {
        envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
      });
      let approvedReads = 0;
      const hostileApproval = directApprovalResponse(requirement);
      Object.defineProperty(hostileApproval, "approved", {
        enumerable: true,
        get: () => {
          approvedReads += 1;
          return approvedReads === 1 ? false : true;
        },
      });
      for (const approval of [
        directApprovalResponse(requirement, {
          approved: false,
          reasonCode: "synthetic_denied",
        }),
        directApprovalResponse(requirement, {
          expiresAt: "2000-01-01T00:00:00Z",
        }),
        hostileApproval,
      ]) {
        await assert.rejects(
          provider.invoke(direct.request, { ...direct.context, approval }),
          /command provider failed/u,
        );
      }
      let contextApprovalReads = 0;
      const hostileContext = { ...direct.context };
      Object.defineProperty(hostileContext, "approval", {
        enumerable: true,
        get: () => {
          contextApprovalReads += 1;
          return contextApprovalReads === 1
            ? directApprovalResponse(requirement, { approved: false })
            : directApprovalResponse(requirement);
        },
      });
      await assert.rejects(
        provider.invoke(direct.request, hostileContext),
        /command provider failed/u,
      );
      assert.equal(inputReads, 0);
      assert.equal(approvedReads, 1);
      assert.equal(contextApprovalReads, 1);
      await assert.rejects(readFile(marker), /ENOENT/u);
    } finally {
      await direct.cleanup();
    }
  } finally {
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("stops direct input access when approval expires during a callback", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-operation-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  const originalNow = Date.now;
  const activeTime = Date.parse("2098-01-01T00:00:00Z");
  const expiredTime = Date.parse("2100-01-01T00:00:00Z");
  let expired = false;
  let inputReads = 0;
  let callbackBuffer: Buffer | undefined;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_MARKER = marker;
    Date.now = () => (expired ? expiredTime : activeTime);
    const requirement = syntheticRequirement();
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
      },
    );
    const readImage = direct.request.image.readBytes;
    direct.request.image.readBytes = async () => {
      callbackBuffer = await readImage();
      expired = true;
      return callbackBuffer;
    };
    try {
      await assert.rejects(
        commandProvider("success", {
          envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
        }).invoke(direct.request, {
          ...direct.context,
          approval: directApprovalResponse(requirement),
        }),
        /command provider failed/u,
      );
      assert.equal(inputReads, 1);
      assert.ok(callbackBuffer !== undefined);
      assert.ok(callbackBuffer.every((byte) => byte === 0));
      await assert.rejects(readFile(marker), /ENOENT/u);
    } finally {
      await direct.cleanup();
    }
  } finally {
    Date.now = originalNow;
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("aborts a pending direct input callback and disposes its late buffer", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-operation-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  let resolveCallback!: (value: Buffer) => void;
  let callbackStartedResolve!: () => void;
  const callbackStarted = new Promise<void>((resolve) => {
    callbackStartedResolve = resolve;
  });
  const lateBuffer = Buffer.from("synthetic late input", "utf8");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_MARKER = marker;
    const requirement = syntheticRequirement();
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => undefined,
    );
    direct.request.image.readBytes = () =>
      new Promise<Buffer>((resolve) => {
        resolveCallback = resolve;
        callbackStartedResolve();
      });
    const controller = new AbortController();
    try {
      const invocation = commandProvider("success", {
        envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
      }).invoke(direct.request, direct.context, controller.signal);
      await callbackStarted;
      controller.abort();
      await settlesWithin(
        assert.rejects(invocation, /command provider failed/u),
        250,
      );
      resolveCallback(lateBuffer);
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.ok(lateBuffer.every((byte) => byte === 0));
      await assert.rejects(readFile(marker), /ENOENT/u);
    } finally {
      await direct.cleanup();
    }
  } finally {
    lateBuffer.fill(0);
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("uses one approval snapshot when direct invoke callbacks mutate the source", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  let inputReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const approval = directApprovalResponse(requirement);
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
        approval.approved = false;
      },
    );
    try {
      const response = await commandProvider("success").invoke(direct.request, {
        ...direct.context,
        approval,
      });
      assert.equal(inputReads, 4);
      assert.equal(approval.approved, false);
      assert.equal(response.approval?.approved, true);
    } finally {
      await direct.cleanup();
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("uses the approved phase snapshot after direct invoke callback mutation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  let inputReads = 0;
  let mutableContext: ProviderAdapterContext | undefined;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
        if (mutableContext !== undefined) mutableContext.phase = "synthetic-other-phase";
      },
    );
    mutableContext = {
      ...direct.context,
      approval: directApprovalResponse(requirement),
    };
    try {
      const response = await commandProvider("echo-phase").invoke(
        direct.request,
        mutableContext,
      );
      assert.equal(inputReads, 4);
      assert.equal(mutableContext.phase, "synthetic-other-phase");
      assert.equal(
        (response.rawDocument as { syntheticPhase?: unknown }).syntheticPhase,
        PHASE,
      );
      assert.equal(response.approval?.phase, PHASE);
    } finally {
      await direct.cleanup();
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("uses one immutable request and context snapshot after direct callback mutation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  let inputReads = 0;
  let mutableRequest: ProviderModelRequest | undefined;
  let mutableContext: ProviderAdapterContext | undefined;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
        if (mutableRequest !== undefined && mutableContext !== undefined) {
          mutableRequest.requested.model = "synthetic-model-b";
          mutableContext.caseId = "synthetic-mutated-case";
          mutableContext.provenance.harnessVersion = "synthetic-mutated-harness";
        }
      },
    );
    mutableRequest = direct.request;
    mutableContext = direct.context;
    mutableRequest.requested.model = "synthetic-model-a";
    try {
      const response = await commandProvider("echo-contract").invoke(
        mutableRequest,
        mutableContext,
      );
      const document = response.rawDocument as Record<string, unknown>;
      assert.equal(inputReads, 4);
      assert.equal(mutableRequest.requested.model, "synthetic-model-b");
      assert.equal(mutableContext.caseId, "synthetic-mutated-case");
      assert.equal(
        mutableContext.provenance.harnessVersion,
        "synthetic-mutated-harness",
      );
      assert.equal(document.syntheticRequestedModel, "synthetic-model-a");
      assert.equal(document.syntheticCaseId, direct.context.caseInputIdentity.caseId);
      assert.equal(document.syntheticHarnessVersion, "synthetic-harness");
      assert.equal(response.respondedModel, "synthetic-model-a");
    } finally {
      await direct.cleanup();
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("snapshots required sanitizer decisions before direct invoke input access", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-operation-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  let inputReads = 0;
  let requiredReads = 0;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_MARKER = marker;
    const requirement = syntheticRequirement(true);
    const direct = await directInvocation(
      bundle,
      path.join(temporary, "staging"),
      requirement,
      () => {
        inputReads += 1;
      },
    );
    const hostileRequirement = { ...requirement.decision };
    Object.defineProperty(hostileRequirement, "sanitizerRequired", {
      enumerable: true,
      get: () => {
        requiredReads += 1;
        return requiredReads === 1;
      },
    });
    try {
      await assert.rejects(
        commandProvider("success", {
          envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
        }).invoke(direct.request, {
          ...direct.context,
          sanitizerRequirement: hostileRequirement,
        }),
        /command provider failed/u,
      );
      assert.equal(requiredReads, 1);
      assert.equal(inputReads, 0);
      await assert.rejects(readFile(marker), /ENOENT/u);
    } finally {
      await direct.cleanup();
    }
  } finally {
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs a policy-free command provider through a private five-file request directory", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider: commandProvider("success"),
      phase: PHASE,
      requestedModel: "synthetic-model",
      requestedEffort: "medium",
      maxTokens: 512,
      sanitizerRequirement: syntheticRequirement(),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(attempt.manifest.run.phase, PHASE);
    assert.equal(attempt.manifest.run.providerId, "synthetic-command");
    assert.equal(attempt.manifest.run.route, "local-command");
    assert.equal(attempt.manifest.run.implementationVersion, "synthetic-v1");
    assert.equal(attempt.manifest.run.protocolVersion, COMMAND_PROVIDER_PROTOCOL_VERSION);
    assert.equal(attempt.manifest.run.responded.model, "synthetic-model");
    assert.equal(attempt.manifest.run.responded.effort, "medium");
    assert.equal(attempt.manifest.approval.applied, false);
    assert.equal(attempt.manifest.sanitizer, undefined);
    assert.equal(
      JSON.stringify(attempt.manifest).includes("fake-command-provider"),
      false,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("preserves optional cache usage from a command provider in the formal attempt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider: commandProvider("cache-usage"),
      sanitizerRequirement: syntheticRequirement(),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.deepEqual(attempt.manifest.run.responded.usage, {
      available: true,
      inputTokens: 23,
      cachedInputTokens: 13,
      cacheWriteInputTokens: 4,
      outputTokens: 8,
      totalTokens: 31,
    });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not inherit cache usage omitted by a command provider", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const inheritedCachedInput = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "cachedInputTokens",
  );
  const inheritedCacheWriteInput = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "cacheWriteInputTokens",
  );
  try {
    Object.defineProperty(Object.prototype, "cachedInputTokens", {
      configurable: true,
      value: 9,
      writable: true,
    });
    Object.defineProperty(Object.prototype, "cacheWriteInputTokens", {
      configurable: true,
      value: 4,
      writable: true,
    });
    await cp(FIXTURE, bundle, { recursive: true });
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider: commandProvider("usage-without-cache"),
      sanitizerRequirement: syntheticRequirement(),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.deepEqual(attempt.manifest.run.responded.usage, {
      available: true,
      inputTokens: 23,
      outputTokens: 8,
      totalTokens: 31,
    });
  } finally {
    if (inheritedCachedInput === undefined) {
      delete (Object.prototype as { cachedInputTokens?: unknown }).cachedInputTokens;
    } else {
      Object.defineProperty(Object.prototype, "cachedInputTokens", inheritedCachedInput);
    }
    if (inheritedCacheWriteInput === undefined) {
      delete (Object.prototype as { cacheWriteInputTokens?: unknown })
        .cacheWriteInputTokens;
    } else {
      Object.defineProperty(
        Object.prototype,
        "cacheWriteInputTokens",
        inheritedCacheWriteInput,
      );
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("binds command responses to phase, input identity, requirement, and approval", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const approval = approvalSettings(requirement);
    const accepted = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "accepted"),
      provider: commandProvider("success"),
      phase: PHASE,
      approval,
      sanitizerRequirement: requirement,
    });
    assert.equal((await readAttempt(accepted.attemptDirectory)).manifest.approval.applied, true);

    for (const [index, mode] of [
      "phase-mismatch",
      "requested-mismatch",
      "identity-mismatch",
      "requirement-mismatch",
      "approval-missing",
      "approval-mismatch",
      "unknown-field",
    ].entries()) {
      const attempts = path.join(temporary, `rejected-${index}`);
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: attempts,
          provider: commandProvider(mode),
          phase: PHASE,
          approval,
          sanitizerRequirement: requirement,
        }),
        (error: unknown) => error instanceof RunnerError && error.code === "provider_failed",
      );
      assert.deepEqual(await readdir(attempts), []);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("requires both adapter transport attestations before input access", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const mismatches = [
      { mode: "transport-mismatch", expectedCode: "approval_response_invalid" },
      { mode: "inline-transport-mismatch", expectedCode: "provider_failed" },
      { mode: "inline-working-file", expectedCode: "provider_failed" },
    ];
    for (const [index, mismatch] of mismatches.entries()) {
      const attempts = path.join(temporary, `attempts-${index}`);
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: attempts,
          provider: commandProvider(mismatch.mode),
          phase: PHASE,
          approval: approvalSettings(requirement),
          sanitizerRequirement: requirement,
        }),
        (error: unknown) =>
          error instanceof RunnerError && error.code === mismatch.expectedCode,
      );
      assert.deepEqual(await readdir(attempts), []);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("isolates every transport reattestation from materialized request files", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const approval = approvalSettings(requirement);
    for (const [index, mode] of [
      "transport-sibling-read",
      "transport-sibling-write",
    ].entries()) {
      const result = await runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, `attempts-${index}`),
        provider: commandProvider(mode),
        phase: PHASE,
        approval,
        sanitizerRequirement: requirement,
      });
      await readAttempt(result.attemptDirectory);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("reattests and releases approved input to the same adapter process", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-handshake-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER = marker;
    const requirement = syntheticRequirement();
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider: commandProvider("success", {
        envAllowlist: ["SYNTHETIC_COMMAND_HANDSHAKE_MARKER"],
      }),
      phase: PHASE,
      approval: approvalSettings(requirement),
      sanitizerRequirement: requirement,
    });
    await readAttempt(result.attemptDirectory);
    const lines = (await readFile(marker, "utf8")).trim().split("\n");
    assert.equal(lines.length, 2);
    const reattestPid = lines[0]?.match(/^reattest:(\d+)$/u)?.[1];
    const invokePid = lines[1]?.match(/^invoke:(\d+)$/u)?.[1];
    assert.notEqual(reattestPid, undefined);
    assert.equal(invokePid, reattestPid);
  } finally {
    if (previousMarker === undefined) {
      delete process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER;
    } else {
      process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER = previousMarker;
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("settles request materialization before cleanup when inline reattestation exits", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const isolatedTemporaryRoot = path.join(temporary, "command-tmp");
  const previousTmpdir = process.env.TMPDIR;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await mkdir(isolatedTemporaryRoot, { mode: 0o700 });
    process.env.TMPDIR = isolatedTemporaryRoot;
    assert.equal(os.tmpdir(), isolatedTemporaryRoot);
    const requirement = syntheticRequirement();
    const attempts = path.join(temporary, "attempts");
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: commandProvider("inline-exit-after-attestation"),
        phase: PHASE,
        approval: approvalSettings(requirement),
        sanitizerRequirement: requirement,
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.deepEqual(await readdir(attempts), []);
    assert.deepEqual(await readdir(isolatedTemporaryRoot), []);
  } finally {
    if (previousTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpdir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test(
  "detects attesting child exit before path release despite inherited stdio",
  { skip: process.platform === "win32" },
  async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const isolatedTemporaryRoot = path.join(temporary, "command-tmp");
  const observedMarker = path.join(temporary, "synthetic-request-observed");
  const handshakeMarker = path.join(temporary, "synthetic-handshake-marker");
  const previousTmpdir = process.env.TMPDIR;
  const previousObservedMarker =
    process.env.SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER;
  const previousHandshakeMarker = process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await mkdir(isolatedTemporaryRoot, { mode: 0o700 });
    process.env.TMPDIR = isolatedTemporaryRoot;
    process.env.SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER = observedMarker;
    process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER = handshakeMarker;
    assert.equal(os.tmpdir(), isolatedTemporaryRoot);
    const requirement = syntheticRequirement();
    const attempts = path.join(temporary, "attempts");
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider: commandProvider("inline-exit-with-inherited-descendant", {
          envAllowlist: [
            "SYNTHETIC_COMMAND_HANDSHAKE_MARKER",
            "SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER",
          ],
        }),
        phase: PHASE,
        approval: approvalSettings(requirement),
        sanitizerRequirement: requirement,
      }),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.equal(await readFile(observedMarker, "utf8"), "synthetic helper ready\n");
    assert.match(await readFile(handshakeMarker, "utf8"), /^reattest:\d+\n$/u);
    assert.deepEqual(await readdir(attempts), []);
    assert.deepEqual(await readdir(isolatedTemporaryRoot), []);
  } finally {
    if (previousTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpdir;
    if (previousObservedMarker === undefined) {
      delete process.env.SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER;
    } else {
      process.env.SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER =
        previousObservedMarker;
    }
    if (previousHandshakeMarker === undefined) {
      delete process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER;
    } else {
      process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER = previousHandshakeMarker;
    }
    await rm(temporary, { recursive: true, force: true });
  }
  },
);

test("rechecks approval expiry after local staging and before adapter spawn", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-operation-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  const originalNow = Date.now;
  let finalInputRead = false;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    process.env.SYNTHETIC_COMMAND_MARKER = marker;
    const base = commandProvider("success", {
      envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
    });
    const provider = {
      ...base,
      invoke: async (...args: Parameters<typeof base.invoke>) => {
        const [request, context, signal] = args;
        return base.invoke(
          {
            ...request,
            instruction: {
              ...request.instruction,
              readText: async () => {
                const value = await request.instruction.readText();
                finalInputRead = true;
                return value;
              },
            },
          },
          context,
          signal,
        );
      },
    };
    const activeTime = Date.parse("2098-01-01T00:00:00Z");
    const expiredTime = Date.parse("2100-01-01T00:00:00Z");
    Date.now = () => (finalInputRead ? expiredTime : activeTime);
    const requirement = syntheticRequirement();
    const attempts = path.join(temporary, "attempts");
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: attempts,
        provider,
        phase: PHASE,
        approval: approvalSettings(requirement),
        sanitizerRequirement: requirement,
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.equal(finalInputRead, true);
    assert.equal(await readFile(marker, "utf8"), "prepare-transport\n");
    assert.deepEqual(await readdir(attempts), []);
  } finally {
    Date.now = originalNow;
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("fails closed on command process, output, and timeout failures", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    for (const [index, mode] of [
      "nonzero",
      "invalid-json",
      "duplicate-json",
      "huge-output",
      "stderr-overflow",
    ].entries()) {
      const attempts = path.join(temporary, `failed-${index}`);
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: attempts,
          provider: commandProvider(mode, { outputLimitBytes: 1024 }),
          phase: PHASE,
          sanitizerRequirement: syntheticRequirement(),
        }),
        (error: unknown) =>
          error instanceof RunnerError &&
          error.code === "provider_failed" &&
          !error.message.includes(temporary),
      );
      assert.deepEqual(await readdir(attempts), []);
    }
    const timeoutAttempts = path.join(temporary, "timeout");
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: timeoutAttempts,
        provider: commandProvider("hang"),
        phase: PHASE,
        providerTimeoutMs: 25,
        sanitizerRequirement: syntheticRequirement(),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_timeout",
    );
    assert.deepEqual(await readdir(timeoutAttempts), []);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("kills descendant processes and finishes private cleanup before timeout returns", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const privateTemporaryRoot = path.join(temporary, "private-temp");
  const descendantMarker = path.join(temporary, "synthetic-descendant-pid");
  const previousTmpdir = process.env.TMPDIR;
  const previousMarker = process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER;
  await mkdir(privateTemporaryRoot, { mode: 0o700 });
  process.env.TMPDIR = privateTemporaryRoot;
  process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER = descendantMarker;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "attempts"),
        provider: commandProvider("descendant-hang", {
          envAllowlist: ["SYNTHETIC_COMMAND_DESCENDANT_MARKER"],
        }),
        phase: PHASE,
        providerTimeoutMs: 1_000,
        sanitizerRequirement: syntheticRequirement(),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_timeout",
    );
    assert.deepEqual(await readdir(privateTemporaryRoot), []);
    if (process.platform !== "win32") {
      const descendantPid = Number((await readFile(descendantMarker, "utf8")).trim());
      assert.throws(
        () => process.kill(descendantPid, 0),
        (error: unknown) =>
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "ESRCH",
      );
    }
  } finally {
    if (previousTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpdir;
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER;
    else process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test(
  "limits portable termination to the spawned process group",
  { skip: process.platform === "win32" },
  async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
    const bundle = path.join(temporary, "bundle");
    const descendantMarker = path.join(temporary, "synthetic-detached-pid");
    const previousMarker = process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER;
    let descendantPid: number | undefined;
    try {
      await cp(FIXTURE, bundle, { recursive: true });
      process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER = descendantMarker;
      const attempts = path.join(temporary, "attempts");
      await assert.rejects(
        runBundle({
          bundleDirectory: bundle,
          attemptRoot: attempts,
          provider: commandProvider("detached-descendant-hang", {
            envAllowlist: ["SYNTHETIC_COMMAND_DESCENDANT_MARKER"],
          }),
          phase: PHASE,
          providerTimeoutMs: 500,
          sanitizerRequirement: syntheticRequirement(),
        }),
        (error: unknown) =>
          error instanceof RunnerError && error.code === "provider_timeout",
      );
      descendantPid = Number((await readFile(descendantMarker, "utf8")).trim());
      assert.equal(Number.isSafeInteger(descendantPid) && descendantPid > 0, true);
      assert.doesNotThrow(() => process.kill(descendantPid!, 0));
      assert.deepEqual(await readdir(attempts), []);
    } finally {
      if (descendantPid === undefined) {
        try {
          descendantPid = Number((await readFile(descendantMarker, "utf8")).trim());
        } catch {
          // The synthetic adapter may have failed before starting its descendant.
        }
      }
      if (descendantPid !== undefined) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch {
          // The exact synthetic detached process may already have exited.
        }
      }
      if (previousMarker === undefined) {
        delete process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER;
      } else {
        process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER = previousMarker;
      }
      await rm(temporary, { recursive: true, force: true });
    }
  },
);

test("zeroes callback-returned binary buffers after taking private copies", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const returnedBuffers: Buffer[] = [];
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const base = commandProvider("success");
    const provider = {
      ...base,
      invoke: async (...args: Parameters<typeof base.invoke>) => {
        const [request, context, signal] = args;
        const capture = async (reader: () => Promise<Buffer>): Promise<Buffer> => {
          const bytes = await reader();
          returnedBuffers.push(bytes);
          return bytes;
        };
        return base.invoke(
          {
            ...request,
            image: { ...request.image, readBytes: () => capture(request.image.readBytes) },
            schemaInput: {
              ...request.schemaInput,
              readBytes: () => capture(request.schemaInput.readBytes),
            },
          },
          context,
          signal,
        );
      },
    };
    await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider,
      phase: PHASE,
      sanitizerRequirement: syntheticRequirement(),
    });
    assert.equal(returnedBuffers.length, 2);
    for (const bytes of returnedBuffers) assert.equal(bytes.every((byte) => byte === 0), true);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("removes private command directories after success and process failure", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const privateTemporaryRoot = path.join(temporary, "private-temp");
  const previousTmpdir = process.env.TMPDIR;
  await mkdir(privateTemporaryRoot, { mode: 0o700 });
  process.env.TMPDIR = privateTemporaryRoot;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "success-attempts"),
      provider: commandProvider("success"),
      phase: PHASE,
      sanitizerRequirement: syntheticRequirement(),
    });
    assert.deepEqual(await readdir(privateTemporaryRoot), []);
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "failure-attempts"),
        provider: commandProvider("nonzero"),
        phase: PHASE,
        sanitizerRequirement: syntheticRequirement(),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_failed",
    );
    assert.deepEqual(await readdir(privateTemporaryRoot), []);
  } finally {
    if (previousTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpdir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("passes only allowlisted environment variables to the command process", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const previousAllowed = process.env.SYNTHETIC_COMMAND_ALLOWED;
  const previousBlocked = process.env.SYNTHETIC_COMMAND_BLOCKED;
  process.env.SYNTHETIC_COMMAND_ALLOWED = "synthetic-allowed";
  process.env.SYNTHETIC_COMMAND_BLOCKED = "synthetic-blocked";
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      provider: commandProvider("env", {
        envAllowlist: ["SYNTHETIC_COMMAND_ALLOWED"],
      }),
      phase: PHASE,
      sanitizerRequirement: syntheticRequirement(),
    });
  } finally {
    if (previousAllowed === undefined) delete process.env.SYNTHETIC_COMMAND_ALLOWED;
    else process.env.SYNTHETIC_COMMAND_ALLOWED = previousAllowed;
    if (previousBlocked === undefined) delete process.env.SYNTHETIC_COMMAND_BLOCKED;
    else process.env.SYNTHETIC_COMMAND_BLOCKED = previousBlocked;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not spawn the command process before approval or Phase B requirements pass", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const marker = path.join(temporary, "synthetic-spawn-marker");
  const previousMarker = process.env.SYNTHETIC_COMMAND_MARKER;
  process.env.SYNTHETIC_COMMAND_MARKER = marker;
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const deniedApproval = approvalSettings(requirement);
    deniedApproval.gate = {
      id: "synthetic-command-gate",
      protocolVersion: 1,
      approve: async (request) => ({ ...approvalResponse(request), approved: false }),
    };
    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "denied-attempts"),
        provider: commandProvider("success", {
          envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
        }),
        phase: PHASE,
        approval: deniedApproval,
        sanitizerRequirement: requirement,
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "approval_denied",
    );
    await assert.rejects(readFile(marker), /ENOENT/u);

    await assert.rejects(
      runBundle({
        bundleDirectory: bundle,
        attemptRoot: path.join(temporary, "required-attempts"),
        provider: commandProvider("success", {
          envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
        }),
        phase: PHASE,
        sanitizerRequirement: syntheticRequirement(true),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "sanitizer_required",
    );
    await assert.rejects(readFile(marker), /ENOENT/u);

    const provider = commandProvider("success", {
      envAllowlist: ["SYNTHETIC_COMMAND_MARKER"],
    });
    for (const flags of [
      { sanitizerRequired: true, policyRequired: false },
      { sanitizerRequired: false, policyRequired: true },
    ]) {
      await assert.rejects(
        provider.prepareTransport!(directApprovalResponse(requirement, flags)),
        /command provider transport preparation failed/u,
      );
      await assert.rejects(readFile(marker), /ENOENT/u);
    }
  } finally {
    if (previousMarker === undefined) delete process.env.SYNTHETIC_COMMAND_MARKER;
    else process.env.SYNTHETIC_COMMAND_MARKER = previousMarker;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("binds the execution phase into run identity and reader validation", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const development = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      attemptKey: "development",
      provider: commandProvider("success"),
      phase: "development",
      sanitizerRequirement: syntheticRequirement(),
    });
    const calibration = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: path.join(temporary, "attempts"),
      attemptKey: "calibration",
      provider: createCommandProvider({
        executable: process.execPath,
        argv: [FAKE_COMMAND_PROVIDER, "success"],
        providerId: "synthetic-command",
        route: "local-command",
        implementationVersion: "synthetic-v1",
      }),
      phase: "api-calibration",
      sanitizerRequirement: syntheticRequirement(),
    });
    assert.notEqual(development.runId, calibration.runId);

    const manifestPath = path.join(development.artifactDirectory, "attempt.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.run.phase = "frozen-holdout";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await assert.rejects(
      readAttempt(development.attemptDirectory),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("reader rejects an internally rehashed approval and execution phase mismatch", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-command-test-"));
  const bundle = path.join(temporary, "bundle");
  const attemptRoot = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const requirement = syntheticRequirement();
    const result = await runBundle({
      bundleDirectory: bundle,
      attemptRoot,
      provider: commandProvider("success"),
      phase: PHASE,
      approval: approvalSettings(requirement),
      sanitizerRequirement: requirement,
    });
    const manifest = JSON.parse(
      await readFile(path.join(result.artifactDirectory, "attempt.json"), "utf8"),
    ) as AttemptManifest;
    manifest.run.phase = "frozen-holdout";
    recomputeManifestIdentities(manifest);
    const movedDirectory = path.join(attemptRoot, manifest.attemptId);
    await rename(result.attemptDirectory, movedDirectory);
    await writeFile(
      path.join(movedDirectory, result.artifactId, "attempt.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
    await assert.rejects(
      readAttempt(movedDirectory),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "attempt_identity_mismatch",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

function commandProvider(
  mode: string,
  overrides: Partial<Parameters<typeof createCommandProvider>[0]> = {},
) {
  return createCommandProvider({
    executable: process.execPath,
    argv: [FAKE_COMMAND_PROVIDER, mode],
    providerId: "synthetic-command",
    route: "local-command",
    implementationVersion: "synthetic-v1",
    ...overrides,
  });
}

async function settlesWithin(promise: Promise<void>, milliseconds: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error("synthetic operation did not settle")),
          milliseconds,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function directInvocation(
  bundleDirectory: string,
  stagingDirectory: string,
  requirement: SanitizerRequirementSettings,
  onInputRead: () => void,
): Promise<{
  request: ProviderModelRequest;
  context: ProviderAdapterContext;
  cleanup: () => Promise<void>;
}> {
  const loaded = await loadBundleForRunner(bundleDirectory, stagingDirectory);
  const requested = { model: null, effort: null, maxTokens: null };
  const identity = computeCaseInputIdentity({
    caseId: loaded.caseId,
    documentKind: loaded.documentKind,
    preparedImage: {
      mediaType: loaded.inputs.image.mediaType,
      sha256: loaded.inputs.image.sha256,
    },
  });
  const request: ProviderModelRequest = {
    image: {
      mediaType: loaded.inputs.image.mediaType,
      readBytes: async () => {
        onInputRead();
        return loaded.inputs.image.readBytes();
      },
    },
    schema: loaded.inputs.schema.value,
    schemaInput: {
      mediaType: loaded.inputs.schema.mediaType,
      readBytes: async () => {
        onInputRead();
        return loaded.inputs.schema.readBytes();
      },
    },
    system: {
      mediaType: loaded.inputs.system.mediaType,
      readText: async () => {
        onInputRead();
        return loaded.inputs.system.readText();
      },
    },
    instruction: {
      mediaType: loaded.inputs.instruction.mediaType,
      readText: async () => {
        onInputRead();
        return loaded.inputs.instruction.readText();
      },
    },
    requested,
  };
  return {
    request,
    context: {
      phase: PHASE,
      bundle: { version: loaded.bundleVersion, manifestDigest: loaded.manifestDigest },
      caseId: loaded.caseId,
      documentKind: loaded.documentKind,
      caseInputIdentity: identity,
      inputDigests: {
        image: loaded.inputs.image.sha256,
        schema: loaded.inputs.schema.sha256,
        system: loaded.inputs.system.sha256,
        instruction: loaded.inputs.instruction.sha256,
      },
      requested,
      provenance: {
        harnessVersion: "synthetic-harness",
        harnessCommit: null,
        promptVersion: loaded.metadata.promptVersion,
        preprocessVersion: loaded.metadata.preprocessVersion,
        sourceCommit: loaded.metadata.sourceCommit,
      },
      sanitizerRequirement: requirement.decision,
      approval: null,
    },
    cleanup: loaded.cleanup,
  };
}

function syntheticRequirement(required = false): SanitizerRequirementSettings {
  const verifier = {
    id: "synthetic-requirement-verifier",
    version: "synthetic-v1",
    derive: () => ({
      sanitizerRequired: required,
      policyRequired: required,
      sanitizerRequirementReason: required
        ? "synthetic_required"
        : "synthetic_not_required",
      consumerSourceCommit: "synthetic-source-v1",
    }),
  };
  return {
    verifier,
    decision: createSanitizerRequirementDecision(verifier.derive(), verifier),
  };
}

function approvalSettings(requirement: SanitizerRequirementSettings): ApprovalSettings {
  const gate: ApprovalGate = {
    id: "synthetic-command-gate",
    protocolVersion: 1,
    approve: async (request) => approvalResponse(request),
  };
  return {
    required: true,
    gate,
    expectedGateId: gate.id,
    expectedProtocolVersion: 1,
    snapshotDigest: "a".repeat(64),
    runtimeBindingDigest: "b".repeat(64),
    runtimeBindingIdentity: "synthetic-runtime",
    approvedScopeDigest: "c".repeat(64),
    approvedScopeIdentity: "synthetic-scope",
    phase: PHASE,
    expectedRequirementVerifierId: requirement.decision.requirementVerifierId,
    expectedRequirementVerifierVersion: requirement.decision.requirementVerifierVersion,
    expectedConsumerSourceCommit: requirement.decision.consumerSourceCommit,
    expectedRequirementDecisionDigest: requirement.decision.requirementDecisionDigest,
    expectedSanitizerRequirementVersion:
      requirement.decision.sanitizerRequirementVersion,
    expectedSanitizerRequired: requirement.decision.sanitizerRequired,
    expectedPolicyRequired: requirement.decision.policyRequired,
    expectedSanitizerRequirementReason:
      requirement.decision.sanitizerRequirementReason,
  };
}

function approvalResponse(request: ApprovalRequest) {
  return {
    responseVersion: 1 as const,
    approved: true,
    gateId: request.expected.gateId,
    protocolVersion: 1 as const,
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
    checkedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
  };
}

function directApprovalResponse(
  requirement: SanitizerRequirementSettings,
  overrides: Partial<ApprovalResponse> = {},
): ApprovalResponse {
  const settings = approvalSettings(requirement);
  return {
    responseVersion: 1,
    approved: true,
    gateId: settings.expectedGateId!,
    protocolVersion: 1,
    snapshotDigest: settings.snapshotDigest!,
    runtimeBindingDigest: settings.runtimeBindingDigest!,
    runtimeBindingIdentity: settings.runtimeBindingIdentity!,
    approvedScopeDigest: settings.approvedScopeDigest!,
    approvedScopeIdentity: settings.approvedScopeIdentity!,
    phase: settings.phase!,
    requirementVerifierId: requirement.decision.requirementVerifierId,
    requirementVerifierVersion: requirement.decision.requirementVerifierVersion,
    consumerSourceCommit: requirement.decision.consumerSourceCommit,
    requirementDecisionDigest: requirement.decision.requirementDecisionDigest,
    sanitizerRequirementVersion: requirement.decision.sanitizerRequirementVersion,
    sanitizerRequired: requirement.decision.sanitizerRequired,
    policyRequired: requirement.decision.policyRequired,
    sanitizerRequirementReason: requirement.decision.sanitizerRequirementReason,
    checkedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
    ...overrides,
  };
}

function recomputeManifestIdentities(manifest: AttemptManifest): void {
  const approval = manifest.approval;
  const sanitizer = manifest.sanitizer;
  manifest.runId = computeRunIdentity({
    caseInputIdentityDigest: manifest.caseInputIdentity.digest,
    bundleManifestDigest: manifest.bundleManifestDigest,
    phase: manifest.run.phase,
    providerId: manifest.run.providerId,
    providerRoute: manifest.run.route,
    providerImplementationVersion: manifest.run.implementationVersion,
    providerProtocolVersion: manifest.run.protocolVersion,
    requestedModel: manifest.run.requested.model,
    requestedEffort: manifest.run.requested.effort,
    maxTokens: manifest.run.requested.maxTokens,
    approvalBindingDigest: approval.runtimeBindingDigest,
    approvalBindingIdentity: approval.runtimeBindingIdentity,
    approvalGateId: approval.gateId,
    approvalProtocolVersion: approval.protocolVersion,
    approvalSnapshotDigest: approval.snapshotDigest,
    approvalPhase: approval.phase,
    approvalScopeDigest: approval.approvedScopeDigest,
    approvalScopeIdentity: approval.approvedScopeIdentity,
    approvalRequired: approval.required,
    sanitizerBindingDigest: sanitizer?.policyBindingDigest ?? null,
    sanitizerId: sanitizer?.id ?? null,
    sanitizerProtocolVersion: sanitizer?.protocolVersion ?? null,
    sanitizerRequired: sanitizer !== undefined,
    policyRequired: sanitizer !== undefined,
    sanitizerRequirementVersion:
      manifest.sanitizerRequirement.sanitizerRequirementVersion,
    sanitizerRequirementReason:
      manifest.sanitizerRequirement.sanitizerRequirementReason,
    requirementVerifierId: manifest.sanitizerRequirement.requirementVerifierId,
    requirementVerifierVersion:
      manifest.sanitizerRequirement.requirementVerifierVersion,
    consumerSourceCommit: manifest.sanitizerRequirement.consumerSourceCommit,
    requirementDecisionDigest:
      manifest.sanitizerRequirement.requirementDecisionDigest,
  });
  manifest.attemptId = computeAttemptIdentity({
    runId: manifest.runId,
    attemptKey: manifest.attemptKey,
  }).attemptId;
}
