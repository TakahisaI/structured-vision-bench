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

import {
  COMMAND_PROVIDER_PROTOCOL_VERSION,
  createCommandProvider,
} from "../src/provider/command.js";
import { readAttempt, type AttemptManifest } from "../src/runner/attempt.js";
import { RunnerError } from "../src/runner/errors.js";
import {
  computeAttemptIdentity,
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

    const manifestPath = path.join(development.attemptDirectory, "attempt.json");
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
      await readFile(path.join(result.attemptDirectory, "attempt.json"), "utf8"),
    ) as AttemptManifest;
    manifest.run.phase = "frozen-holdout";
    recomputeManifestIdentities(manifest);
    const movedDirectory = path.join(attemptRoot, manifest.attemptId);
    await rename(result.attemptDirectory, movedDirectory);
    await writeFile(
      path.join(movedDirectory, "attempt.json"),
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
