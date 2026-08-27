import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createCommandSanitizer,
  isAbortSettlingCommandSanitizer,
} from "../src/runner/command-sanitizer.js";
import { RunnerError } from "../src/runner/errors.js";
import { computeCaseInputIdentity, computePolicyBindingDigest } from "../src/runner/identity.js";
import type { SanitizerRequest } from "../src/runner/types.js";

const FAKE_SANITIZER = path.resolve("test/fixtures/fake-command-sanitizer.mjs");
const RAW_MARKER = "SYNTHETIC_RAW_DOCUMENT_MARKER_8c1a";
const POLICY_MARKER = "SYNTHETIC_POLICY_MARKER_295e";

test("validates and snapshots command sanitizer configuration", () => {
  const invalidOptions = [
    { executable: "./relative", sanitizerId: "synthetic-command-sanitizer" },
    { executable: process.execPath, argv: "invalid", sanitizerId: "synthetic-command-sanitizer" },
    {
      executable: process.execPath,
      argv: Array.from({ length: 65 }, () => "synthetic"),
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      argv: ["x".repeat(241)],
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      envAllowlist: Array.from({ length: 65 }, (_, index) => `SYNTHETIC_${index}`),
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      envAllowlist: ["not-valid-name!"],
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      envAllowlist: ["PATH", "Path"],
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      outputLimitBytes: 0,
      sanitizerId: "synthetic-command-sanitizer",
    },
    {
      executable: process.execPath,
      outputLimitBytes: 16 * 1024 * 1024 + 1,
      sanitizerId: "synthetic-command-sanitizer",
    },
    { executable: process.execPath, sanitizerId: "not safe" },
  ];
  for (const options of invalidOptions) {
    assert.throws(
      () => createCommandSanitizer(options as never),
      (error: unknown) =>
        error instanceof RunnerError && error.code === "sanitizer_configuration_invalid",
    );
  }

  const hostile = {} as Parameters<typeof createCommandSanitizer>[0];
  Object.defineProperty(hostile, "executable", {
    get: () => {
      throw new Error("synthetic hostile getter detail");
    },
  });
  assert.throws(
    () => createCommandSanitizer(hostile),
    (error: unknown) =>
      error instanceof RunnerError &&
      error.code === "sanitizer_configuration_invalid" &&
      !error.message.includes("getter"),
  );
});

test("uses immutable argv and allowlisted environment snapshots", async () => {
  const previousAllowed = process.env.SYNTHETIC_SANITIZER_ALLOWED;
  const argv = [FAKE_SANITIZER, "inspect"];
  const envAllowlist = ["SYNTHETIC_SANITIZER_ALLOWED"];
  try {
    process.env.SYNTHETIC_SANITIZER_ALLOWED = "synthetic-original";
    const sanitizer = createCommandSanitizer({
      executable: process.execPath,
      argv,
      envAllowlist,
      sanitizerId: "synthetic-command-sanitizer",
    });
    argv[1] = "nonzero";
    envAllowlist[0] = "PATH";
    process.env.SYNTHETIC_SANITIZER_ALLOWED = "synthetic-mutated";

    const response = await sanitizer.sanitize(syntheticRequest());
    const document = response.sanitizedDocument as Record<string, unknown>;
    assert.equal(document.syntheticSanitized, true);
    assert.equal(document.cwdPrivate, true);
    assert.equal(document.cwdEmpty, true);
    assert.equal(document.allowedValue, "synthetic-original");
    assert.deepEqual(
      (document.environmentKeys as string[]).filter((name) => name !== "__CF_USER_TEXT_ENCODING"),
      ["SYNTHETIC_SANITIZER_ALLOWED"],
    );
    assert.deepEqual(document.requestKeys, [
      "caseInputIdentity",
      "document",
      "documentKind",
      "policyBindingDigest",
      "policyDigest",
      "policyEnvelope",
      "policyVersion",
      "provenance",
      "provider",
      "requestVersion",
    ]);
    assert.equal(document.stdinEndedWithLf, true);
    assert.equal(response.findings?.[0]?.path, "/synthetic");
  } finally {
    if (previousAllowed === undefined) delete process.env.SYNTHETIC_SANITIZER_ALLOWED;
    else process.env.SYNTHETIC_SANITIZER_ALLOWED = previousAllowed;
  }
});

test("accepts one strict response and strips the wire version", async () => {
  const sanitizer = commandSanitizer("success");
  assert.equal(isAbortSettlingCommandSanitizer(sanitizer), true);
  assert.equal(isAbortSettlingCommandSanitizer({}), false);
  const request = syntheticRequest();
  const response = await sanitizer.sanitize(request);
  assert.deepEqual(response.sanitizedDocument, request.document);
  assert.equal("responseVersion" in response, false);
  assert.equal(response.sanitizerId, sanitizer.id);
  assert.equal(response.policyBindingDigest, request.policyBindingDigest);
});

test("rejects request identity and policy binding changes before spawning", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-sanitizer-test-"));
  const marker = path.join(temporary, "spawned");
  try {
    const sanitizer = commandSanitizer("spawn-marker", [marker]);
    const request = syntheticRequest();
    request.caseInputIdentity.digest = "0".repeat(64);
    await assert.rejects(sanitizer.sanitize(request), fixedCommandFailure);
    await assert.rejects(access(marker));

    const bindingRequest = syntheticRequest();
    bindingRequest.policyBindingDigest = "0".repeat(64);
    await assert.rejects(sanitizer.sanitize(bindingRequest), fixedCommandFailure);
    await assert.rejects(access(marker));

    const targetRequest = syntheticRequest();
    targetRequest.policyEnvelope.target = {
      ...(targetRequest.policyEnvelope.target as Record<string, never>),
      caseInputIdentityDigest: "0".repeat(64),
    };
    await assert.rejects(sanitizer.sanitize(targetRequest), fixedCommandFailure);
    await assert.rejects(access(marker));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("does not spawn when already aborted", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-sanitizer-test-"));
  const marker = path.join(temporary, "spawned");
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      commandSanitizer("spawn-marker", [marker]).sanitize(syntheticRequest(), controller.signal),
      fixedCommandFailure,
    );
    await assert.rejects(access(marker));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects malformed abort signals before spawning", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-sanitizer-test-"));
  const marker = path.join(temporary, "spawned");
  try {
    await assert.rejects(
      commandSanitizer("spawn-marker", [marker]).sanitize(
        syntheticRequest(),
        { aborted: false } as never,
      ),
      fixedCommandFailure,
    );
    await assert.rejects(access(marker));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("aborts a spawned process group and removes its private cwd before settling", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-sanitizer-test-"));
  const marker = path.join(temporary, "spawned.json");
  try {
    const controller = new AbortController();
    const operation = commandSanitizer("record-spawn-and-hang", [marker]).sanitize(
      syntheticRequest(),
      controller.signal,
    );
    await waitForFile(marker);
    controller.abort();
    await settlesWithin(assert.rejects(operation, fixedCommandFailure), 3_000);
    const recorded = JSON.parse(await readFile(marker, "utf8")) as { cwd: string };
    await assert.rejects(access(recorded.cwd));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("terminates stdout and stderr overflow and rejects nonzero exit", async () => {
  for (const mode of ["overflow", "stderr-overflow", "nonzero"]) {
    await settlesWithin(
      assert.rejects(
        commandSanitizer(mode, [], { outputLimitBytes: 1024 }).sanitize(syntheticRequest()),
        fixedCommandFailure,
      ),
      3_000,
    );
  }
});

test("does not expose raw document, policy, stderr, or local paths in failures", async () => {
  const error = await commandSanitizer("raw-error")
    .sanitize(syntheticRequest())
    .then(
      () => undefined,
      (reason: unknown) => reason,
    );
  assert.equal(error instanceof Error, true);
  assert.equal((error as Error).message, "sanitizer command failed");
  assert.equal((error as Error).message.includes(RAW_MARKER), false);
  assert.equal((error as Error).message.includes(POLICY_MARKER), false);
  assert.equal((error as Error).message.includes(os.tmpdir()), false);
});

function commandSanitizer(
  mode: string,
  extraArgv: string[] = [],
  overrides: Partial<Parameters<typeof createCommandSanitizer>[0]> = {},
) {
  return createCommandSanitizer({
    executable: process.execPath,
    argv: [FAKE_SANITIZER, mode, ...extraArgv],
    sanitizerId: "synthetic-command-sanitizer",
    ...overrides,
  });
}

function syntheticRequest(): SanitizerRequest {
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-command-case",
    documentKind: "synthetic-invoice",
    preparedImage: {
      mediaType: "image/png",
      sha256: "1".repeat(64),
    },
  });
  const policy = { syntheticPolicyMarker: POLICY_MARKER, mode: "synthetic" };
  const policyEnvelope = {
    envelopeVersion: 1,
    target: {
      identityVersion: identity.identityVersion,
      caseId: identity.caseId,
      documentKind: identity.documentKind,
      preparedImage: identity.preparedImage,
      caseInputIdentityDigest: identity.digest,
    },
    policyVersion: 1,
    policy,
  };
  const policyDigest = createHash("sha256")
    .update(Buffer.from(`${JSON.stringify(policyEnvelope)}\n`, "utf8"))
    .digest("hex");
  return {
    caseInputIdentity: identity,
    documentKind: identity.documentKind,
    policyEnvelope,
    policy,
    policyVersion: 1,
    policyDigest,
    policyBindingDigest: computePolicyBindingDigest({
      caseInputIdentityDigest: identity.digest,
      policyVersion: 1,
      policyDigest,
    }),
    document: {
      syntheticRawMarker: RAW_MARKER,
      invoiceNumber: "SYNTHETIC-001",
    },
    provider: {
      id: "synthetic-provider",
      route: "synthetic-route",
      requested: { model: null, effort: null, maxTokens: null },
      respondedModel: "synthetic-model",
      effectiveEffort: null,
      usage: { available: false },
      stopReason: "synthetic-stop",
    },
    provenance: {
      harnessVersion: "synthetic-harness",
      harnessCommit: null,
      promptVersion: "synthetic-prompt",
      preprocessVersion: "synthetic-preprocess",
      sourceCommit: null,
    },
  };
}

function fixedCommandFailure(error: unknown): boolean {
  return error instanceof Error && error.message === "sanitizer command failed";
}

async function waitForFile(file: string): Promise<void> {
  const deadline = Date.now() + 3_000;
  for (;;) {
    try {
      await access(file);
      return;
    } catch {
      if (Date.now() >= deadline) throw new Error("synthetic child did not start");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
}

async function settlesWithin(promise: Promise<unknown>, milliseconds: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("synthetic operation did not settle")), milliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
