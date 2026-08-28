import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFile,
  chmod,
  cp,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import fsPromises from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { mock } from "node:test";

import { readAttempt } from "../src/runner/attempt.js";
import { MAX_TIMEOUT_MS } from "../src/runner/run.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  createSanitizerRequirementDecision,
} from "../src/runner/identity.js";
import {
  createSanitizerPolicyEnvelope,
  MAX_SANITIZER_POLICY_BYTES,
} from "../src/runner/sanitizer.js";
import { MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES } from "../src/runner/command-sanitizer.js";
import { readPrivateSanitizerPolicy } from "../src/cli/sanitizer-policy.js";

const CLI = path.join(".tmp", "build", "src", "cli", "svbench.js");
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const FAKE_APPROVAL_GATE = path.resolve("test/fixtures/fake-approval-gate.mjs");
const FAKE_COMMAND_PROVIDER = path.resolve("test/fixtures/fake-command-provider.mjs");
const FAKE_COMMAND_SANITIZER = path.resolve("test/fixtures/fake-command-sanitizer.mjs");
const FAKE_CODEX_APP_SERVER = path.resolve(
  ".tmp/build/test/support/fake-codex-app-server.js",
);
const IMAGE_SHA256 = "dda43d98857bc0977a1bdc67e8005428c3af95ca73cddda69c9e8737eee03cc9";

test("fails closed before opening sanitizer policies on Windows", async () => {
  const syntheticPath = "synthetic-policy-path";
  const openSpy = mock.method(fsPromises, "open", async () => {
    throw new Error("synthetic open must not run");
  });
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
  assert.ok(platformDescriptor);
  let pending: Promise<Buffer>;
  try {
    Object.defineProperty(process, "platform", {
      ...platformDescriptor,
      value: "win32",
    });
    pending = readPrivateSanitizerPolicy(syntheticPath);
  } finally {
    Object.defineProperty(process, "platform", platformDescriptor);
    openSpy.mock.restore();
  }
  await assert.rejects(
    pending,
    (error: unknown) =>
      error instanceof Error &&
      error.message === "sanitizer policy is unreadable" &&
      !error.message.includes(syntheticPath),
  );
  assert.equal(openSpy.mock.callCount(), 0);
});

function commandProviderArguments(mode = "success"): string[] {
  return [
    "--provider",
    "command",
    "--provider-command",
    process.execPath,
    "--provider-arg",
    FAKE_COMMAND_PROVIDER,
    "--provider-arg",
    mode,
    "--provider-id",
    "synthetic-command",
    "--provider-route",
    "local-command",
    "--provider-version",
    "synthetic-v1",
    "--phase",
    "development",
  ];
}

function approvalArguments(mode = "request-boundary"): string[] {
  return [
    "--approval",
    "required",
    "--approval-command",
    process.execPath,
    "--approval-arg",
    FAKE_APPROVAL_GATE,
    "--approval-arg",
    mode,
    "--approval-gate-id",
    "synthetic-cli-gate",
    "--approval-snapshot-digest",
    "a".repeat(64),
    "--approval-runtime-identity",
    "synthetic-runtime",
    "--approval-runtime-digest",
    "b".repeat(64),
    "--approval-scope-identity",
    "synthetic-scope",
    "--approval-scope-digest",
    "c".repeat(64),
    "--approval-phase",
    "development",
  ];
}

function codexAppServerArguments(
  mode: string,
  capture: string,
  timeoutMs = 5_000,
): string[] {
  return [
    "--provider",
    "codex-app-server",
    "--provider-command",
    process.execPath,
    "--provider-arg",
    FAKE_CODEX_APP_SERVER,
    "--provider-arg",
    mode,
    "--provider-arg",
    capture,
    "--provider-arg",
    path.join(path.dirname(capture), "synthetic-canary"),
    "--provider-timeout-ms",
    String(timeoutMs),
    "--model",
    "synthetic-model",
    "--effort",
    "medium",
    "--phase",
    "development",
  ];
}

function requiredSanitizerArguments(input: {
  policyPath: string;
  policyDigest: string;
  caseInputIdentityDigest: string;
  policyBindingDigest: string;
}): string[] {
  const verifier = {
    id: "synthetic-cli-verifier",
    version: "v1",
    derive: (_documentKind: string) => ({
      sanitizerRequired: true,
      policyRequired: true,
      sanitizerRequirementReason: "synthetic_policy_required",
      consumerSourceCommit: null,
    }),
  };
  const decision = createSanitizerRequirementDecision(verifier.derive(""), verifier);
  return [
    "--sanitizer",
    "required",
    "--sanitizer-command",
    process.execPath,
    "--sanitizer-arg",
    FAKE_COMMAND_SANITIZER,
    "--sanitizer-arg",
    "success",
    "--sanitizer-id",
    "synthetic-command-sanitizer",
    "--sanitizer-policy",
    input.policyPath,
    "--sanitizer-policy-version",
    "1",
    "--sanitizer-policy-digest",
    input.policyDigest,
    "--sanitizer-case-input-digest",
    input.caseInputIdentityDigest,
    "--sanitizer-binding-digest",
    input.policyBindingDigest,
    "--requirement-verifier-id",
    verifier.id,
    "--requirement-verifier-version",
    verifier.version,
    "--requirement-reason",
    "synthetic_policy_required",
    "--requirement-decision-digest",
    decision.requirementDecisionDigest,
  ];
}

test("runs a synthetic mock bundle through the public CLI", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        bundle,
        "--provider",
        "mock",
        "--model",
        "mock-v1",
        "--effort",
        "low",
        "--max-tokens",
        "128",
        "--attempt-root",
        attempts,
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as {
      ok: boolean;
      phase: string;
      caseId: string;
      attemptKey: string;
      attemptId: string;
      runId: string;
    };
    assert.equal(summary.ok, true);
    assert.equal(summary.phase, "development");
    assert.equal(summary.caseId, "synthetic-invoice-basic");
    assert.equal(summary.attemptKey, "single");
    assert.match(summary.attemptId, /^[a-f0-9]{64}$/u);
    assert.match(summary.runId, /^[a-f0-9]{64}$/u);
    assert.notEqual(summary.runId, summary.attemptId);
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.attemptIdentityVersion, 1);
    assert.equal(attempt.manifest.attemptKey, "single");
    assert.equal(attempt.manifest.attemptId, summary.attemptId);
    assert.equal(attempt.manifest.runId, summary.runId);
    assert.equal(attempt.manifest.run.requested.model, "mock-v1");
    assert.equal(attempt.manifest.run.requested.effort, "low");
    assert.equal(attempt.manifest.run.requested.maxTokens, 128);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("prints the attempt key in the human success summary", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const attempts = path.join(temporary, "attempts");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        "--provider",
        "mock",
        "--attempt-key",
        "human-001",
        "--attempt-root",
        attempts,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    assert.match(
      result.stdout,
      /^run complete: synthetic-invoice-basic \(phase development, key human-001, attempt [a-f0-9]{64}, run [a-f0-9]{64}\)\n$/u,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs a required command approval gate from the public CLI", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const attempts = path.join(temporary, "attempts");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        "--provider",
        "mock",
        "--attempt-root",
        attempts,
        ...approvalArguments(),
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as { attemptId: string };
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.approval.required, true);
    assert.equal(attempt.manifest.approval.applied, true);
    assert.equal(attempt.manifest.approval.gateId, "synthetic-cli-gate");
    assert.equal(attempt.manifest.approval.approvedScopeIdentity, "synthetic-scope");
    assert.equal(attempt.manifest.approval.phase, "development");
    assert.equal(attempt.manifest.approval.requirementVerifierId, "svbench-cli");
    assert.equal(JSON.stringify(attempt.manifest).includes(FAKE_APPROVAL_GATE), false);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs the policy-free command provider from the public CLI", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const attempts = path.join(temporary, "attempts");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        ...commandProviderArguments(),
        "--model",
        "synthetic-model",
        "--effort",
        "medium",
        "--provider-timeout-ms",
        "5000",
        "--attempt-root",
        attempts,
        ...approvalArguments(),
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as { attemptId: string };
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.run.phase, "development");
    assert.equal(attempt.manifest.run.providerId, "synthetic-command");
    assert.equal(attempt.manifest.run.route, "local-command");
    assert.equal(attempt.manifest.run.implementationVersion, "synthetic-v1");
    assert.equal(attempt.manifest.run.protocolVersion, "command-provider-v1");
    assert.equal(attempt.manifest.approval.applied, true);
    assert.equal(attempt.manifest.sanitizer, undefined);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs one approval-bound Codex app-server attempt from the public CLI", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-codex-"));
  const attempts = path.join(temporary, "attempts");
  const capture = path.join(temporary, "capture.jsonl");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        ...codexAppServerArguments("provider-success", capture),
        "--attempt-root",
        attempts,
        ...approvalArguments("codex-stable"),
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stdout);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as { attemptId: string };
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.run.providerId, "codex-app-server");
    assert.equal(attempt.manifest.run.route, "codex-app-server");
    assert.equal(
      attempt.manifest.run.implementationVersion,
      "codex-app-server-provider-v1",
    );
    assert.equal(
      attempt.manifest.run.protocolVersion,
      "codex-app-server-isolation-v1",
    );
    assert.deepEqual(attempt.manifest.run.requested, {
      model: "synthetic-model",
      effort: "medium",
      maxTokens: null,
    });
    assert.deepEqual(attempt.manifest.run.responded, {
      model: "synthetic-model",
      effort: "medium",
      usage: {
        available: true,
        inputTokens: 11,
        outputTokens: 7,
        totalTokens: 18,
      },
      stopReason: null,
    });
    assert.equal(attempt.manifest.approval.applied, true);

    const records = await readJsonLines(capture);
    const threadStart = records.find((record) => record.threadStart !== undefined);
    const turnStart = records.find((record) => record.turnStart !== undefined);
    assert.ok(threadStart);
    assert.ok(turnStart);
    const hostedWire = JSON.stringify([threadStart, turnStart]);
    for (const prohibited of [
      "synthetic-invoice-basic",
      "synthetic-cli-gate",
      "synthetic-runtime",
      "synthetic-scope",
      "cli_policy_not_required",
    ]) {
      assert.equal(hostedWire.includes(prohibited), false, prohibited);
    }
    const thread = object(threadStart.threadStart);
    const turn = object(turnStart.turnStart);
    assert.equal(thread.model, "synthetic-model");
    assert.equal(typeof thread.baseInstructions, "string");
    assert.equal(turn.model, "synthetic-model");
    assert.equal(turn.effort, "medium");
    assert.equal(typeof turn.outputSchema, "object");
    assert.equal(array(turn.input).length, 2);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("keeps unavailable Codex app-server usage metadata unknown", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-codex-"));
  const attempts = path.join(temporary, "attempts");
  const capture = path.join(temporary, "capture.jsonl");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        ...codexAppServerArguments("provider-success-no-usage", capture),
        "--attempt-root",
        attempts,
        ...approvalArguments("codex-stable"),
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stdout);
    const summary = JSON.parse(result.stdout) as { attemptId: string };
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.deepEqual(attempt.manifest.run.responded.usage, { available: false });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("fails Codex app-server CLI runs before transport when approval is unusable", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-codex-"));
  try {
    const cases = [
      { mode: "deny", expected: "approval_denied" },
      { mode: "mismatch-scope", expected: "approval_response_invalid" },
      { mode: "hang", expected: "approval_timeout", timeout: "100" },
    ];
    for (const [index, entry] of cases.entries()) {
      const attempts = path.join(temporary, `attempts-${index}`);
      const capture = path.join(temporary, `capture-${index}.jsonl`);
      const approval = approvalArguments(entry.mode);
      if (entry.timeout !== undefined) {
        approval.push("--approval-timeout-ms", entry.timeout);
      }
      const result = await runCliWithin(
        [
          "run",
          "--bundle",
          FIXTURE,
          ...codexAppServerArguments("provider-success", capture),
          "--attempt-root",
          attempts,
          ...approval,
          "--json",
        ],
        3_000,
      );
      assert.equal(result.status, 1, result.stdout);
      assert.equal(
        (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
        entry.expected,
      );
      await assert.rejects(readFile(capture), /ENOENT/u);
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects incomplete Codex app-server CLI configuration before runner execution", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-codex-"));
  try {
    const capture = path.join(temporary, "capture.jsonl");
    const base = codexAppServerArguments("provider-success", capture);
    const invalid = [
      base,
      [...base, ...approvalArguments("codex-stable"), "--max-tokens", "1"],
      [...base, ...approvalArguments("codex-stable"), "--provider-id", "synthetic"],
      base
        .map((value) => (value === process.execPath ? "./synthetic-codex" : value))
        .concat(approvalArguments("codex-stable")),
    ];
    for (const [index, arguments_] of invalid.entries()) {
      const attempts = path.join(temporary, `invalid-attempts-${index}`);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          path.join(temporary, "missing-bundle"),
          ...arguments_,
          "--attempt-root",
          attempts,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 2, result.stdout);
      assert.equal(
        (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
        "invalid_arguments",
      );
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
    await assert.rejects(readFile(capture), /ENOENT/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("distinguishes Codex app-server transport and document failures from success", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-codex-"));
  try {
    const cases = [
      { mode: "hang", code: "provider_timeout" },
      { mode: "crash", code: "provider_failed" },
      { mode: "version-mismatch", code: "provider_failed" },
      { mode: "malformed", code: "provider_failed" },
      { mode: "success", code: "provider_document_schema_invalid" },
    ];
    for (const [index, entry] of cases.entries()) {
      const { mode } = entry;
      const attempts = path.join(temporary, `attempts-${index}`);
      const capture = path.join(temporary, `capture-${index}.jsonl`);
      const result = await runCliWithin(
        [
          "run",
          "--bundle",
          FIXTURE,
          ...codexAppServerArguments(mode, capture, mode === "hang" ? 200 : 5_000),
          "--attempt-root",
          attempts,
          ...approvalArguments("codex-stable"),
          "--json",
        ],
        4_000,
      );
      assert.equal(result.status, 1, `${mode}: ${result.stdout}`);
      const code = (JSON.parse(result.stdout) as { error: { code: string } }).error.code;
      assert.equal(code, entry.code);
      const attemptEntries = await readdir(attempts).catch(
        (error: unknown) => {
          if (objectWithCode(error).code === "ENOENT") return [];
          throw error;
        },
      );
      assert.deepEqual(attemptEntries, [], mode);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("runs a target-bound private command sanitizer from the public CLI", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const attempts = path.join(temporary, "attempts");
  const policyPath = path.join(temporary, "synthetic-policy.json");
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
  try {
    await writeFile(policyPath, policyBytes, { mode: 0o600 });
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        "--provider",
        "mock",
        "--attempt-root",
        attempts,
        ...requiredSanitizerArguments({
          policyPath,
          policyDigest,
          caseInputIdentityDigest: identity.digest,
          policyBindingDigest,
        }),
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stdout);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as { attemptId: string };
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.sanitizer?.id, "synthetic-command-sanitizer");
    assert.equal(attempt.manifest.sanitizer?.policyDigest, policyDigest);
    assert.equal(attempt.manifest.sanitizer?.policyBindingDigest, policyBindingDigest);
    assert.equal(attempt.manifest.sanitizer?.findings[0]?.path, null);
    assert.equal(JSON.stringify(attempt.manifest).includes(policyPath), false);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects invalid private sanitizer CLI configuration before runner execution", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const policyPath = path.join(temporary, "synthetic-policy.json");
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
  const valid = requiredSanitizerArguments({
    policyPath,
    policyDigest,
    caseInputIdentityDigest: identity.digest,
    policyBindingDigest,
  });
  try {
    await writeFile(policyPath, policyBytes, { mode: 0o600 });
    const invalidArguments = [
      ["--sanitizer", "required"],
      valid.map((value) => (value === process.execPath ? "./synthetic-sanitizer" : value)),
      valid.map((value) => (value === policyDigest ? "synthetic-invalid-digest" : value)),
      [...valid, "--sanitizer-env", "PATH", "--sanitizer-env", "Path"],
      [...valid, "--sanitizer-output-limit", String(MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES + 1)],
      [...valid, "--sanitizer-timeout-ms", String(MAX_TIMEOUT_MS + 1)],
      valid.map((value) =>
        /^[a-f0-9]{64}$/u.test(value) && value !== policyDigest && value !== identity.digest && value !== policyBindingDigest
          ? "f".repeat(64)
          : value,
      ),
    ];
    for (const [index, args] of invalidArguments.entries()) {
      const attempts = path.join(temporary, `invalid-attempts-${index}`);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          path.join(temporary, "missing-bundle"),
          "--provider",
          "mock",
          "--attempt-root",
          attempts,
          ...args,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 2, result.stdout);
      assert.equal(result.stderr, "");
      assert.equal(
        (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
        "invalid_arguments",
      );
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test(
  "rejects unsafe private sanitizer policy files without blocking or leaking diagnostics",
  { skip: process.platform === "win32" },
  async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
    const identity = computeCaseInputIdentity({
      caseId: "synthetic-invoice-basic",
      documentKind: "synthetic_invoice",
      preparedImage: { mediaType: "image/png", sha256: IMAGE_SHA256 },
    });
    const policyBytes = createSanitizerPolicyEnvelope({
      target: identity,
      policyVersion: 1,
      policy: { syntheticSecretMarker: "SYNTHETIC_POLICY_SECRET_MARKER" },
    });
    const policyDigest = createHash("sha256").update(policyBytes).digest("hex");
    const policyBindingDigest = computePolicyBindingDigest({
      caseInputIdentityDigest: identity.digest,
      policyVersion: 1,
      policyDigest,
    });
    const privatePolicy = path.join(temporary, "private-policy.json");
    const symlinkPolicy = path.join(temporary, "symlink-policy.json");
    const publicPolicy = path.join(temporary, "public-policy.json");
    const fifoPolicy = path.join(temporary, "fifo-policy");
    const growingPolicy = path.join(temporary, "growing-policy.json");
    try {
      await writeFile(privatePolicy, policyBytes, { mode: 0o600 });
      await symlink(privatePolicy, symlinkPolicy);
      await writeFile(publicPolicy, policyBytes, { mode: 0o600 });
      await chmod(publicPolicy, 0o644);
      const fifo = spawnSync("mkfifo", [fifoPolicy], { encoding: "utf8" });
      assert.equal(fifo.status, 0, fifo.stderr);
      const paddingLength = MAX_SANITIZER_POLICY_BYTES - policyBytes.byteLength - 1_024;
      assert.equal(paddingLength > 0, true);
      const growingBytes = Buffer.concat([policyBytes, Buffer.alloc(paddingLength, 0x20)]);
      await writeFile(growingPolicy, growingBytes, { mode: 0o600 });

      const cases = [symlinkPolicy, publicPolicy, fifoPolicy];
      for (const [index, policyPath] of cases.entries()) {
        const attempts = path.join(temporary, `unsafe-attempts-${index}`);
        const result = await runCliWithin(
          [
            "run",
            "--bundle",
            FIXTURE,
            "--provider",
            "mock",
            "--attempt-root",
            attempts,
            ...requiredSanitizerArguments({
              policyPath,
              policyDigest,
              caseInputIdentityDigest: identity.digest,
              policyBindingDigest,
            }),
            "--json",
          ],
          3_000,
        );
        assert.equal(result.status, 1, result.stdout);
        assert.equal(result.stderr, "");
        assert.equal(
          (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
          "sanitizer_policy_invalid",
        );
        assert.equal(result.stdout.includes(policyPath), false);
        assert.equal(result.stdout.includes("SYNTHETIC_POLICY_SECRET_MARKER"), false);
        await assert.rejects(readdir(attempts), /ENOENT/u);
      }

      const growingAttempts = path.join(temporary, "growing-attempts");
      const growingRun = runCliWithin(
        [
          "run",
          "--bundle",
          FIXTURE,
          "--provider",
          "mock",
          "--attempt-root",
          growingAttempts,
          ...requiredSanitizerArguments({
            policyPath: growingPolicy,
            policyDigest: createHash("sha256").update(growingBytes).digest("hex"),
            caseInputIdentityDigest: identity.digest,
            policyBindingDigest,
          }),
          "--json",
        ],
        3_000,
      );
      await appendFile(growingPolicy, Buffer.alloc(2_048, 0x20));
      const growingResult = await growingRun;
      assert.equal(growingResult.status, 1, growingResult.stdout);
      assert.equal(growingResult.stderr, "");
      assert.equal(
        (JSON.parse(growingResult.stdout) as { error: { code: string } }).error.code,
        "sanitizer_policy_invalid",
      );
      assert.equal(growingResult.stdout.includes(growingPolicy), false);
      assert.equal(growingResult.stdout.includes("SYNTHETIC_POLICY_SECRET_MARKER"), false);
      await assert.rejects(readdir(growingAttempts), /ENOENT/u);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  },
);

test("rejects invalid command provider CLI configuration before runner execution", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  try {
    const invalidProviderArguments = [
      ["--provider", "command"],
      commandProviderArguments().map((value) =>
        value === process.execPath ? "./synthetic-provider" : value,
      ),
      commandProviderArguments().filter((value) => value !== "synthetic-command"),
      [
        ...commandProviderArguments(),
        "--provider-output-limit",
        String(16 * 1024 * 1024 + 1),
      ],
      [
        ...commandProviderArguments(),
        "--provider-env",
        "SVBENCH_COMMAND_REQUEST_DIRECTORY",
      ],
      [
        ...commandProviderArguments(),
        "--provider-env",
        "SVBENCH_COMMAND_OPERATION",
      ],
      [
        ...commandProviderArguments(),
        "--provider-env",
        "svbench_command_request_directory",
      ],
      [
        ...commandProviderArguments(),
        "--provider-env",
        "PATH",
        "--provider-env",
        "Path",
      ],
      [
        ...commandProviderArguments(),
        "--provider-timeout-ms",
        String(MAX_TIMEOUT_MS + 1),
      ],
      [
        "--provider",
        "mock",
        "--provider-command",
        process.execPath,
      ],
      [
        ...commandProviderArguments(),
        ...approvalArguments(),
        "--phase",
        "frozen-holdout",
      ],
    ];
    for (const [index, providerArgs] of invalidProviderArguments.entries()) {
      const attempts = path.join(temporary, `attempts-${index}`);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          FIXTURE,
          ...providerArgs,
          "--attempt-root",
          attempts,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 2);
      assert.equal(result.stderr, "");
      assert.equal(
        (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
        "invalid_arguments",
      );
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects incomplete command approval CLI arguments before runner execution", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  try {
    const invalidApprovalArguments = [
      ["--approval", "required"],
      ["--approval-command", process.execPath],
      ["--approval", "required", "--approval-command", "./synthetic-fake-gate"],
      approvalArguments().map((value) =>
        value === "a".repeat(64) ? "synthetic-invalid-digest" : value,
      ),
      [...approvalArguments(), "--approval-env", "SYNTHETIC/INVALID"],
      [...approvalArguments(), "--approval-output-limit", String(16 * 1024 * 1024 + 1)],
      [...approvalArguments(), "--approval-timeout-ms", String(MAX_TIMEOUT_MS + 1)],
    ];
    for (const [index, approvalArgs] of invalidApprovalArguments.entries()) {
      const attempts = path.join(temporary, `attempts-${index}`);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          FIXTURE,
          "--provider",
          "mock",
          "--attempt-root",
          attempts,
          ...approvalArgs,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 2);
      assert.equal(result.stderr, "");
      assert.equal(
        (JSON.parse(result.stdout) as { error: { code: string } }).error.code,
        "invalid_arguments",
      );
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects invalid attempt keys as CLI argument errors", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  try {
    for (const [index, attemptKey] of ["synthetic/key", "a".repeat(65), "合成"].entries()) {
      const attempts = path.join(temporary, `attempts-${index}`);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          FIXTURE,
          "--provider",
          "mock",
          "--attempt-key",
          attemptKey,
          "--attempt-root",
          attempts,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 2);
      assert.equal(result.stderr, "");
      const summary = JSON.parse(result.stdout) as { ok: boolean; error: { code: string } };
      assert.equal(summary.ok, false);
      assert.equal(summary.error.code, "invalid_arguments");
      await assert.rejects(readdir(attempts), /ENOENT/u);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("separates CLI attempt instances by caller key", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const summaries = ["dev-001", "dev-002"].map((attemptKey) => {
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          bundle,
          "--provider",
          "mock",
          "--attempt-key",
          attemptKey,
          "--attempt-root",
          attempts,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      return JSON.parse(result.stdout) as {
        attemptKey: string;
        attemptId: string;
        runId: string;
      };
    });
    assert.deepEqual(summaries.map((summary) => summary.attemptKey), ["dev-001", "dev-002"]);
    assert.equal(summaries[0]!.runId, summaries[1]!.runId);
    assert.notEqual(summaries[0]!.attemptId, summaries[1]!.attemptId);
    assert.deepEqual(
      (await readdir(attempts)).sort(),
      summaries.map((summary) => summary.attemptId).sort(),
    );

    const duplicate = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        bundle,
        "--provider",
        "mock",
        "--attempt-key",
        "dev-001",
        "--attempt-root",
        attempts,
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(duplicate.status, 1);
    assert.equal(
      (JSON.parse(duplicate.stdout) as { error: { code: string } }).error.code,
      "attempt_exists",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("separates CLI attempts when model settings change", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const ids = ["mock-a", "mock-b"].map((model) => {
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          "run",
          "--bundle",
          bundle,
          "--provider",
          "mock",
          "--model",
          model,
          "--attempt-root",
          attempts,
          "--json",
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0);
      return (JSON.parse(result.stdout) as { attemptId: string }).attemptId;
    });
    assert.notEqual(ids[0], ids[1]);
    assert.deepEqual((await readdir(attempts)).sort(), ids.sort());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects an unknown provider as invalid CLI arguments", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const attempts = path.join(temporary, "attempts");
  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        FIXTURE,
        "--provider",
        "not-a-provider",
        "--attempt-root",
        attempts,
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 2);
    assert.equal(result.stderr, "");
    const summary = JSON.parse(result.stdout) as { ok: boolean; error: { code: string } };
    assert.equal(summary.ok, false);
    assert.equal(summary.error.code, "invalid_arguments");
    await assert.rejects(readdir(attempts));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("rejects an unknown top-level command as invalid CLI arguments", () => {
  const result = spawnSync(
    process.execPath,
    [CLI, "bogus", "--bundle", FIXTURE, "--provider", "mock", "--json"],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 2);
  assert.equal(result.stderr, "");
  const summary = JSON.parse(result.stdout) as { ok: boolean; error: { code: string } };
  assert.equal(summary.ok, false);
  assert.equal(summary.error.code, "invalid_arguments");
});

test("reports bundle failures without echoing the bundle path", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-run-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await writeFile(path.join(bundle, "system.txt"), Buffer.from([0x73, 0x79, 0xff]));
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "run",
        "--bundle",
        bundle,
        "--provider",
        "mock",
        "--attempt-root",
        attempts,
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.length < 2_000);
    assert.ok(!result.stdout.includes(bundle));
    const summary = JSON.parse(result.stdout) as { ok: boolean; error: { code: string } };
    assert.equal(summary.ok, false);
    assert.equal(summary.error.code, "text_file_invalid");
    await assert.rejects(readdir(attempts));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

async function runCliWithin(
  arguments_: string[],
  timeoutMs: number,
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...arguments_], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("synthetic CLI operation did not settle"));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      if (signal !== null) {
        reject(new Error("synthetic CLI operation exited by signal"));
        return;
      }
      resolve({ status, stdout, stderr });
    });
  });
}

async function readJsonLines(file: string): Promise<Record<string, unknown>[]> {
  return (await readFile(file, "utf8"))
    .trim()
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function object(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, unknown>;
}

function array(value: unknown): unknown[] {
  assert.ok(Array.isArray(value));
  return value;
}

function objectWithCode(value: unknown): { code?: string } {
  if (value === null || typeof value !== "object") return {};
  return value as { code?: string };
}
