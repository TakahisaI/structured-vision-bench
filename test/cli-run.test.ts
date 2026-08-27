import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { readAttempt } from "../src/runner/attempt.js";

const CLI = path.join(".tmp", "build", "src", "cli", "svbench.js");
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

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
      caseId: string;
      attemptKey: string;
      attemptId: string;
      runId: string;
    };
    assert.equal(summary.ok, true);
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
      /^run complete: synthetic-invoice-basic \(key human-001, attempt [a-f0-9]{64}, run [a-f0-9]{64}\)\n$/u,
    );
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
