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
      attemptId: string;
      runId: string;
    };
    assert.equal(summary.ok, true);
    assert.equal(summary.caseId, "synthetic-invoice-basic");
    assert.match(summary.attemptId, /^[a-f0-9]{64}$/u);
    assert.equal(summary.runId, summary.attemptId);
    const attempt = await readAttempt(path.join(attempts, summary.attemptId));
    assert.equal(attempt.manifest.run.requested.model, "mock-v1");
    assert.equal(attempt.manifest.run.requested.effort, "low");
    assert.equal(attempt.manifest.run.requested.maxTokens, 128);
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
