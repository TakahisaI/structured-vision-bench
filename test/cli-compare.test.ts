import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import type { JsonValue } from "../src/bundle/json.js";
import { createMockProvider } from "../src/provider/mock.js";
import { createSanitizerRequirementDecision } from "../src/runner/identity.js";
import { runBundle } from "../src/runner/run.js";

const CLI = path.join(".tmp", "build", "src", "cli", "svbench.js");
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");
const DOCUMENT = {
  documentKind: "synthetic_invoice",
  invoiceNumber: "INV-SYNTH-001",
  issuedAt: "2030-01-15",
  currency: "JPY",
  lines: [
    {
      lineNo: 1,
      description: "Widget Alpha",
      quantity: 2,
      unitPrice: 500,
      amount: 1000,
    },
    {
      lineNo: 2,
      description: "Service Beta",
      quantity: 1,
      unitPrice: 234,
      amount: 234,
    },
  ],
  totalAmount: 1234,
} satisfies JsonValue;

test("prints machine-readable and Markdown single-case comparisons", async () => {
  await withAttempt(async ({ bundle, attemptDirectory }) => {
    const json = spawnSync(
      process.execPath,
      [CLI, "compare", "--bundle", bundle, "--attempt", attemptDirectory, "--json"],
      { encoding: "utf8" },
    );
    assert.equal(json.status, 0);
    assert.equal(json.stderr, "");
    const summary = JSON.parse(json.stdout) as {
      ok: boolean;
      result: {
        summary: { fields: { total: number; matched: number }; hardGate: { passed: boolean } };
      };
    };
    assert.equal(summary.ok, true);
    assert.deepEqual(summary.result.summary.fields, {
      total: 13,
      matched: 13,
      missed: 0,
      fabricated: 0,
      wrong: 0,
      comparisonErrors: 0,
    });
    assert.equal(summary.result.summary.hardGate.passed, true);
    assert.equal(json.stdout.includes("INV-SYNTH-001"), false);

    const markdown = spawnSync(
      process.execPath,
      [CLI, "compare", "--bundle", bundle, "--attempt", attemptDirectory],
      { encoding: "utf8" },
    );
    assert.equal(markdown.status, 0);
    assert.equal(markdown.stderr, "");
    assert.match(markdown.stdout, /^# Single-case comparison/mu);
    assert.match(markdown.stdout, /Field matched\/total: 13\/13/u);
    assert.equal(markdown.stdout.includes("INV-SYNTH-001"), false);
  });
});

test("requires explicit bounded rescore arguments", async () => {
  for (const arguments_ of [
    ["--rescore"],
    ["--rescore-reason", "synthetic-reason"],
    ["--rescore", "--rescore-reason", "synthetic/reason"],
  ]) {
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        "compare",
        "--bundle",
        FIXTURE,
        "--attempt",
        "synthetic-attempt",
        ...arguments_,
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
  }
});

test("rejects implicit scoring changes and accepts explicit truth rescoring", async () => {
  await withAttempt(async ({ temporary, bundle, attemptDirectory }) => {
    const scoringBundle = path.join(temporary, "scoring-bundle");
    await cp(bundle, scoringBundle, { recursive: true });
    const truthPath = path.join(scoringBundle, "truth.json");
    const truth = JSON.parse(await readFile(truthPath, "utf8")) as { totalAmount: number };
    truth.totalAmount = 999;
    const truthBytes = `${JSON.stringify(truth, null, 2)}\n`;
    await writeFile(truthPath, truthBytes, "utf8");
    const manifestPath = path.join(scoringBundle, "bundle.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      inputs: { truth: { sha256: string } };
    };
    manifest.inputs.truth.sha256 = createHash("sha256").update(truthBytes).digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    const implicit = spawnSync(
      process.execPath,
      [CLI, "compare", "--bundle", scoringBundle, "--attempt", attemptDirectory, "--json"],
      { encoding: "utf8" },
    );
    assert.equal(implicit.status, 1);
    assert.equal(
      (JSON.parse(implicit.stdout) as { error: { code: string } }).error.code,
      "comparison_bundle_identity_mismatch",
    );

    const explicit = spawnSync(
      process.execPath,
      [
        CLI,
        "compare",
        "--bundle",
        scoringBundle,
        "--attempt",
        attemptDirectory,
        "--rescore",
        "--rescore-reason",
        "synthetic-truth-correction",
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.equal(explicit.status, 0);
    const result = (JSON.parse(explicit.stdout) as {
      result: { identity: { rescored: boolean }; summary: { outcomes: { wrong: number } } };
    }).result;
    assert.equal(result.identity.rescored, true);
    assert.equal(result.summary.outcomes.wrong, 1);
  });
});

async function withAttempt(
  callback: (context: {
    temporary: string;
    bundle: string;
    attemptDirectory: string;
  }) => Promise<void>,
): Promise<void> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-compare-"));
  const bundle = path.join(temporary, "bundle");
  const attempts = path.join(temporary, "attempts");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    const verifier = {
      id: "synthetic-cli-comparison",
      version: "v1",
      derive: (_documentKind: string) => ({
        sanitizerRequired: false,
        policyRequired: false,
        sanitizerRequirementReason: "synthetic_policy_not_required",
        consumerSourceCommit: null,
      }),
    };
    const core = verifier.derive("synthetic_invoice");
    const run = await runBundle({
      bundleDirectory: bundle,
      attemptRoot: attempts,
      provider: createMockProvider({ document: DOCUMENT }),
      sanitizerRequirement: {
        verifier,
        decision: createSanitizerRequirementDecision(core, verifier),
      },
    });
    await callback({ temporary, bundle, attemptDirectory: run.attemptDirectory });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
