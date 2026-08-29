import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BundleValidationError,
  normalizeKeyForComparison,
  validateBundle,
} from "../src/bundle/validate-bundle.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

type FileReference = { path: string; sha256: string };
type Truth = Record<string, any>;
type Manifest = {
  comparison: Record<string, unknown>;
  inputs: Record<string, (FileReference & Record<string, unknown>) | undefined>;
  [key: string]: unknown;
};

test("applies only declared normalization operations in canonical order", () => {
  assert.equal(normalizeKeyForComparison("Ａ", []), "Ａ");
  assert.equal(normalizeKeyForComparison("Ａ", ["trim"]), "Ａ");
  assert.equal(normalizeKeyForComparison("Ａ", ["nfkc"]), "A");
  assert.equal(
    normalizeKeyForComparison("\u3000Ａ   Ｂ\u3000", [
      "collapse-whitespace",
      "trim",
      "nfkc",
    ]),
    "A B",
  );
});

test("does not resolve inherited Object prototype properties as JSON Pointer paths", async () => {
  for (const pointer of ["/constructor", "/toString"]) {
    await withFixture(async (bundle) => {
      const manifest = await readManifest(bundle);
      manifest.comparison.scalars = [
        ...(manifest.comparison.scalars as string[]),
        pointer,
      ];
      await writeManifest(bundle, manifest);
      await expectCode(bundle, "truth_contract_invalid");
    });
  }
});

test("rejects object and array values in projected array fields", async () => {
  for (const value of [{ nested: "synthetic" }, ["synthetic"]]) {
    await withFixture(async (bundle) => {
      await rewriteTruth(bundle, (truth) => {
        truth.lines[0].description = value;
      });
      await expectCode(bundle, "truth_contract_invalid");
    });
  }
});

async function withFixture(run: (bundle: string) => Promise<void>): Promise<void> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-contract-regression-"));
  const bundle = path.join(temporary, "case");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await run(bundle);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function expectCode(bundle: string, code: string): Promise<void> {
  try {
    await validateBundle(bundle);
  } catch (error) {
    assert.ok(error instanceof BundleValidationError);
    assert.equal(error.code, code);
    return;
  }
  assert.fail("expected bundle validation to fail");
}

async function readManifest(bundle: string): Promise<Manifest> {
  return JSON.parse(await readFile(path.join(bundle, "bundle.json"), "utf8")) as Manifest;
}

async function writeManifest(bundle: string, manifest: Manifest): Promise<void> {
  await writeFile(path.join(bundle, "bundle.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function rewriteTruth(bundle: string, mutate: (truth: Truth) => void): Promise<void> {
  const truthPath = path.join(bundle, "truth.json");
  const truth = JSON.parse(await readFile(truthPath, "utf8")) as Truth;
  mutate(truth);
  const updated = `${JSON.stringify(truth, null, 2)}\n`;
  await writeFile(truthPath, updated, "utf8");

  const manifest = await readManifest(bundle);
  const truthReference = manifest.inputs.truth;
  if (truthReference) {
    truthReference.sha256 = createHash("sha256").update(updated, "utf8").digest("hex");
    await writeManifest(bundle, manifest);
  }
}
