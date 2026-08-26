import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { BundleValidationError, validateBundle } from "../src/bundle/validate-bundle.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

test("accepts the complete synthetic bundle", async () => {
  const result = await validateBundle(FIXTURE);
  assert.deepEqual(result, {
    caseId: "synthetic-invoice-basic",
    referencedFiles: 5,
    bundleVersion: 1,
  });
});

test("rejects an unknown bundle version before reading providers", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.bundleVersion = 2;
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "manifest_schema_invalid");
  });
});

test("rejects a missing referenced file", async () => {
  await withFixture(async (bundle) => {
    await unlink(path.join(bundle, "instruction.txt"));
    await expectCode(bundle, "referenced_file_missing");
  });
});

test("rejects a path traversal reference", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.inputs.system.path = "../system.txt";
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "unsafe_reference_path");
  });
});

test("rejects an absolute reference", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.inputs.system.path = "/tmp/system.txt";
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "unsafe_reference_path");
  });
});

test("rejects a digest mismatch", async () => {
  await withFixture(async (bundle) => {
    await writeFile(path.join(bundle, "system.txt"), "changed after manifest creation\n", "utf8");
    await expectCode(bundle, "digest_mismatch");
  });
});

test("rejects a symlinked input", { skip: process.platform === "win32" }, async () => {
  await withFixture(async (bundle) => {
    const target = path.join(bundle, "system-target.txt");
    const link = path.join(bundle, "system.txt");
    await writeFile(target, "synthetic system prompt\n", "utf8");
    await unlink(link);
    await symlink("system-target.txt", link);
    await expectCode(bundle, "referenced_file_symlink");
  });
});

async function withFixture(run: (bundle: string) => Promise<void>): Promise<void> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-bundle-"));
  const bundle = path.join(temporary, "case");
  try {
    await cp(FIXTURE, bundle, { recursive: true });
    await run(bundle);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function expectCode(bundle: string, code: string): Promise<void> {
  await assert.rejects(
    validateBundle(bundle),
    (error: unknown) => error instanceof BundleValidationError && error.code === code,
  );
}

type Manifest = {
  bundleVersion: number;
  inputs: {
    system: { path: string };
  };
};

async function readManifest(bundle: string): Promise<Manifest> {
  return JSON.parse(await readFile(path.join(bundle, "bundle.json"), "utf8")) as Manifest;
}

async function writeManifest(bundle: string, manifest: Manifest): Promise<void> {
  await writeFile(path.join(bundle, "bundle.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}
