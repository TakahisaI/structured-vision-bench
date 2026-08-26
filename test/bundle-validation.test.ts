import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BundleValidationError,
  MAX_JSON_BYTES,
  normalizeKeyForComparison,
  validateBundle,
} from "../src/bundle/validate-bundle.js";

const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

type FileReference = { path: string; sha256: string };

type Truth = Record<string, any>;

type Manifest = {
  bundleVersion: number;
  comparison: Record<string, unknown>;
  inputs: { system: FileReference & Record<string, unknown> } & Record<
    string,
    (FileReference & Record<string, unknown>) | undefined
  >;
  [key: string]: unknown;
};

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

test("rejects a symlinked bundle manifest", { skip: process.platform === "win32" }, async () => {
  await withFixture(async (bundle) => {
    const manifestPath = path.join(bundle, "bundle.json");
    const targetPath = path.join(bundle, "bundle-target.json");
    await writeFile(targetPath, await readFile(manifestPath));
    await unlink(manifestPath);
    await symlink("bundle-target.json", manifestPath);
    await expectCode(bundle, "bundle_manifest_symlink");
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

test("accepts a safe path segment that starts with two dots", async () => {
  await withFixture(async (bundle) => {
    const safeDirectory = path.join(bundle, "..safe");
    await mkdir(safeDirectory);
    await cp(path.join(bundle, "system.txt"), path.join(safeDirectory, "system.txt"));

    const manifest = await readManifest(bundle);
    manifest.inputs.system.path = "..safe/system.txt";
    await writeManifest(bundle, manifest);

    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });
});

test("rejects a digest mismatch without echoing digest values", async () => {
  await withFixture(async (bundle) => {
    await writeFile(path.join(bundle, "system.txt"), "changed after manifest creation\n", "utf8");
    const error = await captureError(bundle);
    assert.equal(error.code, "digest_mismatch");
    assert.deepEqual(error.details, []);
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

test("never echoes an unknown manifest key into diagnostics", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    // Synthetic marker stands in for a real local absolute path or secret.
    const marker = "/tmp/synthetic-local/SECRET_TOKEN=SYNTHETIC-VALUE";
    manifest[marker] = true;
    await writeManifest(bundle, manifest);

    const error = await captureError(bundle);
    assert.equal(error.code, "manifest_schema_invalid");
    const rendered = JSON.stringify({ message: error.message, details: error.details });
    assert.ok(!rendered.includes(marker), "unknown key name must not reach diagnostics");
    assert.ok(
      error.details.some((detail) => detail.includes("unexpected propert")),
      `expected an unexpected-property detail, got: ${JSON.stringify(error.details)}`,
    );
  });
});

test("bounds the number of diagnostic details", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    for (const reference of Object.values(manifest.inputs)) {
      if (reference === undefined) continue;
      for (let index = 0; index < 10; index += 1) {
        reference[`syntheticUnknown${index}`] = true;
      }
    }
    await writeManifest(bundle, manifest);

    const error = await captureError(bundle);
    assert.equal(error.code, "manifest_schema_invalid");
    assert.ok(
      error.details.length <= 20,
      `details should be bounded, got ${error.details.length}`,
    );
    assert.ok(
      error.details.every((detail) => !detail.includes("syntheticUnknown")),
      "unknown key names must not reach diagnostics",
    );
  });
});

test("rejects a wildcard in scalar paths", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.scalars = ["/lines/*/amount"];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "manifest_schema_invalid");
  });
});

test("rejects two wildcards in one pointer", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.critical = [
      "/invoiceNumber",
      "/issuedAt",
      "/totalAmount",
      "/lines/*/a/*/amount",
    ];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "manifest_schema_invalid");
  });
});

test("rejects a critical field not compared by its array", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.critical = [
      "/invoiceNumber",
      "/issuedAt",
      "/totalAmount",
      "/lines/*/discount",
    ];
    await writeManifest(bundle, manifest);
    const error = await captureError(bundle);
    assert.equal(error.code, "comparison_contract_invalid");
    assert.ok(!JSON.stringify(error.details).includes("/Users"), "no absolute path in diagnostics");
  });
});

test("rejects a critical entry referencing an undeclared array", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.critical = [
      "/invoiceNumber",
      "/issuedAt",
      "/totalAmount",
      "/payments/*/amount",
    ];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "comparison_contract_invalid");
  });
});

test("rejects duplicate array declarations and scalars duplicating arrays", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.arrays = [
      ...(manifest.comparison.arrays as unknown[]),
      { path: "/lines", key: "/lineNo", fields: ["/amount"] },
    ];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "comparison_contract_invalid");
  });

  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.scalars = [...(manifest.comparison.scalars as string[]), "/lines"];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "comparison_contract_invalid");
  });
});

test("rejects a whole-array critical entry", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.critical = ["/invoiceNumber", "/issuedAt", "/totalAmount", "/lines"];
    await writeManifest(bundle, manifest);
    await expectCode(bundle, "comparison_contract_invalid");
  });
});

test("accepts every declared array field as critical", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.critical = ["/lines/*/description", "/lines/*/lineNo"];
    await writeManifest(bundle, manifest);
    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });
});

test("accepts embedded-star literals and nested critical scalars", async () => {
  await withFixture(async (bundle) => {
    const manifest = await readManifest(bundle);
    manifest.comparison.scalars = [
      "/documentKind",
      "/invoiceNumber",
      "/issuedAt",
      "/currency",
      "/totalAmount",
      "/header/total",
      "/li*nes/count",
    ];
    manifest.comparison.critical = ["/header/total", "/li*nes/count"];
    await writeManifest(bundle, manifest);
    // The truth projection now demands the new scalars exist in truth.json.
    await rewriteTruth(bundle, (truth) => {
      truth.header = { total: truth.totalAmount };
      truth["li*nes"] = { count: 2 };
    });

    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });
});

test("reports comparison diagnostics by position without echoing pointer values", async () => {
  await withFixture(async (bundle) => {
    const marker = "/tmp/synthetic-local/PRIVATE_CORPUS_PATH";
    const manifest = await readManifest(bundle);
    manifest.comparison.arrays = [
      { path: "/lines", key: "/lineNo", fields: ["/amount"] },
      { path: marker, key: "/lineNo", fields: ["/amount"] },
      { path: marker, key: "/lineNo", fields: ["/amount"] },
    ];
    await writeManifest(bundle, manifest);

    const error = await captureError(bundle);
    assert.equal(error.code, "comparison_contract_invalid");
    const rendered = JSON.stringify({ message: error.message, details: error.details });
    assert.ok(!rendered.includes(marker), "pointer values must not reach diagnostics");
    assert.ok(rendered.includes("comparison.arrays[2]"), "position must be reported instead");
  });
});

test("validates the truth projection during preflight", async () => {
  // The shipped fixture satisfies its own projection.
  await withFixture(async (bundle) => {
    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });

  await withFixture(async (bundle) => {
    await rewriteTruth(bundle, (truth) => {
      delete truth.totalAmount;
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    await rewriteTruth(bundle, (truth) => {
      truth.lines[0].amount = undefined;
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    await rewriteTruth(bundle, (truth) => {
      truth.lines[1].lineNo = null;
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    await rewriteTruth(bundle, (truth) => {
      truth.lines[1].lineNo = truth.lines[0].lineNo;
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    // An array whose elements all violate the key contract fails preflight.
    // (An empty truth array has no elements to check; it is not a violation.)
    await rewriteTruth(bundle, (truth) => {
      truth.lines = [{ description: "no key here" }];
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    await rewriteTruth(bundle, (truth) => {
      truth.lines = { notAnArray: true };
    });
    await expectCode(bundle, "truth_contract_invalid");
  });

  await withFixture(async (bundle) => {
    // A projected field may be explicitly null; this stays valid.
    await rewriteTruth(bundle, (truth) => {
      truth.lines[0].description = null;
    });
    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });

  await withFixture(async (bundle) => {
    // Unrelated model-only fields on elements stay allowed.
    await rewriteTruth(bundle, (truth) => {
      truth.lines[0].selfReportedConfidence = 0.9;
    });
    const result = await validateBundle(bundle);
    assert.equal(result.caseId, "synthetic-invoice-basic");
  });

  await withFixture(async (bundle) => {
    // Duplicate keys that appear only after normalization are rejected:
    // fullwidth "１" normalizes to "1", colliding with element 1's numeric key.
    await rewriteTruth(bundle, (truth) => {
      truth.lines[1].lineNo = "１";
      truth.lines[0].lineNo = "1";
    });
    await expectCode(bundle, "truth_contract_invalid");
  });
});

test("normalizes keys per the v1 whitespace and order rules", () => {
  const operations = ["nfkc", "trim", "collapse-whitespace"];
  assert.equal(normalizeKeyForComparison("  Widget   Alpha\u3000 ", operations), "Widget Alpha");
  assert.equal(normalizeKeyForComparison("１", operations), "1");
  assert.equal(normalizeKeyForComparison("\u00A0\u3000", operations), "");
});

test("rejects a manifest exactly one byte over the size limit", async () => {
  await withFixture(async (bundle) => {
    // {"synthetic":"<padding>"} sized to exactly MAX_JSON_BYTES + 1 bytes.
    const head = Buffer.from('{"synthetic":"', "utf8");
    const tail = Buffer.from('"}', "utf8");
    const padding = Buffer.alloc(MAX_JSON_BYTES + 1 - head.length - tail.length, 0x78);
    await writeFile(path.join(bundle, "bundle.json"), Buffer.concat([head, padding, tail]));
    await expectCode(bundle, "json_file_too_large");
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
  const error = await captureError(bundle);
  assert.equal(error.code, code);
}

async function captureError(bundle: string): Promise<BundleValidationError> {
  try {
    await validateBundle(bundle);
  } catch (error) {
    assert.ok(error instanceof BundleValidationError);
    return error;
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

  // Keep the manifest digest in sync with the mutated truth file.
  const manifestPath = path.join(bundle, "bundle.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
  if (manifest.inputs.truth) {
    manifest.inputs.truth.sha256 = createHash("sha256").update(updated, "utf8").digest("hex");
    await writeManifest(bundle, manifest);
  }
}
