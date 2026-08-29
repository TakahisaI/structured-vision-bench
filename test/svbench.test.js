import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { BenchError, compareDocuments, loadCase, runCase, validateDocument } from "../src/svbench.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = path.join(ROOT, "fixtures", "synthetic-invoice");

async function copyFixture() {
  const target = await mkdtemp(path.join(os.tmpdir(), "svbench-"));
  await cp(FIXTURE, target, { recursive: true });
  return target;
}

test("runs one synthetic case with mock output", async () => {
  const result = await runCase({ caseDirectory: FIXTURE, mock: true });
  assert.equal(result.status, "pass");
  assert.equal(result.schemaValid, true);
  assert.equal(result.exactMatch, true);
  assert.deepEqual(result.schemaIssues, []);
  assert.deepEqual(result.comparisonIssues, []);
});

test("runs one local provider command", async () => {
  const result = await runCase({
    caseDirectory: FIXTURE,
    provider: process.execPath,
    providerArgs: [path.join(ROOT, "examples", "mock-provider.js")],
  });
  assert.equal(result.status, "pass");
  assert.equal(result.provider, path.basename(process.execPath));
});

test("reports truth differences without values", async () => {
  const target = await copyFixture();
  const outputPath = path.join(target, "mock-output.json");
  const output = JSON.parse(await readFile(outputPath, "utf8"));
  output.total = 999999;
  await writeFile(outputPath, JSON.stringify(output));

  const result = await runCase({ caseDirectory: target, mock: true });
  assert.equal(result.status, "fail");
  assert.deepEqual(result.comparisonIssues, [{ path: "/total", kind: "different" }]);
  assert.equal(JSON.stringify(result).includes("999999"), false);
  assert.equal(Object.hasOwn(result, "document"), false);
});

test("reports schema failures separately", async () => {
  const target = await copyFixture();
  const outputPath = path.join(target, "mock-output.json");
  const output = JSON.parse(await readFile(outputPath, "utf8"));
  delete output.invoiceNumber;
  await writeFile(outputPath, JSON.stringify(output));

  const result = await runCase({ caseDirectory: target, mock: true });
  assert.equal(result.status, "fail");
  assert.deepEqual(result.schemaIssues, [{ path: "/invoiceNumber", kind: "required" }]);
});

test("rejects files that escape the case directory", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "svbench-escape-"));
  const target = path.join(parent, "case");
  await cp(FIXTURE, target, { recursive: true });
  await writeFile(path.join(parent, "outside.svg"), "synthetic");
  const manifestPath = path.join(target, "case.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.image = "../outside.svg";
  await writeFile(manifestPath, JSON.stringify(manifest));

  await assert.rejects(() => loadCase(target), (error) => {
    assert.equal(error instanceof BenchError, true);
    assert.equal(error.code, "invalid_case");
    return true;
  });
});

test(
  "rejects a case manifest symlink that escapes the directory",
  { skip: process.platform === "win32" },
  async () => {
    const parent = await mkdtemp(path.join(os.tmpdir(), "svbench-manifest-"));
    const target = path.join(parent, "case");
    await cp(FIXTURE, target, { recursive: true });
    const outsideManifest = path.join(parent, "outside-case.json");
    await writeFile(outsideManifest, await readFile(path.join(target, "case.json")));
    await unlink(path.join(target, "case.json"));
    await symlink(outsideManifest, path.join(target, "case.json"));

    await assert.rejects(() => loadCase(target), (error) => {
      assert.equal(error instanceof BenchError, true);
      assert.equal(error.code, "invalid_case");
      return true;
    });
  },
);

test("rejects invalid UTF-8 in case text", async () => {
  const target = await copyFixture();
  await writeFile(path.join(target, "instruction.txt"), Buffer.from([0xc3, 0x28]));
  await assert.rejects(() => loadCase(target), (error) => {
    assert.equal(error instanceof BenchError, true);
    assert.equal(error.code, "invalid_case");
    return true;
  });
});

test("validates the documented schema subset", () => {
  const schema = {
    type: "object",
    required: ["id"],
    properties: { id: { type: "string" }, count: { type: "integer" } },
    additionalProperties: false,
  };
  assert.deepEqual(validateDocument(schema, { id: "x", count: 2 }), []);
  assert.deepEqual(validateDocument(schema, { id: "x", count: 2.5, extra: true }), [
    { path: "/count", kind: "type" },
    { path: "/extra", kind: "additional_property" },
  ]);
});

test("compares nested JSON with path-only issues", () => {
  assert.deepEqual(compareDocuments({ rows: [{ id: 1 }] }, { rows: [{ id: 2 }, { id: 3 }] }), [
    { path: "/rows/0/id", kind: "different" },
    { path: "/rows/1", kind: "extra" },
  ]);
});
