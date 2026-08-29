import assert from "node:assert/strict";
import test from "node:test";

import {
  isSanitizerFindingPath,
  sanitizerFindingPathIsAllowed,
  sanitizerFindingPathMatchesPatterns,
  snapshotSanitizerFindingPathPatterns,
} from "../src/runner/sanitizer-finding-path.js";

const PRE_SANITIZATION_DOCUMENT = {
  synthetic: { exact: "SYNTHETIC" },
  items: [{ note: "SYNTHETIC-A" }, { note: "SYNTHETIC-B" }],
  numericObject: { "0": { note: "SYNTHETIC-OBJECT" } },
};

test("matches consumer-owned exact paths", () => {
  const patterns = snapshotSanitizerFindingPathPatterns([
    "/synthetic/exact",
    "/items/0/note",
  ]);

  assert.equal(
    sanitizerFindingPathIsAllowed("/synthetic/exact", patterns, PRE_SANITIZATION_DOCUMENT),
    true,
  );
  assert.equal(
    sanitizerFindingPathIsAllowed("/items/0/note", patterns, PRE_SANITIZATION_DOCUMENT),
    true,
  );
  assert.equal(
    sanitizerFindingPathIsAllowed("/items/1/note", patterns, PRE_SANITIZATION_DOCUMENT),
    false,
  );
});

test("matches one wildcard only to an existing canonical array index", () => {
  const patterns = snapshotSanitizerFindingPathPatterns([
    "/items/*/note",
    "/synthetic/exact",
  ]);

  for (const path of ["/items/0/note", "/items/1/note"]) {
    assert.equal(
      sanitizerFindingPathIsAllowed(path, patterns, PRE_SANITIZATION_DOCUMENT),
      true,
    );
    assert.equal(sanitizerFindingPathMatchesPatterns(path, patterns), true);
  }
  for (const path of [
    "/items/01/note",
    "/items/+1/note",
    "/items/-1/note",
    "/items/1e0/note",
    "/items/-/note",
    "/items/4294967295/note",
    "/items/2/note",
    "/numericObject/0/note",
    "/items/0/note/extra",
  ]) {
    assert.equal(
      sanitizerFindingPathIsAllowed(path, patterns, PRE_SANITIZATION_DOCUMENT),
      false,
    );
  }
  assert.equal(sanitizerFindingPathMatchesPatterns("/items/2/note", patterns), true);
  assert.equal(sanitizerFindingPathMatchesPatterns("/items/01/note", patterns), false);
  assert.equal(
    sanitizerFindingPathIsAllowed(
      "/items/0/missing",
      snapshotSanitizerFindingPathPatterns(["/items/*/missing"]),
      PRE_SANITIZATION_DOCUMENT,
    ),
    true,
  );
});

test("accepts one wildcard pattern and rejects wildcard response paths and malformed allowlists", () => {
  assert.equal(isSanitizerFindingPath("/items/*/note"), false);
  assert.equal(isSanitizerFindingPath("/items/~0/note"), true);
  assert.deepEqual(snapshotSanitizerFindingPathPatterns(["/items/*/note"]), [
    "/items/*/note",
  ]);
  assert.deepEqual(snapshotSanitizerFindingPathPatterns(["/items/**/note"]), [
    "/items/**/note",
  ]);
  assert.throws(() => snapshotSanitizerFindingPathPatterns(["/items/*/*"]));
  assert.throws(() => snapshotSanitizerFindingPathPatterns(["/same", "/same"]));
  assert.throws(() => snapshotSanitizerFindingPathPatterns(["/invalid~path"]));
  assert.throws(() => snapshotSanitizerFindingPathPatterns([`/${"x".repeat(1024)}`]));
  assert.throws(() =>
    snapshotSanitizerFindingPathPatterns([
      `/${String.fromCharCode(0xd800)}`,
    ]),
  );
  assert.throws(() =>
    snapshotSanitizerFindingPathPatterns([
      `/${String.fromCharCode(0xdc00)}`,
    ]),
  );
  assert.deepEqual(snapshotSanitizerFindingPathPatterns(["/�"]), ["/�"]);
});
