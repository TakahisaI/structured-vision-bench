import assert from "node:assert/strict";
import test from "node:test";

import {
  isSanitizerFindingPath,
  sanitizerFindingPathIsAllowed,
  snapshotSanitizerFindingPathPatterns,
} from "../src/runner/sanitizer-finding-path.js";

test("matches only consumer-owned exact paths", () => {
  const patterns = snapshotSanitizerFindingPathPatterns([
    "/synthetic/exact",
    "/items/0/note",
  ]);

  assert.equal(sanitizerFindingPathIsAllowed("/synthetic/exact", patterns), true);
  assert.equal(sanitizerFindingPathIsAllowed("/items/0/note", patterns), true);
  assert.equal(sanitizerFindingPathIsAllowed("/items/1/note", patterns), false);
  assert.equal(sanitizerFindingPathIsAllowed("/items/01/note", patterns), false);
  assert.equal(sanitizerFindingPathIsAllowed("/items/0/note/extra", patterns), false);
});

test("rejects wildcard response paths and malformed allowlists", () => {
  assert.equal(isSanitizerFindingPath("/items/*/note"), false);
  assert.equal(isSanitizerFindingPath("/items/~0/note"), true);
  assert.throws(() => snapshotSanitizerFindingPathPatterns(["/items/*/note"]));
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
