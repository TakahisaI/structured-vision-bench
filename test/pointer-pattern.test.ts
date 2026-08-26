import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The shipped $defs patterns are the machine-readable half of the comparison
// pointer contract. This test keeps them honest inside npm test (the manual
// script scripts/verify-pointer-patterns.mjs checks the same cases).
const schema = JSON.parse(readFileSync("schemas/bundle-v1.schema.json", "utf8"));
const defs = schema.$defs;

function matches(defName: string, sample: string): boolean {
  return new RegExp(defs[defName]!.pattern, "u").test(sample);
}

function expectSet(defName: string, samples: [string, boolean][]): void {
  for (const [sample, expected] of samples) {
    assert.equal(
      matches(defName, sample),
      expected,
      `${defName} ${JSON.stringify(sample)} expected ${expected}`,
    );
  }
}

test("plainPointer treats embedded stars as literals and reserves whole-star segments", () => {
  expectSet("plainPointer", [
    // accepted: literal stars, including '**' and leading single stars
    ["/customer/name", true],
    ["/li*nes", true],
    ["/*field", true], // leading single star, not a whole-star segment
    ["/rows/*id", true],
    ["/*~0", true],
    ["/items/*code", true],
    ["/x*y/z", true],
    ["/li**nes", true],
    ["/**", true],
    ["/a/**", true],
    ["/**/b", true],
    ["/***", true],
    ["/a/b/c", true],
    ["/a~1b/c~0d", true],
    ["/~1", true], // escaped "/" as a property name
    // rejected
    ["/", false],
    ["/a/", false],
    ["/*", false],
    ["/a/*", false],
    ["/*/x", false],
    ["a", false],
    ["a/b", false],
    ["/a//b", false],
    ["/~2x", false],
    ["/a~b", false],
  ]);
});

test("relativeFieldPointer accepts one non-wildcard segment", () => {
  expectSet("relativeFieldPointer", [
    ["/amount", true],
    ["/line*No", true],
    ["/**", true],
    ["/a~1b", true],
    ["/", false],
    ["/*", false],
    ["/a/b", false],
    ["x", false],
  ]);
});

test("criticalPointer accepts nested scalars and single wildcard shapes", () => {
  expectSet("criticalPointer", [
    // scalar branch (any nesting depth)
    ["/totalAmount", true],
    ["/customer/name", true],
    ["/header/total", true],
    // wildcard branch
    ["/lines/*/amount", true],
    ["/li*nes/*/amount", true],
    ["/**/*/b", true], // array path "/**" is a literal name
    ["/*array/*/value", true], // array path "/*array" is a literal name
    ["/lines/*/*field", true], // field named "*field" via wildcard
    // rejected shapes
    ["/", false],
    ["/*", false],
    ["/*/x", false],
    ["/a/*", false],
    ["/*/b", false],
    ["/a/*/b/c", false],
  ]);
});

test("cross-field rules still reject what syntax allows", async () => {
  // "/lines/**" is syntactically a plain pointer, but as a critical it names a
  // whole declared array and must fail with comparison_contract_invalid.
  const { assertComparisonContract } = await import("../src/bundle/validate-bundle.js");
  const comparison = {
    scalars: [],
    arrays: [{ path: "/lines", key: "/lineNo", fields: ["/amount"] }],
    critical: ["/lines/**"],
  };
  assert.throws(
    () => assertComparisonContract(comparison),
    (error: unknown) =>
      typeof error === "object" && error !== null && (error as { code?: string }).code === "comparison_contract_invalid",
  );
});
