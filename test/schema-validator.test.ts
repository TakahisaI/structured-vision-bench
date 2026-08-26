import assert from "node:assert/strict";
import test from "node:test";

import { validateJsonSchema } from "../src/bundle/schema-validator.js";

test("validates required fields, constants, patterns, and additional properties", () => {
  const schema = {
    type: "object",
    required: ["version", "id"],
    properties: {
      version: { type: "integer", const: 1 },
      id: { type: "string", pattern: "^[a-z]+$" },
    },
    additionalProperties: false,
  };

  assert.deepEqual(validateJsonSchema(schema, { version: 1, id: "case" }), []);

  const issues = validateJsonSchema(schema, { version: 2, id: "Case", extra: true });
  assert.deepEqual(
    issues.map((issue) => issue.path),
    ["$.version", "$.id", "$"],
  );
});

test("reports unexpected properties by parent location and count only", () => {
  const schema = {
    type: "object",
    properties: {},
    additionalProperties: false,
  };
  // Synthetic marker stands in for a local absolute path or secret-shaped key.
  const marker = "/tmp/synthetic-local/secret-env-KEY=SYNTHETICVALUE";
  const issues = validateJsonSchema(schema, { [marker]: true });

  assert.deepEqual(issues, [{ path: "$", message: "has an unexpected property" }]);
  assert.ok(!JSON.stringify(issues).includes(marker), "unknown key name must not appear");
});

test("counts multiple unexpected properties in one bounded issue", () => {
  const schema = {
    type: "object",
    properties: { known: { type: "integer" } },
    additionalProperties: false,
  };
  const issues = validateJsonSchema(schema, { known: 1, mysteryA: true, mysteryB: true });
  assert.deepEqual(issues, [{ path: "$", message: "has 2 unexpected properties" }]);
});

test("validates arrays and uniqueness", () => {
  const schema = {
    type: "array",
    minItems: 1,
    uniqueItems: true,
    items: { type: "string", minLength: 2 },
  };

  const issues = validateJsonSchema(schema, ["a", "bb", "bb"]);
  assert.deepEqual(
    issues.map((issue) => issue.path),
    ["$[2]", "$[0]"],
  );
});

test("measures string length in Unicode code points, not UTF-16 code units", () => {
  // U+1F600 is one code point but two UTF-16 code units.
  const emoji = "\u{1F600}";
  assert.equal(emoji.length, 2);
  assert.equal([...emoji].length, 1);

  const schema = { type: "string", minLength: 127, maxLength: 128 };

  const atMinLength = validateJsonSchema(schema, emoji.repeat(127));
  assert.deepEqual(atMinLength, []);

  const atMaxLength = validateJsonSchema(schema, emoji.repeat(128));
  assert.deepEqual(atMaxLength, []);

  const belowMinLength = validateJsonSchema(schema, emoji.repeat(126));
  assert.deepEqual(belowMinLength, [{ path: "$", message: "must have at least 127 characters" }]);

  const aboveMaxLength = validateJsonSchema(schema, emoji.repeat(129));
  assert.deepEqual(aboveMaxLength, [{ path: "$", message: "must have at most 128 characters" }]);
});

test("resolves local $ref definitions alongside sibling keywords", () => {
  const schema = {
    type: "array",
    items: { $ref: "#/$defs/plainPointer" },
    uniqueItems: true,
    $defs: {
      plainPointer: { type: "string", pattern: "^/(?:[^/*~]|~[01])+$", maxLength: 8 },
      missing: { type: "string" },
    },
  };

  assert.deepEqual(validateJsonSchema(schema, ["/ok", "/also-ok"]), []);

  const issues = validateJsonSchema(schema, ["/*bad"]);
  assert.deepEqual(issues, [{ path: "$[0]", message: "must match ^/(?:[^/*~]|~[01])+$" }]);

  const lengthIssues = validateJsonSchema(schema, ["/way-too-long"]);
  assert.deepEqual(lengthIssues, [{ path: "$[0]", message: "must have at most 8 characters" }]);
});

test("reports an unresolvable local $ref", () => {
  const schema = { type: "object", properties: { x: { $ref: "#/$defs/missing" } } };
  const issues = validateJsonSchema(schema, { x: 1 });
  assert.deepEqual(issues.map((issue) => issue.message), ["unresolvable schema $ref #/$defs/missing"]);
});
