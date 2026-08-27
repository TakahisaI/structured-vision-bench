import assert from "node:assert/strict";
import test from "node:test";

import type { JsonValue } from "../src/bundle/json.js";
import {
  validateJsonSchema,
  validateJsonSchemaDefinition,
} from "../src/bundle/schema-validator.js";

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
  assert.deepEqual(issues, [{ path: "$[0]", message: "does not match the string pattern" }]);

  const lengthIssues = validateJsonSchema(schema, ["/way-too-long"]);
  assert.deepEqual(lengthIssues, [{ path: "$[0]", message: "must have at most 8 characters" }]);
});

test("reports an unresolvable local $ref", () => {
  const schema = { type: "object", properties: { x: { $ref: "#/$defs/missing" } } };
  const issues = validateJsonSchema(schema, { x: 1 });
  assert.deepEqual(issues.map((issue) => issue.message), ["unresolvable schema reference"]);
});

test("enforces union, anyOf, and type-less properties", () => {
  assert.deepEqual(validateJsonSchema({ type: ["string", "null"] }, 42), [
    { path: "$", message: "has an invalid type" },
  ]);
  assert.deepEqual(validateJsonSchema({ anyOf: [{ type: "string" }, { type: "null" }] }, true), [
    { path: "$", message: "must match one of the allowed schemas" },
  ]);
  assert.deepEqual(validateJsonSchema({ properties: { value: { type: "string" } } }, { value: 42 }), [
    { path: "$.value", message: "has an invalid type" },
  ]);
});

test("applies type-specific keywords when the schema omits type", () => {
  assert.deepEqual(validateJsonSchema({ pattern: "^[a-z]+$" }, "SYNTHETIC"), [
    { path: "$", message: "does not match the string pattern" },
  ]);
  assert.deepEqual(validateJsonSchema({ minLength: 2 }, "S"), [
    { path: "$", message: "must have at least 2 characters" },
  ]);
  assert.deepEqual(validateJsonSchema({ minimum: 2 }, 1), [
    { path: "$", message: "must be at least 2" },
  ]);
  assert.deepEqual(validateJsonSchema({ minItems: 1 }, []), [
    { path: "$", message: "must contain at least 1 items" },
  ]);
  assert.deepEqual(validateJsonSchema({ minProperties: 1 }, {}), [
    { path: "$", message: "has too few properties" },
  ]);
});

test("rejects impossible calendar dates in date-time values", () => {
  assert.deepEqual(validateJsonSchema({ format: "date-time" }, "2024-02-30T00:00:00Z"), [
    { path: "$", message: "must be a valid date-time" },
  ]);
  assert.deepEqual(validateJsonSchema({ format: "date-time" }, "2024-02-29T23:59:59Z"), []);
});

test("does not echo pattern source in schema diagnostics", () => {
  const marker = "SYNTHETIC-SECRET-SHAPED-MARKER";
  const issues = validateJsonSchema({ pattern: `^${marker}$` }, "other");
  assert.deepEqual(issues, [{ path: "$", message: "does not match the string pattern" }]);
  assert.equal(JSON.stringify(issues).includes(marker), false);
});

test("rejects malformed schema keyword values and non-schema references", () => {
  assert.notDeepEqual(validateJsonSchemaDefinition({ uniqueItems: "true" }), []);
  assert.notDeepEqual(
    validateJsonSchemaDefinition({ $defs: { scalar: true }, $ref: "#/$defs/scalar" }),
    [],
  );
});

test("rejects recursive and excessively deep schema definitions", () => {
  const recursive = { $defs: { loop: { $ref: "#/$defs/loop" } }, $ref: "#/$defs/loop" };
  assert.notDeepEqual(validateJsonSchemaDefinition(recursive), []);
  assert.notDeepEqual(validateJsonSchema(recursive, "synthetic"), []);

  let deep: JsonValue = { type: "string" };
  for (let index = 0; index < 100; index += 1) deep = { not: deep };
  assert.notDeepEqual(validateJsonSchemaDefinition(deep), []);
  assert.notDeepEqual(validateJsonSchema(deep, "synthetic"), []);
});

test("rejects recursive references through schema containment edges", () => {
  const throughProperties = {
    $defs: {
      node: {
        type: "object",
        properties: { next: { $ref: "#/$defs/node" } },
      },
    },
    $ref: "#/$defs/node",
  };
  const throughItems = {
    $defs: { node: { type: "array", items: { $ref: "#/$defs/node" } } },
    $ref: "#/$defs/node",
  };
  const throughAnyOf = {
    $defs: {
      node: {
        anyOf: [{ type: "null" }, { $ref: "#/$defs/node" }],
      },
    },
    $ref: "#/$defs/node",
  };
  for (const schema of [throughProperties, throughItems, throughAnyOf]) {
    assert.notDeepEqual(validateJsonSchemaDefinition(schema), []);
  }
});

test("accepts a long acyclic reference chain and a shared reference DAG", () => {
  const definitions: Record<string, JsonValue> = {
    leaf: { type: "string" },
  };
  for (let index = 0; index < 20; index += 1) {
    const next = index === 0 ? "leaf" : `node-${index - 1}`;
    definitions[`node-${index}`] = { $ref: `#/$defs/${next}` };
  }
  const chain = { $defs: definitions, $ref: "#/$defs/node-19" };
  assert.deepEqual(validateJsonSchemaDefinition(chain), []);

  const shared = {
    $defs: { value: { type: "string", minLength: 1 } },
    type: "object",
    properties: {
      left: { $ref: "#/$defs/value" },
      right: { $ref: "#/$defs/value" },
    },
  };
  assert.deepEqual(validateJsonSchemaDefinition(shared), []);
});

test("checks the deepest route to a shared schema node during preflight", () => {
  let leaf: JsonValue = { type: "string" };
  for (let index = 0; index < 55; index += 1) leaf = { not: leaf };

  let branch: JsonValue = { $ref: "#/$defs/leaf" };
  for (let index = 0; index < 10; index += 1) branch = { not: branch };

  const schema = { $defs: { leaf }, allOf: [branch] } satisfies JsonValue;
  const issues = validateJsonSchemaDefinition(schema);
  assert.ok(issues.some((issue) => issue.message === "schema nesting is too deep"));
});

test("rejects unsupported or malformed output schemas before validation", () => {
  assert.notDeepEqual(validateJsonSchemaDefinition({ type: "object", unknownKeyword: true }), []);
  assert.notDeepEqual(validateJsonSchemaDefinition({ type: "string", pattern: "[" }), []);
});
