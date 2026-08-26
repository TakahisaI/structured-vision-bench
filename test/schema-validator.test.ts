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
    ["$.version", "$.id", "$.extra"],
  );
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
