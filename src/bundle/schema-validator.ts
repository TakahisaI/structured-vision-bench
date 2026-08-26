import { isDeepStrictEqual } from "node:util";

import { isJsonObject, type JsonValue } from "./json.js";

export type SchemaIssue = {
  path: string;
  message: string;
};

export function validateJsonSchema(schema: JsonValue, value: JsonValue): SchemaIssue[] {
  const issues: SchemaIssue[] = [];
  validateNode(schema, value, "$", issues);
  return issues;
}

function validateNode(
  schemaValue: JsonValue,
  value: JsonValue,
  path: string,
  issues: SchemaIssue[],
): void {
  if (!isJsonObject(schemaValue)) {
    issues.push({ path, message: "schema node must be an object" });
    return;
  }
  const schema = schemaValue;

  if ("const" in schema && !isDeepStrictEqual(value, schema.const)) {
    issues.push({ path, message: `must equal ${JSON.stringify(schema.const)}` });
    return;
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((item) => isDeepStrictEqual(item, value))) {
    issues.push({ path, message: `must be one of ${JSON.stringify(schema.enum)}` });
    return;
  }

  const type = typeof schema.type === "string" ? schema.type : undefined;
  if (type !== undefined && !matchesType(type, value)) {
    issues.push({ path, message: `must be ${type}` });
    return;
  }

  if (type === "object" && isJsonObject(value)) validateObject(schema, value, path, issues);
  if (type === "array" && Array.isArray(value)) validateArray(schema, value, path, issues);
  if (type === "string" && typeof value === "string") validateString(schema, value, path, issues);
  if ((type === "number" || type === "integer") && typeof value === "number") {
    validateNumber(schema, value, path, issues);
  }
}

function validateObject(
  schema: Record<string, JsonValue>,
  value: Record<string, JsonValue>,
  path: string,
  issues: SchemaIssue[],
): void {
  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  for (const key of required) {
    if (!(key in value)) issues.push({ path: `${path}.${key}`, message: "is required" });
  }

  const properties = isJsonObject(schema.properties) ? schema.properties : {};
  for (const [key, child] of Object.entries(value)) {
    const childSchema = properties[key];
    if (childSchema !== undefined) {
      validateNode(childSchema, child, `${path}.${key}`, issues);
      continue;
    }
    if (schema.additionalProperties === false) {
      issues.push({ path: `${path}.${key}`, message: "is not allowed" });
    }
  }
}

function validateArray(
  schema: Record<string, JsonValue>,
  value: JsonValue[],
  path: string,
  issues: SchemaIssue[],
): void {
  if (typeof schema.minItems === "number" && value.length < schema.minItems) {
    issues.push({ path, message: `must contain at least ${schema.minItems} items` });
  }
  if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
    issues.push({ path, message: `must contain at most ${schema.maxItems} items` });
  }
  if (schema.uniqueItems === true) {
    for (let index = 0; index < value.length; index += 1) {
      for (let other = index + 1; other < value.length; other += 1) {
        if (isDeepStrictEqual(value[index], value[other])) {
          issues.push({ path: `${path}[${other}]`, message: "must be unique" });
        }
      }
    }
  }
  if (schema.items !== undefined) {
    value.forEach((item, index) => validateNode(schema.items!, item, `${path}[${index}]`, issues));
  }
}

function validateString(
  schema: Record<string, JsonValue>,
  value: string,
  path: string,
  issues: SchemaIssue[],
): void {
  if (typeof schema.minLength === "number" && value.length < schema.minLength) {
    issues.push({ path, message: `must have at least ${schema.minLength} characters` });
  }
  if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
    issues.push({ path, message: `must have at most ${schema.maxLength} characters` });
  }
  if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
    issues.push({ path, message: `must match ${schema.pattern}` });
  }
}

function validateNumber(
  schema: Record<string, JsonValue>,
  value: number,
  path: string,
  issues: SchemaIssue[],
): void {
  if (typeof schema.minimum === "number" && value < schema.minimum) {
    issues.push({ path, message: `must be at least ${schema.minimum}` });
  }
  if (typeof schema.maximum === "number" && value > schema.maximum) {
    issues.push({ path, message: `must be at most ${schema.maximum}` });
  }
}

function matchesType(type: string, value: JsonValue): boolean {
  switch (type) {
    case "object":
      return isJsonObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      return false;
  }
}
