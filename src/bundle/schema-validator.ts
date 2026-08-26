import { isDeepStrictEqual } from "node:util";

import { isJsonObject, type JsonValue } from "./json.js";

export type SchemaIssue = {
  path: string;
  message: string;
};

// RFC 6901 array indices are "0" or digits without a leading zero.
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/u;

// Cap on collected issues so a hostile document cannot exhaust memory through
// quadratic uniqueItems comparisons before boundedDetails runs.
const MAX_ISSUES = 200;

export function validateJsonSchema(schema: JsonValue, value: JsonValue): SchemaIssue[] {
  const issues: SchemaIssue[] = [];
  validateNode(schema, value, "$", issues, schema);
  return issues;
}

function resolveLocalRef(rootSchema: JsonValue, ref: string): JsonValue | undefined {
  if (!ref.startsWith("#")) return undefined;
  const pointer = decodeURIComponent(ref.slice(1));
  if (pointer === "" ) return rootSchema;
  if (!pointer.startsWith("/")) return undefined;
  let current: JsonValue = rootSchema;
  for (const rawSegment of pointer.slice(1).split("/")) {
    const segment = rawSegment.replace(/~1/gu, "/").replace(/~0/gu, "~");
    if (Array.isArray(current)) {
      if (!ARRAY_INDEX_PATTERN.test(segment)) return undefined;
      const index = Number(segment);
      if (index >= current.length) return undefined;
      current = current[index]!;
      continue;
    }
    // hasOwn keeps inherited members out of $ref resolution.
    if (isJsonObject(current) && Object.hasOwn(current, segment)) {
      current = current[segment]!;
      continue;
    }
    return undefined;
  }
  return current;
}

function validateNode(
  schemaValue: JsonValue,
  value: JsonValue,
  path: string,
  issues: SchemaIssue[],
  rootSchema?: JsonValue,
): void {
  if (!isJsonObject(schemaValue)) {
    issues.push({ path, message: "schema node must be an object" });
    return;
  }
  const schema = schemaValue;

  // Draft 2020-12 allows $ref alongside sibling keywords; both must hold. Only
  // local "#/..." references are supported, which is all the bundled contract
  // schema uses.
  if (Object.hasOwn(schema, "$ref") && typeof schema.$ref === "string" && rootSchema !== undefined) {
    const resolved = resolveLocalRef(rootSchema, schema.$ref);
    if (resolved === undefined) {
      issues.push({ path, message: `unresolvable schema $ref ${schema.$ref}` });
      return;
    }
    validateNode(resolved, value, path, issues, rootSchema);
  }

  if (Object.hasOwn(schema, "const") && !isDeepStrictEqual(value, schema.const)) {
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

  if (issueBudgetExceeded(issues)) return;

  const root = rootSchema ?? schema;
  if (type === "object" && isJsonObject(value)) validateObject(schema, value, path, issues, root);
  if (type === "array" && Array.isArray(value)) validateArray(schema, value, path, issues, root);
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
  rootSchema: JsonValue,
): void {
  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  for (const key of required) {
    if (!Object.hasOwn(value, key)) issues.push({ path: `${path}.${key}`, message: "is required" });
  }

  const properties = isJsonObject(schema.properties) ? schema.properties : {};
  let disallowedCount = 0;
  let firstDisallowedPath: string | undefined;
  for (const [key, child] of Object.entries(value)) {
    // properties lookup is own-property only, so "__proto__" cannot resolve to
    // Object.prototype and bypass additionalProperties: false.
    const childSchema = Object.hasOwn(properties, key) ? properties[key] : undefined;
    if (childSchema !== undefined) {
      validateNode(childSchema, child, `${path}.${key}`, issues, rootSchema);
      continue;
    }
    if (schema.additionalProperties === false) {
      // Never echo the unknown key itself: a manifest key can carry a local
      // path or secret-shaped text that must not reach logs. Report the parent
      // location and count instead.
      disallowedCount += 1;
      firstDisallowedPath ??= path;
    }
  }
  if (disallowedCount > 0) {
    issues.push({
      path: firstDisallowedPath!,
      message:
        disallowedCount === 1
          ? "has an unexpected property"
          : `has ${disallowedCount} unexpected properties`,
    });
  }
}

function validateArray(
  schema: Record<string, JsonValue>,
  value: JsonValue[],
  path: string,
  issues: SchemaIssue[],
  rootSchema: JsonValue,
): void {
  if (typeof schema.minItems === "number" && value.length < schema.minItems) {
    issues.push({ path, message: `must contain at least ${schema.minItems} items` });
  }
  if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
    issues.push({ path, message: `must contain at most ${schema.maxItems} items` });
  }
  if (schema.uniqueItems === true) {
    // Linear scan over canonical encodings: object keys are sorted so that
    // member order cannot hide a duplicate ({a:1,b:2} === {b:2,a:1}).
    const seen = new Map<string, number>();
    for (const [index, item] of value.entries()) {
      const encoded = canonicalEncode(item);
      const firstIndex = seen.get(encoded);
      if (firstIndex !== undefined) {
        issues.push({ path: `${path}[${index}]`, message: "must be unique" });
        if (issues.length >= MAX_ISSUES) return;
        continue;
      }
      seen.set(encoded, index);
    }
  }
  if (schema.items !== undefined) {
    for (const [index, item] of value.entries()) {
      validateNode(schema.items!, item, `${path}[${index}]`, issues, rootSchema);
      if (issues.length >= MAX_ISSUES) return;
    }
  }
}

function issueBudgetExceeded(issues: SchemaIssue[]): boolean {
  return issues.length >= MAX_ISSUES;
}

/** Canonical encoding for duplicate detection: object keys sorted recursively. */
function canonicalEncode(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "number":
    case "boolean":
      return String(value);
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalEncode(item)).join(",")}]`;
      }
      return `{${Object.keys(value)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalEncode(value[key]!)}`)
        .join(",")}}`;
    default:
      // JSON values are always one of the above; unreachable in practice.
      return String(value);
  }
}

// JSON Schema measures string lengths in Unicode code points, not UTF-16 code
// units, so surrogate pairs count as one character.
function stringLength(value: string): number {
  return [...value].length;
}

function validateString(
  schema: Record<string, JsonValue>,
  value: string,
  path: string,
  issues: SchemaIssue[],
): void {
  if (typeof schema.minLength === "number" && stringLength(value) < schema.minLength) {
    issues.push({ path, message: `must have at least ${schema.minLength} characters` });
  }
  if (typeof schema.maxLength === "number" && stringLength(value) > schema.maxLength) {
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
