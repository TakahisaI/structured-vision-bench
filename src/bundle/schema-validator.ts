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
const MAX_SCHEMA_DEPTH = 64;
const JSON_SCHEMA_TYPES = new Set(["array", "boolean", "integer", "null", "number", "object", "string"]);
const SUPPORTED_KEYWORDS = new Set([
  "$defs",
  "$id",
  "$ref",
  "$schema",
  "additionalProperties",
  "allOf",
  "anyOf",
  "const",
  "enum",
  "format",
  "items",
  "maxItems",
  "maxLength",
  "maxProperties",
  "maximum",
  "minItems",
  "minLength",
  "minProperties",
  "minimum",
  "not",
  "oneOf",
  "pattern",
  "properties",
  "required",
  "title",
  "type",
  "uniqueItems",
]);

export function validateJsonSchema(schema: JsonValue, value: JsonValue): SchemaIssue[] {
  const issues: SchemaIssue[] = [];
  validateNode(schema, value, "$", issues, schema, 0, new Set());
  return issues.slice(0, MAX_ISSUES);
}

/** Validates the supported JSON Schema subset before it can reach a provider. */
export function validateJsonSchemaDefinition(schema: JsonValue): SchemaIssue[] {
  const issues: SchemaIssue[] = [];
  const state: SchemaDefinitionState = {
    seen: new Set(),
    references: new Map(),
  };
  validateSchemaDefinitionNode(schema, issues, schema, 0, state);
  if (!issueBudgetExceeded(issues) && hasReferenceCycle(state.references)) {
    issues.push({ path: "$", message: "schema contains a cyclic reference" });
  }
  return issues.slice(0, MAX_ISSUES);
}

type SchemaDefinitionState = {
  seen: Set<Record<string, JsonValue>>;
  references: Map<Record<string, JsonValue>, Record<string, JsonValue>>;
};

function validateSchemaDefinitionNode(
  value: JsonValue,
  issues: SchemaIssue[],
  rootSchema: JsonValue,
  depth: number,
  state: SchemaDefinitionState,
): void {
  if (issues.length >= MAX_ISSUES) return;
  if (depth > MAX_SCHEMA_DEPTH) {
    issues.push({ path: "$", message: "schema nesting is too deep" });
    return;
  }
  if (!isJsonObject(value)) {
    issues.push({ path: "$", message: "schema node must be an object" });
    return;
  }
  if (state.seen.has(value)) return;
  state.seen.add(value);
  for (const key of Object.keys(value)) {
    if (!SUPPORTED_KEYWORDS.has(key)) {
      issues.push({ path: "$", message: "schema contains an unsupported keyword" });
      if (issues.length >= MAX_ISSUES) return;
    }
  }
  if (value.$ref !== undefined) {
    const resolved =
      typeof value.$ref === "string" && value.$ref.startsWith("#")
        ? resolveLocalRef(rootSchema, value.$ref)
        : undefined;
    if (!isJsonObject(resolved)) {
      issues.push({ path: "$", message: "schema reference is invalid" });
    } else {
      state.references.set(value, resolved);
      validateSchemaDefinitionNode(resolved, issues, rootSchema, depth + 1, state);
    }
  }
  const type = value.type;
  if (
    type !== undefined &&
    ((typeof type !== "string" && !Array.isArray(type)) ||
      (Array.isArray(type) && (type.length === 0 || type.some((entry) => typeof entry !== "string"))) ||
      (typeof type === "string" && !JSON_SCHEMA_TYPES.has(type)) ||
      (Array.isArray(type) && type.some((entry) => typeof entry === "string" && !JSON_SCHEMA_TYPES.has(entry))))
  ) {
    issues.push({ path: "$", message: "schema type is invalid" });
  }
  if (value.pattern !== undefined) {
    if (typeof value.pattern !== "string") {
      issues.push({ path: "$", message: "schema pattern is invalid" });
    } else {
      try {
        new RegExp(value.pattern, "u");
      } catch {
        issues.push({ path: "$", message: "schema pattern is invalid" });
      }
    }
  }
  if (value.format !== undefined && value.format !== "date-time") {
    issues.push({ path: "$", message: "schema format is unsupported" });
  }
  validateRequiredKeyword(value.required, issues);
  validateEnumKeyword(value.enum, issues);
  validateBooleanKeyword(value.uniqueItems, issues);
  validateNumericKeywords(value, issues);
  validateSchemaObjectKeyword(value.properties, issues, rootSchema, depth, state);
  validateSchemaObjectKeyword(value.$defs, issues, rootSchema, depth, state);
  validateSchemaChild(value.additionalProperties, issues, true, rootSchema, depth, state);
  validateSchemaChild(value.items, issues, false, rootSchema, depth, state);
  validateSchemaChild(value.not, issues, false, rootSchema, depth, state);
  for (const keyword of ["anyOf", "oneOf", "allOf"] as const) {
    const alternatives = value[keyword];
    if (alternatives !== undefined) {
      if (!Array.isArray(alternatives) || alternatives.length === 0) {
        issues.push({ path: "$", message: `schema ${keyword} must contain alternatives` });
      } else {
        for (const alternative of alternatives) {
          validateSchemaDefinitionNode(alternative, issues, rootSchema, depth + 1, state);
          if (issueBudgetExceeded(issues)) return;
        }
      }
    }
  }
}

function validateSchemaObjectKeyword(
  value: JsonValue | undefined,
  issues: SchemaIssue[],
  rootSchema: JsonValue,
  depth: number,
  state: SchemaDefinitionState,
): void {
  if (value === undefined) return;
  if (!isJsonObject(value)) {
    issues.push({ path: "$", message: "schema object keyword is invalid" });
    return;
  }
  for (const child of Object.values(value)) {
    validateSchemaDefinitionNode(child, issues, rootSchema, depth + 1, state);
    if (issues.length >= MAX_ISSUES) return;
  }
}

function validateSchemaChild(
  value: JsonValue | undefined,
  issues: SchemaIssue[],
  allowBoolean: boolean,
  rootSchema: JsonValue,
  depth: number,
  state: SchemaDefinitionState,
): void {
  if (value === undefined) return;
  if (allowBoolean && typeof value === "boolean") return;
  validateSchemaDefinitionNode(value, issues, rootSchema, depth + 1, state);
}

function validateRequiredKeyword(value: JsonValue | undefined, issues: SchemaIssue[]): void {
  if (value === undefined) return;
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => typeof entry !== "string") ||
    new Set(value).size !== value.length
  ) {
    issues.push({ path: "$", message: "schema required is invalid" });
  }
}

function validateEnumKeyword(value: JsonValue | undefined, issues: SchemaIssue[]): void {
  if (value !== undefined && (!Array.isArray(value) || value.length === 0)) {
    issues.push({ path: "$", message: "schema enum is invalid" });
  }
}

function validateBooleanKeyword(value: JsonValue | undefined, issues: SchemaIssue[]): void {
  if (value !== undefined && typeof value !== "boolean") {
    issues.push({ path: "$", message: "schema boolean keyword is invalid" });
  }
}

function validateNumericKeywords(schema: Record<string, JsonValue>, issues: SchemaIssue[]): void {
  for (const key of ["minimum", "maximum"] as const) {
    if (schema[key] !== undefined && (typeof schema[key] !== "number" || !Number.isFinite(schema[key]))) {
      issues.push({ path: "$", message: "schema numeric bound is invalid" });
    }
  }
  for (const key of ["minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"] as const) {
    const value = schema[key];
    if (value !== undefined && (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)) {
      issues.push({ path: "$", message: "schema size bound is invalid" });
    }
  }
}

function resolveLocalRef(rootSchema: JsonValue, ref: string): JsonValue | undefined {
  if (!ref.startsWith("#")) return undefined;
  let pointer: string;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    return undefined;
  }
  if (pointer === "") return rootSchema;
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

function hasReferenceCycle(
  references: Map<Record<string, JsonValue>, Record<string, JsonValue>>,
): boolean {
  const visited = new Set<Record<string, JsonValue>>();
  for (const start of references.keys()) {
    const chain = new Set<Record<string, JsonValue>>();
    let current: Record<string, JsonValue> | undefined = start;
    while (current !== undefined) {
      if (chain.has(current)) return true;
      if (visited.has(current)) break;
      chain.add(current);
      visited.add(current);
      current = references.get(current);
    }
  }
  return false;
}

function validateNode(
  schemaValue: JsonValue,
  value: JsonValue,
  path: string,
  issues: SchemaIssue[],
  rootSchema: JsonValue,
  depth: number,
  activeRefs: Set<Record<string, JsonValue>>,
): void {
  if (depth > MAX_SCHEMA_DEPTH) {
    issues.push({ path, message: "schema nesting is too deep" });
    return;
  }
  if (!isJsonObject(schemaValue)) {
    issues.push({ path, message: "schema node must be an object" });
    return;
  }
  const schema = schemaValue;

  if (Object.hasOwn(schema, "anyOf")) {
    const alternatives = schema.anyOf;
    if (!Array.isArray(alternatives) || alternatives.length === 0) {
      issues.push({ path, message: "schema anyOf must contain alternatives" });
      return;
    }
    let matched = false;
    let fatalIssue: SchemaIssue | undefined;
    for (const alternative of alternatives) {
      const alternativeIssues: SchemaIssue[] = [];
      validateNode(alternative, value, path, alternativeIssues, rootSchema, depth + 1, activeRefs);
      fatalIssue ??= firstFatalSchemaIssue(alternativeIssues);
      if (fatalIssue !== undefined) break;
      if (alternativeIssues.length === 0) {
        matched = true;
        break;
      }
    }
    if (fatalIssue !== undefined) issues.push(fatalIssue);
    else if (!matched) issues.push({ path, message: "must match one of the allowed schemas" });
  }

  if (Object.hasOwn(schema, "oneOf")) {
    const alternatives = schema.oneOf;
    if (!Array.isArray(alternatives) || alternatives.length === 0) {
      issues.push({ path, message: "schema oneOf must contain alternatives" });
    } else {
      let matches = 0;
      for (const alternative of alternatives) {
        const alternativeIssues: SchemaIssue[] = [];
        validateNode(alternative, value, path, alternativeIssues, rootSchema, depth + 1, activeRefs);
        const fatalIssue = firstFatalSchemaIssue(alternativeIssues);
        if (fatalIssue !== undefined) {
          issues.push(fatalIssue);
          return;
        }
        if (alternativeIssues.length === 0) matches += 1;
      }
      if (matches !== 1) issues.push({ path, message: "must match exactly one allowed schema" });
    }
  }

  if (Object.hasOwn(schema, "allOf")) {
    const alternatives = schema.allOf;
    if (!Array.isArray(alternatives) || alternatives.length === 0) {
      issues.push({ path, message: "schema allOf must contain alternatives" });
    } else {
      for (const alternative of alternatives) {
        validateNode(alternative, value, path, issues, rootSchema, depth + 1, activeRefs);
        if (issueBudgetExceeded(issues)) return;
      }
    }
  }

  if (Object.hasOwn(schema, "not")) {
    const alternativeIssues: SchemaIssue[] = [];
    if (schema.not !== undefined) {
      validateNode(schema.not, value, path, alternativeIssues, rootSchema, depth + 1, activeRefs);
    }
    else alternativeIssues.push({ path, message: "schema node must be an object" });
    const fatalIssue = firstFatalSchemaIssue(alternativeIssues);
    if (fatalIssue !== undefined) issues.push(fatalIssue);
    else if (alternativeIssues.length === 0) issues.push({ path, message: "must not match the schema" });
  }

  // Draft 2020-12 allows $ref alongside sibling keywords; both must hold. Only
  // local "#/..." references are supported, which is all the bundled contract
  // schema uses.
  if (Object.hasOwn(schema, "$ref") && typeof schema.$ref === "string" && rootSchema !== undefined) {
    const resolved = resolveLocalRef(rootSchema, schema.$ref);
    if (resolved === undefined) {
      issues.push({ path, message: "unresolvable schema reference" });
      return;
    }
    if (!isJsonObject(resolved) || resolved === schema || activeRefs.has(resolved)) {
      issues.push({ path, message: "cyclic or invalid schema reference" });
      return;
    }
    activeRefs.add(resolved);
    try {
      validateNode(resolved, value, path, issues, rootSchema, depth + 1, activeRefs);
    } finally {
      activeRefs.delete(resolved);
    }
  }

  if (Object.hasOwn(schema, "const") && !isDeepStrictEqual(value, schema.const)) {
    issues.push({ path, message: "must equal the required constant" });
    return;
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((item) => isDeepStrictEqual(item, value))) {
    issues.push({ path, message: "must match one allowed value" });
    return;
  }

  const types = schemaTypes(schema.type);
  if (schema.type !== undefined && (types.length === 0 || !matchesType(types, value))) {
    issues.push({ path, message: "has an invalid type" });
    return;
  }

  if (issueBudgetExceeded(issues)) return;

  if (
    isJsonObject(value) &&
    (types.length === 0 || types.includes("object")) &&
    (types.includes("object") ||
      schema.properties !== undefined ||
      schema.required !== undefined ||
      schema.additionalProperties !== undefined ||
      schema.minProperties !== undefined ||
      schema.maxProperties !== undefined)
  ) {
    validateObject(schema, value, path, issues, rootSchema, depth, activeRefs);
  }
  if (
    Array.isArray(value) &&
    (types.length === 0 || types.includes("array")) &&
    (types.includes("array") ||
      schema.items !== undefined ||
      schema.uniqueItems !== undefined ||
      schema.minItems !== undefined ||
      schema.maxItems !== undefined)
  ) {
    validateArray(schema, value, path, issues, rootSchema, depth, activeRefs);
  }
  if ((types.length === 0 || types.includes("string")) && typeof value === "string") {
    validateString(schema, value, path, issues);
  }
  if (
    (types.length === 0 || types.includes("number") || types.includes("integer")) &&
    typeof value === "number"
  ) {
    validateNumber(schema, value, path, issues);
  }
}

function validateObject(
  schema: Record<string, JsonValue>,
  value: Record<string, JsonValue>,
  path: string,
  issues: SchemaIssue[],
  rootSchema: JsonValue,
  depth: number,
  activeRefs: Set<Record<string, JsonValue>>,
): void {
  if (typeof schema.minProperties === "number" && Object.keys(value).length < schema.minProperties) {
    issues.push({ path, message: "has too few properties" });
  }
  if (typeof schema.maxProperties === "number" && Object.keys(value).length > schema.maxProperties) {
    issues.push({ path, message: "has too many properties" });
  }
  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  for (const key of required) {
    if (!Object.hasOwn(value, key)) issues.push({ path: `${path}.${key}`, message: "is required" });
    if (issueBudgetExceeded(issues)) return;
  }

  const properties = isJsonObject(schema.properties) ? schema.properties : {};
  let disallowedCount = 0;
  let firstDisallowedPath: string | undefined;
  for (const [key, child] of Object.entries(value)) {
    // properties lookup is own-property only, so "__proto__" cannot resolve to
    // Object.prototype and bypass additionalProperties: false.
    const childSchema = Object.hasOwn(properties, key) ? properties[key] : undefined;
    if (childSchema !== undefined) {
      validateNode(childSchema, child, `${path}.${key}`, issues, rootSchema, depth + 1, activeRefs);
      continue;
    }
    if (schema.additionalProperties === false) {
      // Never echo the unknown key itself: a manifest key can carry a local
      // path or secret-shaped text that must not reach logs. Report the parent
      // location and count instead.
      disallowedCount += 1;
      firstDisallowedPath ??= path;
    } else if (isJsonObject(schema.additionalProperties)) {
      validateNode(schema.additionalProperties, child, `${path}.${key}`, issues, rootSchema, depth + 1, activeRefs);
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
  depth: number,
  activeRefs: Set<Record<string, JsonValue>>,
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
      validateNode(schema.items!, item, `${path}[${index}]`, issues, rootSchema, depth + 1, activeRefs);
      if (issues.length >= MAX_ISSUES) return;
    }
  }
}

function issueBudgetExceeded(issues: SchemaIssue[]): boolean {
  return issues.length >= MAX_ISSUES;
}

function firstFatalSchemaIssue(issues: SchemaIssue[]): SchemaIssue | undefined {
  return issues.find(
    (issue) =>
      issue.message === "schema nesting is too deep" ||
      issue.message === "cyclic or invalid schema reference",
  );
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
  if (typeof schema.pattern === "string") {
    try {
      if (!new RegExp(schema.pattern, "u").test(value)) {
        issues.push({ path, message: "does not match the string pattern" });
      }
    } catch {
      issues.push({ path, message: "schema pattern is invalid" });
    }
  }
  if (schema.format === "date-time" && !isDateTime(value)) {
    issues.push({ path, message: "must be a valid date-time" });
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

function schemaTypes(value: JsonValue | undefined): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function matchesType(types: string[], value: JsonValue): boolean {
  return types.some((type) => {
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
  });
}

function isDateTime(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/u.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  if (match[7] !== "Z" && (Number(match[8]) > 23 || Number(match[9]) > 59)) return false;
  return true;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}
