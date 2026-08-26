import { createHash } from "node:crypto";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

import { isJsonObject, parseJson, type JsonValue } from "./json.js";
import { validateJsonSchema } from "./schema-validator.js";

const MANIFEST_NAME = "bundle.json";
export const MAX_JSON_BYTES = 4 * 1024 * 1024;

type FileReference = {
  path: string;
  sha256: string;
};

export type BundleValidationResult = {
  caseId: string;
  referencedFiles: number;
  bundleVersion: 1;
};

export class BundleValidationError extends Error {
  readonly code: string;
  readonly details: string[];

  constructor(code: string, message: string, details: string[] = []) {
    super(message);
    this.name = "BundleValidationError";
    this.code = code;
    this.details = details;
  }
}

export async function validateBundle(
  bundleDirectory: string,
  contractSchemaPath = path.resolve("schemas/bundle-v1.schema.json"),
): Promise<BundleValidationResult> {
  await assertBundleRoot(bundleDirectory);
  const root = await realpath(bundleDirectory);
  const manifestPath = path.join(root, MANIFEST_NAME);
  await assertManifestFile(manifestPath);

  const manifest = await readJsonFile(manifestPath, MANIFEST_NAME, MAX_JSON_BYTES);
  const contractSchema = await readJsonFile(contractSchemaPath, "bundle v1 schema", MAX_JSON_BYTES);
  const schemaIssues = validateJsonSchema(contractSchema, manifest);
  if (schemaIssues.length > 0) {
    throw new BundleValidationError(
      "manifest_schema_invalid",
      "bundle.json does not conform to bundle v1",
      boundDetails(schemaIssues.map((issue) => `${issue.path}: ${issue.message}`)),
    );
  }
  if (!isJsonObject(manifest)) {
    throw new BundleValidationError("manifest_schema_invalid", "bundle.json must be an object");
  }

  assertComparisonContract(manifest.comparison ?? null);

  const inputs = manifest.inputs;
  if (!isJsonObject(inputs)) {
    throw new BundleValidationError("manifest_schema_invalid", "bundle.json inputs must be an object");
  }

  const references = collectReferences(inputs);
  for (const [label, reference] of references) {
    const absolute = await resolveReferencedFile(root, reference.path, label);
    const digest = await sha256File(absolute);
    if (digest !== reference.sha256) {
      throw new BundleValidationError(
        "digest_mismatch",
        `${label} digest does not match bundle.json`,
      );
    }
  }

  await readJsonFile(
    await resolveReferencedFile(root, requireReference(inputs, "schema").path, "inputs.schema"),
    "inputs.schema",
    MAX_JSON_BYTES,
  );
  if ("truth" in inputs) {
    await readJsonFile(
      await resolveReferencedFile(root, requireReference(inputs, "truth").path, "inputs.truth"),
      "inputs.truth",
      MAX_JSON_BYTES,
    );
  }

  return {
    caseId: String(manifest.caseId),
    referencedFiles: references.length,
    bundleVersion: 1,
  };
}

async function assertBundleRoot(bundleDirectory: string): Promise<void> {
  let info;
  try {
    info = await lstat(bundleDirectory);
  } catch {
    throw new BundleValidationError("bundle_not_found", "bundle directory does not exist");
  }
  if (info.isSymbolicLink()) {
    throw new BundleValidationError("bundle_root_symlink", "bundle directory must not be a symlink");
  }
  if (!info.isDirectory()) {
    throw new BundleValidationError("bundle_not_directory", "bundle path must be a directory");
  }
}

async function assertManifestFile(manifestPath: string): Promise<void> {
  let info;
  try {
    info = await lstat(manifestPath);
  } catch {
    throw new BundleValidationError("bundle_manifest_missing", "bundle.json is missing");
  }
  if (info.isSymbolicLink()) {
    throw new BundleValidationError("bundle_manifest_symlink", "bundle.json must not be a symlink");
  }
  if (!info.isFile()) {
    throw new BundleValidationError("bundle_manifest_not_regular", "bundle.json must be a regular file");
  }
}

function collectReferences(inputs: Record<string, JsonValue>): [string, FileReference][] {
  const keys = ["image", "schema", "system", "instruction", "truth"];
  const references: [string, FileReference][] = [];
  for (const key of keys) {
    if (!(key in inputs)) continue;
    references.push([`inputs.${key}`, requireReference(inputs, key)]);
  }
  return references;
}

function requireReference(inputs: Record<string, JsonValue>, key: string): FileReference {
  const value = inputs[key];
  if (!isJsonObject(value) || typeof value.path !== "string" || typeof value.sha256 !== "string") {
    throw new BundleValidationError(
      "manifest_schema_invalid",
      `inputs.${key} must be a file reference`,
    );
  }
  return { path: value.path, sha256: value.sha256 };
}

async function resolveReferencedFile(root: string, manifestPath: string, label: string): Promise<string> {
  assertSafeRelativePath(manifestPath, label);
  const absolute = path.join(root, ...manifestPath.split("/"));

  let info;
  try {
    info = await lstat(absolute);
  } catch {
    throw new BundleValidationError("referenced_file_missing", `${label} is missing`);
  }
  if (info.isSymbolicLink()) {
    throw new BundleValidationError("referenced_file_symlink", `${label} must not be a symlink`);
  }
  if (!info.isFile()) {
    throw new BundleValidationError("referenced_file_not_regular", `${label} must be a regular file`);
  }

  const canonical = await realpath(absolute);
  const relative = path.relative(root, canonical);
  const outsideRoot =
    relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
  if (outsideRoot) {
    throw new BundleValidationError(
      "referenced_file_outside_bundle",
      `${label} resolves outside bundle`,
    );
  }
  return canonical;
}

function assertSafeRelativePath(value: string, label: string): void {
  if (value.length === 0 || value.includes("\\") || value.includes("\0")) {
    throw new BundleValidationError("unsafe_reference_path", `${label} has an unsafe path`);
  }
  if (path.posix.isAbsolute(value)) {
    throw new BundleValidationError("unsafe_reference_path", `${label} must use a relative path`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new BundleValidationError("unsafe_reference_path", `${label} has an unsafe path segment`);
  }
  if (path.posix.normalize(value) !== value) {
    throw new BundleValidationError("unsafe_reference_path", `${label} path must be normalized`);
  }
}

async function readJsonFile(file: string, label: string, maxBytes: number | null): Promise<JsonValue> {
  let info;
  try {
    info = await stat(file);
  } catch {
    throw new BundleValidationError("json_file_missing", `${label} is missing`);
  }
  if (maxBytes !== null && info.size > maxBytes) {
    throw new BundleValidationError(
      "json_file_too_large",
      `${label} exceeds the ${formatLimit(maxBytes)} limit`,
    );
  }

  let source;
  try {
    source = await readFile(file, "utf8");
  } catch {
    throw new BundleValidationError("json_file_unreadable", `${label} could not be read`);
  }
  try {
    return parseJson(source, label);
  } catch (error) {
    throw new BundleValidationError(
      "json_file_invalid",
      error instanceof Error ? error.message : `${label} is invalid`,
    );
  }
}

function formatLimit(maxBytes: number): string {
  const mebibytes = maxBytes / (1024 * 1024);
  return Number.isInteger(mebibytes) ? `${mebibytes} MiB` : `${maxBytes} byte`;
}

async function sha256File(file: string): Promise<string> {
  const content = await readFile(file);
  return createHash("sha256").update(content).digest("hex");
}

// --- Bounded diagnostics ----------------------------------------------------
// Unknown keys, secret-shaped strings, and absolute paths must never reach
// logs. Details are capped in count and per-message length; omitted entries
// are summarized instead of printed.

const MAX_DETAIL_MESSAGES = 20;
const MAX_DETAIL_LENGTH = 240;

export function boundDetails(details: string[]): string[] {
  const bounded = details.slice(0, MAX_DETAIL_MESSAGES).map((detail) => truncateDetail(detail));
  const omitted = details.length - bounded.length;
  if (omitted > 0) bounded.push(`${omitted} additional issues omitted`);
  return bounded;
}

function truncateDetail(detail: string): string {
  return detail.length <= MAX_DETAIL_LENGTH ? detail : `${detail.slice(0, MAX_DETAIL_LENGTH)}…`;
}

// --- Comparison path contract ------------------------------------------------
// v1 comparison paths are RFC 6901 JSON Pointer with one extension:
//
//   - A segment that is exactly "*" matches every element of the array at the
//     remaining prefix ("wildcard").
//   - Wildcards are allowed only in critical entries, at most one per pointer,
//     and never as the last segment. "*" inside a segment (for example "/a*b")
//     is a literal name. scalars and arrays paths are plain pointers.
//   - A critical entry must be either a declared scalar or
//     "<declared-array-path>/*/<field declared by that array>".
//
// Syntax-level violations are rejected by the JSON Schema patterns. The checks
// here enforce the cross-field rules that a static schema cannot express.

function comparisonContractError(message: string): BundleValidationError {
  return new BundleValidationError("comparison_contract_invalid", message);
}

export function assertComparisonContract(comparison: JsonValue): void {
  if (!isJsonObject(comparison)) {
    // The schema already rejected a missing or non-object comparison.
    throw comparisonContractError("comparison must be an object");
  }

  const scalars = collectPointerList(comparison.scalars ?? null);
  const arrays = Array.isArray(comparison.arrays) ? comparison.arrays : [];
  const scalarPaths = new Set(scalars);
  const arrayPaths = new Set<string>();
  const fieldsByArrayPath = new Map<string, Set<string>>();

  for (const entry of arrays) {
    if (!isJsonObject(entry)) continue;
    const entryPath = entry.path;
    if (typeof entryPath !== "string") continue;
    if (arrayPaths.has(entryPath)) {
      throw comparisonContractError(`arrays entry declares the same array path twice: ${entryPath}`);
    }
    arrayPaths.add(entryPath);

    const fields = Array.isArray(entry.fields)
      ? entry.fields.filter((field): field is string => typeof field === "string")
      : [];
    const keyFields = typeof entry.key === "string" ? [entry.key] : [];
    fieldsByArrayPath.set(entryPath, new Set([...keyFields, ...fields]));
  }

  for (const scalar of scalars) {
    if (arrayPaths.has(scalar)) {
      throw comparisonContractError(`scalars entry duplicates a declared array path: ${scalar}`);
    }
  }

  const criticals = collectPointerList(comparison.critical ?? null);
  for (const critical of criticals) {
    if (fieldsByArrayPath.has(critical)) {
      throw comparisonContractError(
        `critical entry must select a scalar or an array element field, not the whole array: ${critical}`,
      );
    }
    if (scalarPaths.has(critical)) continue;
    const wildcardField = splitWildcardField(critical);
    if (wildcardField === undefined) {
      throw comparisonContractError(
        `critical entry must be a declared scalar or "<array>/*/<field>": ${critical}`,
      );
    }
    const [arrayPath, field] = wildcardField;
    const fields = fieldsByArrayPath.get(arrayPath);
    if (fields === undefined) {
      throw comparisonContractError(
        `critical entry uses an undeclared array path: ${critical} (declare "${arrayPath}" in comparison.arrays first)`,
      );
    }
    if (!fields.has(field)) {
      throw comparisonContractError(
        `critical entry uses a field not compared for its array: ${critical} (add "${field}" to key or fields of "${arrayPath}")`,
      );
    }
  }
}

function collectPointerList(value: JsonValue): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

/**
 * Matches a pointer shaped like an array path, one wildcard segment, and a
 * single field. Returns undefined when the pointer does not have that shape.
 */
function splitWildcardField(pointer: string): [string, string] | undefined {
  const segments = pointer.split("/");
  const wildcardIndex = segments.indexOf("*");
  if (wildcardIndex < 1 || wildcardIndex !== segments.length - 2 || segments.lastIndexOf("*") !== wildcardIndex) {
    return undefined;
  }
  const arrayPath = segments.slice(0, wildcardIndex).join("/");
  const rawField = segments[wildcardIndex + 1]!;
  if (rawField.length === 0) return undefined;
  const field = `/${rawField}`;
  return [arrayPath, field];
}
