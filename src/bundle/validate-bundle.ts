import { createHash } from "node:crypto";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

import { isJsonObject, parseJson, type JsonValue } from "./json.js";
import { validateJsonSchema } from "./schema-validator.js";

const MANIFEST_NAME = "bundle.json";
const MAX_JSON_BYTES = 4 * 1024 * 1024;

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

  const manifest = await readJsonFile(path.join(root, MANIFEST_NAME), MANIFEST_NAME);
  const contractSchema = await readJsonFile(contractSchemaPath, "bundle v1 schema");
  const schemaIssues = validateJsonSchema(contractSchema, manifest);
  if (schemaIssues.length > 0) {
    throw new BundleValidationError(
      "manifest_schema_invalid",
      "bundle.json does not conform to bundle v1",
      schemaIssues.map((issue) => `${issue.path}: ${issue.message}`),
    );
  }
  if (!isJsonObject(manifest)) {
    throw new BundleValidationError("manifest_schema_invalid", "bundle.json must be an object");
  }

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
        [`${reference.path}: expected ${reference.sha256}, received ${digest}`],
      );
    }
  }

  await readJsonFile(
    await resolveReferencedFile(root, requireReference(inputs, "schema").path, "inputs.schema"),
    "inputs.schema",
  );
  if ("truth" in inputs) {
    await readJsonFile(
      await resolveReferencedFile(root, requireReference(inputs, "truth").path, "inputs.truth"),
      "inputs.truth",
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
    throw new BundleValidationError("referenced_file_missing", `${label} is missing`, [manifestPath]);
  }
  if (info.isSymbolicLink()) {
    throw new BundleValidationError("referenced_file_symlink", `${label} must not be a symlink`, [
      manifestPath,
    ]);
  }
  if (!info.isFile()) {
    throw new BundleValidationError("referenced_file_not_regular", `${label} must be a regular file`, [
      manifestPath,
    ]);
  }

  const canonical = await realpath(absolute);
  const relative = path.relative(root, canonical);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new BundleValidationError("referenced_file_outside_bundle", `${label} resolves outside bundle`, [
      manifestPath,
    ]);
  }
  return canonical;
}

function assertSafeRelativePath(value: string, label: string): void {
  if (value.length === 0 || value.includes("\\") || value.includes("\0")) {
    throw new BundleValidationError("unsafe_reference_path", `${label} has an unsafe path`, [value]);
  }
  if (path.posix.isAbsolute(value)) {
    throw new BundleValidationError("unsafe_reference_path", `${label} must use a relative path`, [value]);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new BundleValidationError("unsafe_reference_path", `${label} has an unsafe path segment`, [
      value,
    ]);
  }
  if (path.posix.normalize(value) !== value) {
    throw new BundleValidationError("unsafe_reference_path", `${label} path must be normalized`, [value]);
  }
}

async function readJsonFile(file: string, label: string): Promise<JsonValue> {
  let info;
  try {
    info = await stat(file);
  } catch {
    throw new BundleValidationError("json_file_missing", `${label} is missing");
  }
  if (info.size > MAX_JSON_BYTES) {
    throw new BundleValidationError("json_file_too_large", `${label} exceeds the 4 MiB limit`);
  }

  let source;
  try {
    source = await readFile(file, "utf8");
  } catch {
    throw new BundleValidationError("json_file_unreadable", `${label} could not be read");
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

async function sha256File(file: string): Promise<string> {
  const content = await readFile(file);
  return createHash("sha256").update(content).digest("hex");
}
