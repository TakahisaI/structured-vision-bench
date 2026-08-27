import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  createReadStream,
  fstatSync,
  openSync,
  readSync,
  writeSync,
} from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  realpath,
  rm,
} from "node:fs/promises";

import path from "node:path";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "./json.js";
import { validateJsonSchema, validateJsonSchemaDefinition } from "./schema-validator.js";

const MANIFEST_NAME = "bundle.json";
export const MAX_JSON_BYTES = 4 * 1024 * 1024;
export const MAX_PROVIDER_INPUT_BYTES = 16 * 1024 * 1024;
export const MAX_ERROR_MESSAGE_LENGTH = 240;
const MAX_DETAIL_MESSAGES = 20;
const MAX_DETAIL_LENGTH = 240;
const UTF8_TEXT_INPUT_LABELS = new Set(["inputs.system", "inputs.instruction"]);
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const NONBLOCK = constants.O_NONBLOCK ?? 0;
const READ_ONLY_NOFOLLOW = constants.O_RDONLY | NOFOLLOW | NONBLOCK;
const STAGING_DIRECTORY_MODE = 0o700;
const STAGING_FILE_MODE = 0o600;

type FileReference = {
  path: string;
  sha256: string;
  mediaType: string;
};

export type BundleValidationResult = {
  caseId: string;
  referencedFiles: number;
  bundleVersion: 1;
};

export type LoadedBundleForComparison = {
  caseId: string;
  documentKind: string;
  metadata: {
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  bundleVersion: 1;
  manifestDigest: string;
  inputs: {
    image: LoadedBundleInput;
    schema: LoadedBundleInput;
    system: LoadedBundleInput;
    instruction: LoadedBundleInput;
    truth?: LoadedBundleInput & { value: JsonValue };
  };
  comparison: JsonValue;
};

export type LoadedBundleInput = {
  sha256: string;
  mediaType: string;
};

type StagedProviderFile<T> = {
  input: T;
  dispose: () => void;
};

type LoadedBundleForRunnerInput = LoadedBundleForRunner["inputs"];

export type LoadedBundleForRunner = {
  caseId: string;
  documentKind: string;
  metadata: {
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  bundleVersion: 1;
  manifestDigest: string;
  inputs: {
    image: LoadedBundleInput & {
      readBytes: () => Promise<Buffer>;
    };
    schema: LoadedBundleInput & { value: JsonValue };
    system: LoadedBundleInput & { readText: () => Promise<string> };
    instruction: LoadedBundleInput & { readText: () => Promise<string> };
    truth?: LoadedBundleInput & { value: JsonValue };
  };
  cleanup: () => Promise<void>;
};

export type PreparedBundleForRunner = {
  caseId: string;
  documentKind: string;
  metadata: {
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  bundleVersion: 1;
  manifestDigest: string;
  image: LoadedBundleInput;
  prepareAttemptRootGuard: (attemptRoot: string) => Promise<AttemptRootGuard>;
};

export type AttemptRootGuard = {
  assertStable: () => Promise<void>;
};

export class BundleValidationError extends Error {
  readonly code: string;
  readonly details: string[];

  constructor(code: string, message: string, details: string[] = []) {
    super(truncateText(message, MAX_ERROR_MESSAGE_LENGTH));
    this.name = "BundleValidationError";
    this.code = code;
    this.details = boundDetails(details);
  }
}

type ResolvedReference = FileReference & { absolute: string };

type JsonFileResult = {
  value: JsonValue;
  bytes: Buffer;
};

type ValidatedBundleInternals = {
  root: string;
  manifest: Record<string, JsonValue>;
  manifestBytes: Buffer;
  manifestDigest: string;
  summary: BundleValidationResult;
  references: Map<string, ResolvedReference>;
  jsonFiles: Map<string, JsonFileResult>;
};

export async function validateBundle(
  bundleDirectory: string,
  contractSchemaPath = path.resolve("schemas/bundle-v1.schema.json"),
): Promise<BundleValidationResult> {
  return (await validateBundleInternal(bundleDirectory, contractSchemaPath)).summary;
}

/** Loads only validated identities, truth, and policy needed by comparison. */
export async function loadBundleForComparison(
  bundleDirectory: string,
  contractSchemaPath = path.resolve("schemas/bundle-v1.schema.json"),
): Promise<LoadedBundleForComparison> {
  const validated = await validateBundleInternal(bundleDirectory, contractSchemaPath);
  const metadata = validated.manifest.metadata;
  const comparison = validated.manifest.comparison;
  const image = validated.references.get("inputs.image");
  const schema = validated.references.get("inputs.schema");
  const system = validated.references.get("inputs.system");
  const instruction = validated.references.get("inputs.instruction");
  const truthReference = validated.references.get("inputs.truth");
  const truthFile = validated.jsonFiles.get("inputs.truth");
  if (
    !isJsonObject(metadata) ||
    comparison === undefined ||
    image === undefined ||
    schema === undefined ||
    system === undefined ||
    instruction === undefined
  ) {
    throw new BundleValidationError("comparison_bundle_incomplete", "comparison bundle is incomplete");
  }
  return {
    caseId: String(validated.manifest.caseId),
    documentKind: String(metadata.documentKind),
    metadata: {
      promptVersion: String(metadata.promptVersion),
      preprocessVersion: String(metadata.preprocessVersion),
      sourceCommit: typeof metadata.sourceCommit === "string" ? metadata.sourceCommit : null,
    },
    bundleVersion: 1,
    manifestDigest: validated.manifestDigest,
    inputs: {
      image: { sha256: image.sha256, mediaType: image.mediaType },
      schema: { sha256: schema.sha256, mediaType: schema.mediaType },
      system: { sha256: system.sha256, mediaType: system.mediaType },
      instruction: { sha256: instruction.sha256, mediaType: instruction.mediaType },
      ...(truthReference !== undefined && truthFile !== undefined
        ? {
            truth: {
              sha256: truthReference.sha256,
              mediaType: truthReference.mediaType,
              value: truthFile.value,
            },
          }
        : {}),
    },
    comparison,
  };
}

/**
 * Validates a bundle and fixes the four provider inputs in a private staging
 * directory. Provider-facing callbacks expose bytes/text but never the bundle
 * root or an original path. The caller owns cleanup after the run finishes.
 */
export async function loadBundleForRunner(
  bundleDirectory: string,
  stagingDirectory: string,
  contractSchemaPath = path.resolve("schemas/bundle-v1.schema.json"),
): Promise<LoadedBundleForRunner> {
  const validated = await validateBundleInternal(bundleDirectory, contractSchemaPath, {
    deferReferencedContent: false,
  });
  const imageReference = validated.references.get("inputs.image");
  const systemReference = validated.references.get("inputs.system");
  const instructionReference = validated.references.get("inputs.instruction");
  const schemaReference = validated.references.get("inputs.schema");
  const schemaFile = validated.jsonFiles.get("inputs.schema");
  if (
    imageReference === undefined ||
    systemReference === undefined ||
    instructionReference === undefined ||
    schemaReference === undefined ||
    schemaFile === undefined
  ) {
    throw new BundleValidationError("runner_bundle_incomplete", "bundle inputs are incomplete");
  }

  const metadata = validated.manifest.metadata;
  if (!isJsonObject(metadata) || typeof metadata.documentKind !== "string") {
    throw new BundleValidationError("manifest_schema_invalid", "bundle metadata is invalid");
  }

  let ownsStagingDirectory = false;
  const disposers: Array<() => void> = [];
  try {
    await mkdir(stagingDirectory, { mode: STAGING_DIRECTORY_MODE });
    await chmod(stagingDirectory, STAGING_DIRECTORY_MODE);
    ownsStagingDirectory = true;
    const imageResult = await stageProviderFile(imageReference, stagingDirectory, "image", false, validated.root);
    disposers.push(imageResult.dispose);
    const systemResult = await stageProviderFile(systemReference, stagingDirectory, "system", true, validated.root);
    disposers.push(systemResult.dispose);
    const instructionResult = await stageProviderFile(
      instructionReference,
      stagingDirectory,
      "instruction",
      true,
      validated.root,
    );
    disposers.push(instructionResult.dispose);
    const image = imageResult.input;
    const system = systemResult.input;
    const instruction = instructionResult.input;
    const truthFile = validated.jsonFiles.get("inputs.truth");
    const truthReference = validated.references.get("inputs.truth");

    let cleaned = false;
    return {
      caseId: String(validated.manifest.caseId),
      documentKind: metadata.documentKind,
      metadata: {
        promptVersion: String(metadata.promptVersion),
        preprocessVersion: String(metadata.preprocessVersion),
        sourceCommit: typeof metadata.sourceCommit === "string" ? metadata.sourceCommit : null,
      },
      bundleVersion: 1,
      manifestDigest: validated.manifestDigest,
      inputs: {
        image,
        schema: {
          sha256: schemaReference.sha256,
          mediaType: schemaReference.mediaType,
          value: schemaFile.value,
        },
        system,
        instruction,
        ...(truthFile !== undefined && truthReference !== undefined
          ? {
              truth: {
                sha256: truthReference.sha256,
                mediaType: truthReference.mediaType,
                value: truthFile.value,
              },
            }
          : {}),
      },
      cleanup: async () => {
        if (cleaned) return;
        cleaned = true;
        for (const dispose of disposers) dispose();
        await rm(stagingDirectory, { recursive: true, force: true }).catch(() => undefined);
      },
    };
  } catch (error) {
    for (const dispose of disposers) dispose();
    if (ownsStagingDirectory) {
      await rm(stagingDirectory, { recursive: true, force: true }).catch(() => undefined);
    }
    throw error;
  }
}

/**
 * Performs the pre-approval portion of runner validation without opening
 * referenced input contents. The complete validator and staging pass is run
 * after approval, before provider invocation.
 */
export async function prepareBundleForRunner(
  bundleDirectory: string,
  contractSchemaPath = path.resolve("schemas/bundle-v1.schema.json"),
): Promise<PreparedBundleForRunner> {
  const validated = await validateBundleInternal(bundleDirectory, contractSchemaPath, {
    deferReferencedContent: true,
  });
  const imageReference = validated.references.get("inputs.image");
  const metadata = validated.manifest.metadata;
  if (imageReference === undefined || !isJsonObject(metadata) || typeof metadata.documentKind !== "string") {
    throw new BundleValidationError("runner_bundle_incomplete", "bundle inputs are incomplete");
  }
  return {
    caseId: String(validated.manifest.caseId),
    documentKind: metadata.documentKind,
    metadata: {
      promptVersion: String(metadata.promptVersion),
      preprocessVersion: String(metadata.preprocessVersion),
      sourceCommit: typeof metadata.sourceCommit === "string" ? metadata.sourceCommit : null,
    },
    bundleVersion: 1,
    manifestDigest: validated.manifestDigest,
    image: {
      sha256: imageReference.sha256,
      mediaType: imageReference.mediaType,
    },
    prepareAttemptRootGuard: (attemptRoot) => prepareAttemptRootGuard(attemptRoot, validated.root),
  };
}

async function validateBundleInternal(
  bundleDirectory: string,
  contractSchemaPath: string,
  options: { deferReferencedContent: boolean } = { deferReferencedContent: false },
): Promise<ValidatedBundleInternals> {
  await assertBundleRoot(bundleDirectory);
  const root = await realpath(bundleDirectory);
  const manifestPath = path.join(root, MANIFEST_NAME);
  await assertManifestFile(manifestPath);

  const manifestResult = await readJsonFile(manifestPath, MANIFEST_NAME, MAX_JSON_BYTES, root);
  const manifest = manifestResult.value;
  const contractSchema = (
    await readJsonFile(contractSchemaPath, "bundle v1 schema", MAX_JSON_BYTES)
  ).value;
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
  const digestsByPath = new Map<string, string>();
  const resolvedReferences = new Map<string, ResolvedReference>();
  for (const [label, reference] of references) {
    const absolute = await resolveReferencedFile(root, reference.path, label);
    resolvedReferences.set(label, { ...reference, absolute });
    if (options.deferReferencedContent) continue;
    const requiresUtf8Validation = UTF8_TEXT_INPUT_LABELS.has(label);
    // Text inputs must hash and decode the same stream. They cannot use a
    // digest-only cache because a second read would validate different bytes.
    let digest = requiresUtf8Validation ? undefined : digestsByPath.get(absolute);
    if (digest === undefined) {
      digest = requiresUtf8Validation
        ? await hashAndValidateUtf8File(absolute, label, root)
        : await sha256File(absolute, label, root);
      digestsByPath.set(absolute, digest);
    }
    if (digest !== reference.sha256) {
      throw new BundleValidationError(
        "digest_mismatch",
        `${label} digest does not match bundle.json`,
      );
    }
  }

  const schemaReference = requireReference(inputs, "schema");
  const jsonFiles = new Map<string, JsonFileResult>();
  const schemaFile = await readVerifiedJson(
    root,
    schemaReference.path,
    "inputs.schema",
    schemaReference.sha256,
  );
  const schemaDefinitionIssues = validateJsonSchemaDefinition(schemaFile.value);
  if (schemaDefinitionIssues.length > 0) {
    throw new BundleValidationError(
      "output_schema_invalid",
      "output schema is not supported",
      boundDetails(schemaDefinitionIssues.map((issue) => `${issue.path}: ${issue.message}`)),
    );
  }
  jsonFiles.set("inputs.schema", schemaFile);
  if (!options.deferReferencedContent) {
    if (Object.hasOwn(inputs, "truth")) {
      const truthReference = requireReference(inputs, "truth");
      const truthFile = await readVerifiedJson(
        root,
        truthReference.path,
        "inputs.truth",
        truthReference.sha256,
      );
      jsonFiles.set("inputs.truth", truthFile);
      const { value: truth } = truthFile;
      assertTruthProjection(manifest.comparison ?? null, truth);
    }
  }

  const summary = {
    caseId: String(manifest.caseId),
    referencedFiles: references.length,
    bundleVersion: 1 as const,
  };
  return {
    root,
    manifest,
    manifestBytes: manifestResult.bytes,
    manifestDigest: createHash("sha256").update(manifestResult.bytes).digest("hex"),
    summary,
    references: resolvedReferences,
    jsonFiles,
  };
}

/**
 * Re-reads a referenced JSON file and confirms its bytes still hash to the
 * digest recorded during preflight, so projection/syntax checks apply to the
 * exact bytes the manifest committed to. A swap between reads fails here
 * instead of validating different bytes than the digest covered.
 */
async function readVerifiedJson(
  root: string,
  manifestPath: string,
  label: string,
  expectedDigest: string,
): Promise<{ value: JsonValue; bytes: Buffer }> {
  const absolute = await resolveReferencedFile(root, manifestPath, label);
  const result = await readJsonFile(absolute, label, MAX_JSON_BYTES, root);
  const actualDigest = createHash("sha256").update(result.bytes).digest("hex");
  if (actualDigest !== expectedDigest) {
    throw new BundleValidationError(
      "digest_mismatch",
      `${label} changed after preflight digest verification`,
    );
  }
  return result;
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
    if (!Object.hasOwn(inputs, key)) continue;
    references.push([`inputs.${key}`, requireReference(inputs, key)]);
  }
  return references;
}

function requireReference(inputs: Record<string, JsonValue>, key: string): FileReference {
  const value = inputs[key];
  if (
    !isJsonObject(value) ||
    typeof value.path !== "string" ||
    typeof value.sha256 !== "string" ||
    typeof value.mediaType !== "string"
  ) {
    throw new BundleValidationError(
      "manifest_schema_invalid",
      `inputs.${key} must be a file reference`,
    );
  }
  return { path: value.path, sha256: value.sha256, mediaType: value.mediaType };
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

  let canonical: string;
  try {
    canonical = await realpath(absolute);
  } catch {
    throw new BundleValidationError("bundle_io_error", `${label} could not be resolved`);
  }
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

async function readJsonFile(
  file: string,
  label: string,
  maxBytes: number | null,
  root?: string,
): Promise<{ value: JsonValue; bytes: Buffer }> {
  let descriptor: OpenFileDescriptor | undefined;
  let bytes: Buffer;
  try {
    descriptor = await openVerifiedFile(file, root);
    const info = fstatSync(descriptor);
    if (maxBytes !== null && info.size > maxBytes) {
      throw new BundleValidationError(
        "json_file_too_large",
        `${label} exceeds the ${formatLimit(maxBytes)} limit`,
      );
    }
    bytes = readBounded(descriptor, maxBytes);
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    if (error instanceof BoundedReadError) {
      throw new BundleValidationError(
        "json_file_too_large",
        `${label} exceeds the ${formatLimit(maxBytes ?? MAX_JSON_BYTES)} limit`,
      );
    }
    throw new BundleValidationError("bundle_io_error", `${label} could not be read`);
  } finally {
    if (descriptor !== undefined) closeDescriptor(descriptor);
  }

  try {
    const source = decodeUtf8Strict(bytes, label);
    return { value: parseJson(source, label), bytes };
  } catch {
    throw new BundleValidationError("json_file_invalid", `${label} is invalid`);
  }
}

async function stageProviderFile(
  reference: ResolvedReference,
  stagingDirectory: string,
  basename: "image" | "system" | "instruction",
  text: false,
  root: string,
): Promise<StagedProviderFile<LoadedBundleForRunnerInput["image"]>>;
async function stageProviderFile(
  reference: ResolvedReference,
  stagingDirectory: string,
  basename: "image" | "system" | "instruction",
  text: true,
  root: string,
): Promise<StagedProviderFile<LoadedBundleForRunnerInput["system"]>>;
async function stageProviderFile(
  reference: ResolvedReference,
  stagingDirectory: string,
  basename: "image" | "system" | "instruction",
  text: boolean,
  root: string,
): Promise<
  | StagedProviderFile<LoadedBundleForRunnerInput["image"]>
  | StagedProviderFile<LoadedBundleForRunnerInput["system"]>
> {
  const partialPath = path.join(stagingDirectory, `${basename}.part`);
  const stagedPath = path.join(stagingDirectory, `${basename}.input`);
  let committed = false;
  let disposed = false;
  let snapshot: Buffer | undefined;
  let textSnapshot: string | undefined;
  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    snapshot?.fill(0);
    snapshot = undefined;
    textSnapshot = undefined;
  };
  try {
    await copyFileNoFollow(
      reference.absolute,
      partialPath,
      `inputs.${basename}`,
      root,
      MAX_PROVIDER_INPUT_BYTES,
    );
    snapshot = await readFileNoFollow(partialPath, `inputs.${basename}`, MAX_PROVIDER_INPUT_BYTES);
    const digest = createHash("sha256").update(snapshot).digest("hex");
    if (digest !== reference.sha256) {
      throw new BundleValidationError(
        "digest_mismatch",
        `inputs.${basename} changed while being staged`,
      );
    }
    textSnapshot = text
      ? decodeUtf8Strict(snapshot, `inputs.${basename}`)
      : undefined;
    await link(partialPath, stagedPath);
    committed = true;
    await rm(partialPath, { force: true }).catch(() => undefined);
    if (text) {
      return {
        input: {
          sha256: reference.sha256,
          mediaType: reference.mediaType,
          readText: async () => {
            const value = textSnapshot;
            if (disposed || value === undefined) throw new Error();
            return value;
          },
        },
        dispose,
      };
    }
    return {
      input: {
        sha256: reference.sha256,
        mediaType: reference.mediaType,
        readBytes: async () => {
          if (disposed || snapshot === undefined) throw new Error();
          return Buffer.from(snapshot);
        },
      },
      dispose,
    };
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    throw new BundleValidationError(
      "runner_input_unreadable",
      `inputs.${basename} could not be staged`,
    );
  } finally {
    if (!committed) dispose();
    await rm(partialPath, { force: true }).catch(() => undefined);
    if (!committed) await rm(stagedPath, { force: true }).catch(() => undefined);
  }
}

async function hashAndValidateUtf8Stream(
  stream: AsyncIterable<Uint8Array>,
  label: string,
): Promise<string> {
  const hash = createHash("sha256");
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const prefix = new Uint8Array(3);
  let prefixLength = 0;

  try {
    for await (const chunk of stream) {
      hash.update(chunk);
      if (prefixLength < prefix.length) {
        const copied = Math.min(prefix.length - prefixLength, chunk.length);
        prefix.set(chunk.subarray(0, copied), prefixLength);
        prefixLength += copied;
        if (
          prefixLength === prefix.length &&
          prefix[0] === 0xef &&
          prefix[1] === 0xbb &&
          prefix[2] === 0xbf
        ) {
          throw new BundleValidationError("text_file_invalid", `${label} must not start with a UTF-8 BOM`);
        }
      }

      try {
        decoder.decode(chunk, { stream: true });
      } catch {
        throw new BundleValidationError("text_file_invalid", `${label} is not valid UTF-8`);
      }
    }

    try {
      decoder.decode();
    } catch {
      throw new BundleValidationError("text_file_invalid", `${label} is not valid UTF-8`);
    }

    return hash.digest("hex");
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    throw new BundleValidationError("text_file_unreadable", `${label} could not be read`);
  }
}

function formatLimit(maxBytes: number): string {
  const mebibytes = maxBytes / (1024 * 1024);
  return Number.isInteger(mebibytes) ? `${mebibytes} MiB` : `${maxBytes} byte`;
}

type OpenFileDescriptor = number;

class BoundedReadError extends Error {}

async function openVerifiedFile(file: string, root?: string): Promise<OpenFileDescriptor> {
  let descriptor: OpenFileDescriptor | undefined;
  try {
    descriptor = openSync(file, READ_ONLY_NOFOLLOW);
    const info = fstatSync(descriptor);
    if (!info.isFile()) throw new Error();
    if (root !== undefined) {
      await assertStableRoot(root);
      const canonical = await realpath(file);
      if (!isWithinRoot(root, canonical)) throw new Error();
    }
    return descriptor;
  } catch (error) {
    if (descriptor !== undefined) closeDescriptor(descriptor);
    throw error;
  }
}

function readBounded(descriptor: OpenFileDescriptor, maxBytes: number | null): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const remaining = maxBytes === null ? 64 * 1024 : maxBytes + 1 - total;
    if (remaining <= 0) throw new BoundedReadError();
    const chunk = Buffer.alloc(Math.min(64 * 1024, remaining));
    const bytesRead = readSync(descriptor, chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    total += bytesRead;
    if (maxBytes !== null && total > maxBytes) throw new BoundedReadError();
  }
  return Buffer.concat(chunks, total);
}

async function readFileNoFollow(file: string, label: string, maxBytes: number): Promise<Buffer> {
  let descriptor: OpenFileDescriptor | undefined;
  try {
    descriptor = await openVerifiedFile(file);
    return readBounded(descriptor, maxBytes);
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    if (error instanceof BoundedReadError) {
      throw new BundleValidationError(
        "runner_input_too_large",
        `${label} exceeds the ${formatLimit(maxBytes)} limit`,
      );
    }
    throw new BundleValidationError("runner_input_unreadable", `${label} could not be read from staging`);
  } finally {
    if (descriptor !== undefined) closeDescriptor(descriptor);
  }
}

async function copyFileNoFollow(
  source: string,
  destination: string,
  label: string,
  root: string,
  maxBytes: number,
): Promise<void> {
  let sourceDescriptor: OpenFileDescriptor | undefined;
  let destinationDescriptor: OpenFileDescriptor | undefined;
  try {
    sourceDescriptor = await openVerifiedFile(source, root);
    if (fstatSync(sourceDescriptor).size > maxBytes) throw new BoundedReadError();
    destinationDescriptor = openSync(
      destination,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW,
      STAGING_FILE_MODE,
    );
    const chunk = Buffer.alloc(64 * 1024);
    let total = 0;
    for (;;) {
      const bytesRead = readSync(sourceDescriptor, chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw new BoundedReadError();
      let written = 0;
      while (written < bytesRead) {
        written += writeSync(destinationDescriptor, chunk, written, bytesRead - written);
      }
    }
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    if (error instanceof BoundedReadError) {
      throw new BundleValidationError(
        "runner_input_too_large",
        `${label} exceeds the ${formatLimit(maxBytes)} limit`,
      );
    }
    throw new BundleValidationError("runner_input_unreadable", `${label} could not be staged`);
  } finally {
    if (sourceDescriptor !== undefined) closeDescriptor(sourceDescriptor);
    if (destinationDescriptor !== undefined) closeDescriptor(destinationDescriptor);
  }
}

async function hashAndValidateUtf8File(
  file: string,
  label: string,
  root?: string,
  errorCode: "text_file_unreadable" | "runner_input_unreadable" = "text_file_unreadable",
): Promise<string> {
  let descriptor: OpenFileDescriptor | undefined;
  let stream: ReturnType<typeof createReadStream> | undefined;
  let completed = false;
  try {
    descriptor = await openVerifiedFile(file, root);
    stream = createReadStream(file, { fd: descriptor, autoClose: false });
    stream.on("error", () => undefined);
    const digest = await hashAndValidateUtf8Stream(stream, label);
    completed = true;
    return digest;
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    throw new BundleValidationError(errorCode, `${label} could not be read`);
  } finally {
    if (!completed) stream?.destroy();
    if (descriptor !== undefined) closeDescriptor(descriptor);
  }
}

async function sha256File(
  file: string,
  label: string,
  root?: string,
  errorCode: "referenced_file_unreadable" | "runner_input_unreadable" = "referenced_file_unreadable",
): Promise<string> {
  let descriptor: OpenFileDescriptor | undefined;
  try {
    // Stream the file so a huge image or PDF cannot exhaust memory during digest verification.
    descriptor = await openVerifiedFile(file, root);
    const hash = createHash("sha256");
    const chunk = Buffer.alloc(64 * 1024);
    for (;;) {
      const bytesRead = readSync(descriptor, chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      hash.update(chunk.subarray(0, bytesRead));
    }
    return hash.digest("hex");
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    if (errorCode === "referenced_file_unreadable") {
      throw new BundleValidationError("bundle_io_error", `${label} could not be read`);
    }
    throw new BundleValidationError(errorCode, `${label} could not be read`);
  } finally {
    if (descriptor !== undefined) closeDescriptor(descriptor);
  }
}

function closeDescriptor(descriptor: OpenFileDescriptor): void {
  try {
    closeSync(descriptor);
  } catch {
    // A failed stream may already have closed its descriptor.
  }
}

async function assertStableRoot(root: string): Promise<void> {
  if ((await realpath(root)) !== root) throw new Error();
}

function isWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function prepareAttemptRootGuard(attemptRoot: string, bundleRoot: string): Promise<AttemptRootGuard> {
  const canonicalAttemptRoot = await canonicalizePossiblyMissingPath(attemptRoot);
  if (isWithinRoot(bundleRoot, canonicalAttemptRoot)) {
    throw new BundleValidationError("attempt_root_invalid", "attempt root must be outside the bundle");
  }
  return {
    assertStable: async () => {
      let current: string;
      try {
        current = await realpath(path.resolve(attemptRoot));
      } catch {
        throw new BundleValidationError("attempt_root_invalid", "attempt root changed");
      }
      if (current !== canonicalAttemptRoot) {
        throw new BundleValidationError("attempt_root_invalid", "attempt root changed");
      }
    },
  };
}

async function canonicalizePossiblyMissingPath(value: string): Promise<string> {
  const absolute = path.resolve(value);
  const missingSegments: string[] = [];
  let current = absolute;
  for (;;) {
    try {
      const canonical = await realpath(current);
      return path.join(canonical, ...missingSegments);
    } catch (error) {
      if (!isNotFoundError(error) || current === path.dirname(current)) {
        throw new BundleValidationError("attempt_root_invalid", "attempt root could not be inspected");
      }
      missingSegments.unshift(path.basename(current));
      current = path.dirname(current);
    }
  }
}

function isNotFoundError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

// --- Bounded diagnostics ----------------------------------------------------
// Unknown keys, secret-shaped strings, and absolute paths must never reach
// logs. Details are capped in count and per-message length; omitted entries
// are summarized instead of printed.

export function boundDetails(details: string[]): string[] {
  const bounded = details.slice(0, MAX_DETAIL_MESSAGES).map((detail) => truncateDetail(detail));
  const omitted = details.length - bounded.length;
  if (omitted > 0) bounded.push(`${omitted} additional issues omitted`);
  return bounded;
}

function truncateDetail(detail: string): string {
  return truncateText(detail, MAX_DETAIL_LENGTH);
}

function truncateText(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength - 1)}…`;
}

// --- Comparison path contract ------------------------------------------------
// v1 comparison paths are RFC 6901 JSON Pointer with one extension:
//
//   - A segment that is exactly "*" matches every element of the array at the
//     remaining prefix ("wildcard").
//   - Wildcards are allowed only in critical entries, at most one per pointer,
//     and never as the last segment. "*" inside a segment (for example "/a*b")
//     is a literal name. scalars and arrays paths are plain pointers.
//   - A critical entry must be either a declared scalar (any nesting depth) or
//     "<declared-array-path>/*/<field declared by that array>".
//
// Syntax-level violations are rejected by the JSON Schema patterns. The checks
// here enforce the cross-field rules that a static schema cannot express.
// Diagnostics report positions only — never pointer values, which may carry
// confidential text.

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

  for (const [entryIndex, entry] of arrays.entries()) {
    if (!isJsonObject(entry)) continue;
    const entryPath = entry.path;
    if (typeof entryPath !== "string") continue;
    if (arrayPaths.has(entryPath)) {
      throw comparisonContractError(
        `comparison.arrays[${entryIndex}].path duplicates an earlier array path`,
      );
    }
    arrayPaths.add(entryPath);

    const fields = Array.isArray(entry.fields)
      ? entry.fields.filter((field): field is string => typeof field === "string")
      : [];
    const keyFields = typeof entry.key === "string" ? [entry.key] : [];
    fieldsByArrayPath.set(entryPath, new Set([...keyFields, ...fields]));
  }

  for (const [scalarIndex, scalar] of scalars.entries()) {
    if (arrayPaths.has(scalar)) {
      throw comparisonContractError(
        `comparison.scalars[${scalarIndex}] duplicates a declared array path`,
      );
    }
  }

  const criticals = collectPointerList(comparison.critical ?? null);
  for (const [criticalIndex, critical] of criticals.entries()) {
    if (fieldsByArrayPath.has(critical)) {
      throw comparisonContractError(
        `comparison.critical[${criticalIndex}] must select a scalar or an array element field, not the whole array`,
      );
    }
    if (scalarPaths.has(critical)) continue;
    const wildcardField = splitWildcardField(critical);
    if (wildcardField === undefined) {
      throw comparisonContractError(
        `comparison.critical[${criticalIndex}] must be a declared scalar or an "<array>/*/<field>" wildcard pointer`,
      );
    }
    const [arrayPath, field] = wildcardField;
    const fields = fieldsByArrayPath.get(arrayPath);
    if (fields === undefined) {
      throw comparisonContractError(
        `comparison.critical[${criticalIndex}] uses an undeclared array path (declare it in comparison.arrays first)`,
      );
    }
    if (!fields.has(field)) {
      throw comparisonContractError(
        `comparison.critical[${criticalIndex}] uses a field not compared by its declared array (add it to key or fields there)`,
      );
    }
  }
}

function truthContractError(message: string): BundleValidationError {
  return new BundleValidationError("truth_contract_invalid", message);
}

// Normalization used for key uniqueness and empty-key checks. Canonical fixed
// order is nfkc -> trim -> collapse-whitespace regardless of declaration
// order; each enabled operation applies at most once. The whitespace set
// matches docs/bundle-v1.md exactly.
const UNICODE_WHITESPACE = /[\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/gu;

export function normalizeKeyForComparison(value: string, operations: JsonValue): string {
  const ops = Array.isArray(operations)
    ? operations.filter((item): item is string => typeof item === "string")
    : [];
  let normalized = value;
  if (ops.includes("nfkc")) normalized = normalized.normalize("NFKC");
  if (ops.includes("trim")) normalized = trimWhitespace(normalized);
  if (ops.includes("collapse-whitespace")) normalized = collapseWhitespace(normalized);
  return normalized;
}

function trimWhitespace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isUnicodeWhitespace(value[start]!)) start += 1;
  while (end > start && isUnicodeWhitespace(value[end - 1]!)) end -= 1;
  return value.slice(start, end);
}

function collapseWhitespace(value: string): string {
  let output = "";
  let inRun = false;
  for (const character of value) {
    if (isUnicodeWhitespace(character)) {
      inRun = true;
      continue;
    }
    if (inRun) {
      output += " ";
      inRun = false;
    }
    output += character;
  }
  if (inRun) output += " ";
  return output;
}

function isUnicodeWhitespace(character: string | undefined): boolean {
  if (character === undefined) return false;
  UNICODE_WHITESPACE.lastIndex = 0;
  return UNICODE_WHITESPACE.test(character);
}

/**
 * Validates the optional truth file against its projection contract during
 * preflight: every declared path exists, keys are sound and unique, and
 * projected fields are present. Violations fail with truth_contract_invalid.
 */
export function assertTruthProjection(comparison: JsonValue, truth: JsonValue): void {
  if (!isJsonObject(comparison)) {
    // The schema already rejected a malformed manifest; nothing to project.
    return;
  }
  if (!isJsonObject(truth)) {
    throw truthContractError("inputs.truth root must be an object");
  }

  for (const [scalarIndex, scalar] of collectPointerList(comparison.scalars ?? null).entries()) {
    const segments = decodePointerSegments(scalar);
    const value = resolvePointer(truth, segments);
    if (value === JSON_POINTER_NOT_FOUND) {
      throw truthContractError(`inputs.truth is missing declared scalar ${scalarIndex} of comparison.scalars`);
    }
    if (value !== null && typeof value === "object") {
      throw truthContractError(`inputs.truth value at declared scalar ${scalarIndex} must be a JSON scalar or null`);
    }
  }

  const arrays = Array.isArray(comparison.arrays) ? comparison.arrays : [];
  for (const [entryIndex, entry] of arrays.entries()) {
    if (!isJsonObject(entry)) continue;
    const arrayPath = entry.path;
    const keyPointer = entry.key;
    if (typeof arrayPath !== "string" || typeof keyPointer !== "string") continue;

    const elements = resolvePointer(truth, decodePointerSegments(arrayPath));
    if (elements === JSON_POINTER_NOT_FOUND) {
      throw truthContractError(`inputs.truth is missing declared array ${entryIndex} of comparison.arrays`);
    }
    if (!Array.isArray(elements)) {
      throw truthContractError(`inputs.truth value at declared array ${entryIndex} must be an array`);
    }

    const fieldPointers = Array.isArray(entry.fields)
      ? entry.fields.filter((field): field is string => typeof field === "string")
      : [];
    const normalizedKeys = new Set<string>();
    const normalization = isJsonObject(comparison.normalization)
      ? (comparison.normalization.strings ?? [])
      : [];

    for (const [elementIndex, element] of elements.entries()) {
      if (!isJsonObject(element)) {
        throw truthContractError(
          `inputs.truth element ${elementIndex} of declared array ${entryIndex} must be an object`,
        );
      }
      const keyValue = resolvePointer(element, decodePointerSegments(keyPointer));
      if (keyValue === JSON_POINTER_NOT_FOUND) {
        throw truthContractError(
          `inputs.truth element ${elementIndex} of declared array ${entryIndex} is missing its key`,
        );
      }
      if (typeof keyValue !== "string" && typeof keyValue !== "number") {
        throw truthContractError(
          `inputs.truth key of element ${elementIndex} in declared array ${entryIndex} must be a string or number`,
        );
      }
      if (typeof keyValue === "string") {
        const normalizedKey = normalizeKeyForComparison(keyValue, normalization);
        if (normalizedKey.length === 0) {
          throw truthContractError(
            `inputs.truth string key of element ${elementIndex} in declared array ${entryIndex} is empty after normalization`,
          );
        }
        // Prefix distinguishes a normalized string key from a numeric key with
        // the same digits: number 1 and string "1" never collide or match.
        const encodedKey = `s:${normalizedKey}`;
        if (normalizedKeys.has(encodedKey)) {
          throw truthContractError(
            `inputs.truth declared array ${entryIndex} has duplicate keys after normalization`,
          );
        }
        normalizedKeys.add(encodedKey);
      } else {
        const encodedKey = `n:${keyValue}`;
        if (normalizedKeys.has(encodedKey)) {
          throw truthContractError(
            `inputs.truth declared array ${entryIndex} has duplicate keys after normalization`,
          );
        }
        normalizedKeys.add(encodedKey);
      }

      for (const [fieldIndex, fieldPointer] of fieldPointers.entries()) {
        const fieldValue = resolvePointer(element, decodePointerSegments(fieldPointer));
        if (fieldValue === JSON_POINTER_NOT_FOUND) {
          throw truthContractError(
            `inputs.truth element ${elementIndex} of declared array ${entryIndex} is missing compared field ${fieldIndex}`,
          );
        }
        // Projected fields follow the same rule as projected scalars: JSON
        // scalar or explicit null, never an object or array.
        if (fieldValue !== null && typeof fieldValue === "object") {
          throw truthContractError(
            `inputs.truth compared field ${fieldIndex} of element ${elementIndex} in declared array ${entryIndex} must be a JSON scalar or null`,
          );
        }
      }
    }
  }
}

export const JSON_POINTER_NOT_FOUND = Symbol("pointer-not-found");

// RFC 6901 array indices are "0" or digits without a leading zero. "01", "1e0",
// and "+1" name object members, never array elements.
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/u;

/** Decodes RFC 6901 escape sequences; "~2" stays invalid per the schema patterns. */
export function decodePointerSegments(pointer: string): string[] {
  if (!pointer.startsWith("/")) return [];
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => segment.replace(/~1/gu, "/").replace(/~0/gu, "~"));
}

export function resolvePointer(
  root: JsonValue,
  segments: string[],
): JsonValue | typeof JSON_POINTER_NOT_FOUND {
  let current: JsonValue = root;
  for (const segment of segments) {
    if (Array.isArray(current)) {
      if (!ARRAY_INDEX_PATTERN.test(segment)) return JSON_POINTER_NOT_FOUND;
      const index = Number(segment);
      if (index >= current.length) return JSON_POINTER_NOT_FOUND;
      current = current[index]!;
      continue;
    }
    // hasOwn keeps inherited members (constructor, toString, __proto__) out of
    // pointer resolution; only owned JSON values are reachable.
    if (isJsonObject(current) && Object.hasOwn(current, segment)) {
      current = current[segment]!;
      continue;
    }
    return JSON_POINTER_NOT_FOUND;
  }
  return current;
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
  if (
    wildcardIndex < 1 ||
    wildcardIndex !== segments.length - 2 ||
    segments.lastIndexOf("*") !== wildcardIndex
  ) {
    return undefined;
  }
  const arrayPath = segments.slice(0, wildcardIndex).join("/");
  const rawField = segments[wildcardIndex + 1]!;
  if (rawField.length === 0) return undefined;
  const field = `/${rawField}`;
  return [arrayPath, field];
}
