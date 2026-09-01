import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, mkdir, mkdtemp, open, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  decodeUtf8Strict,
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../bundle/validate-bundle.js";
import { RunnerError } from "../runner/errors.js";
import {
  computeCaseInputIdentity,
  computeSanitizerRequirementDigest,
  type SanitizerRequirementDecisionV1,
} from "../runner/identity.js";
import type {
  ApprovalResponse,
  Provider,
  ProviderAdapterContext,
  ProviderModelRequest,
  ProviderResponse,
  ProviderUsage,
  RequestedExecutionSettings,
} from "../runner/types.js";

export const COMMAND_PROVIDER_PROTOCOL_VERSION = "command-provider-v1";
export const COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV =
  "SVBENCH_COMMAND_REQUEST_DIRECTORY";
export const COMMAND_PROVIDER_OPERATION_ENV = "SVBENCH_COMMAND_OPERATION";
export const DEFAULT_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024;
export const MAX_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const MAX_REQUEST_MANIFEST_BYTES = 1024 * 1024;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const EXCLUSIVE_WRITE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const ABORT_SETTLING_COMMAND_PROVIDERS = new WeakSet<object>();
const INPUT_FILES = Object.freeze({
  image: "image.input",
  schema: "schema.json",
  system: "system.txt",
  instruction: "instruction.txt",
});
const REQUEST_FILE = "request.json";

export type CommandProviderOptions = {
  executable: string;
  argv?: string[];
  envAllowlist?: string[];
  outputLimitBytes?: number;
  providerId: string;
  route: string;
  implementationVersion: string;
};

export type CommandProviderRequestManifestV1 = {
  requestVersion: 1;
  phase: string;
  provider: {
    id: string;
    route: string;
    implementationVersion: string;
    protocolVersion: typeof COMMAND_PROVIDER_PROTOCOL_VERSION;
  };
  bundle: {
    version: 1;
    manifestDigest: string;
  };
  case: {
    id: string;
    documentKind: string;
  };
  caseInputIdentity: {
    identityVersion: 1;
    caseId: string;
    documentKind: string;
    preparedImage: {
      mediaType: string;
      sha256: string;
    };
    digest: string;
  };
  inputs: {
    image: CommandProviderInputReference;
    schema: CommandProviderInputReference;
    system: CommandProviderInputReference;
    instruction: CommandProviderInputReference;
  };
  requested: RequestedExecutionSettings;
  provenance: ProviderAdapterContext["provenance"];
  sanitizerRequirement: ProviderAdapterContext["sanitizerRequirement"];
  approval: ApprovalResponse | null;
};

export type CommandProviderInputReference = {
  path: string;
  mediaType: string;
  sha256: string;
};

export type CommandProviderResponseV1 = {
  responseVersion: 1;
  phase: string;
  provider: CommandProviderRequestManifestV1["provider"];
  requested: RequestedExecutionSettings;
  caseInputIdentity: {
    identityVersion: 1;
    digest: string;
  };
  sanitizerRequirement: ProviderAdapterContext["sanitizerRequirement"];
  approval: ApprovalResponse | null;
  document: JsonValue;
  responded: {
    model: string | null;
    effort: string | null;
    usage: ProviderUsage;
    stopReason: string | null;
  };
};

export type CommandProviderTransportRequestV1 = {
  requestVersion: 1;
  operation: "prepareTransport";
  approval: ApprovalResponse;
};

export type CommandProviderInvokeRequestV1 = {
  requestVersion: 1;
  operation: "invoke";
  requestDirectory: string;
};

type ValidatedCommandProviderOptions = Readonly<{
  executable: string;
  argv: string[];
  envAllowlist: string[];
  outputLimitBytes: number;
  providerId: string;
  route: string;
  implementationVersion: string;
}>;

type ValidatedInvocation = Readonly<{
  request: ProviderModelRequest;
  context: ProviderAdapterContext;
}>;

/** Creates a shell-free provider backed by a consumer-owned local process. */
export function createCommandProvider(options: CommandProviderOptions): Provider {
  const validated = validateOptions(options);
  const provider = Object.freeze({
    id: validated.providerId,
    route: validated.route,
    implementationVersion: validated.implementationVersion,
    protocolVersion: COMMAND_PROVIDER_PROTOCOL_VERSION,
    async prepareTransport(
      approval: ApprovalResponse,
      signal?: AbortSignal,
    ): Promise<ApprovalResponse> {
      try {
        const snapshot = snapshotApprovalResponse(approval);
        if (
          !snapshot.approved ||
          snapshot.sanitizerRequired ||
          snapshot.policyRequired ||
          (snapshot.expiresAt !== undefined &&
            snapshot.expiresAt !== null &&
            Date.parse(snapshot.expiresAt) <= Date.now())
        ) {
          throw new Error();
        }
        return await prepareCommandTransport(validated, snapshot, signal);
      } catch {
        throw new Error("command provider transport preparation failed");
      }
    },
    async invoke(
      request: ProviderModelRequest,
      context: ProviderAdapterContext,
      signal?: AbortSignal,
    ): Promise<ProviderResponse> {
      try {
        return await invokeCommandProvider(validated, request, context, signal);
      } catch {
        throw new Error("command provider failed");
      }
    },
  });
  ABORT_SETTLING_COMMAND_PROVIDERS.add(provider);
  return provider;
}

/** @internal Read-only lifecycle capability check; registration is module-private. */
export function isAbortSettlingCommandProvider(provider: object): boolean {
  return ABORT_SETTLING_COMMAND_PROVIDERS.has(provider);
}

function validateOptions(options: CommandProviderOptions): ValidatedCommandProviderOptions {
  try {
    const value: unknown = options;
    if (value === null || typeof value !== "object") throw new Error();
    const candidate = value as Partial<CommandProviderOptions>;
    const executable = candidate.executable;
    const sourceArgv = candidate.argv ?? [];
    const sourceEnvAllowlist = candidate.envAllowlist ?? [];
    const outputLimitBytes =
      candidate.outputLimitBytes ?? DEFAULT_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES;
    const providerId = candidate.providerId;
    const route = candidate.route;
    const implementationVersion = candidate.implementationVersion;
    if (!Array.isArray(sourceArgv) || !Array.isArray(sourceEnvAllowlist)) throw new Error();
    const argvLength = sourceArgv.length;
    const envAllowlistLength = sourceEnvAllowlist.length;
    if (argvLength > 64 || envAllowlistLength > 64) throw new Error();
    const argv: unknown[] = [];
    const envAllowlist: unknown[] = [];
    for (let index = 0; index < argvLength; index += 1) argv.push(sourceArgv[index]);
    for (let index = 0; index < envAllowlistLength; index += 1) {
      envAllowlist.push(sourceEnvAllowlist[index]);
    }
    const normalizedEnvironmentNames = new Set<string>();
    const environmentInvalid = envAllowlist.some((name) => {
      if (typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name)) {
        return true;
      }
      const normalized = name.toUpperCase();
      if (
        normalized === COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV ||
        normalized === COMMAND_PROVIDER_OPERATION_ENV ||
        normalizedEnvironmentNames.has(normalized)
      ) {
        return true;
      }
      normalizedEnvironmentNames.add(normalized);
      return false;
    });
    if (
      typeof executable !== "string" ||
      executable.length === 0 ||
      executable.length > 240 ||
      !path.isAbsolute(executable) ||
      argv.some((argument) => typeof argument !== "string" || argument.length > 240) ||
      environmentInvalid ||
      !Number.isSafeInteger(outputLimitBytes) ||
      outputLimitBytes < 1 ||
      outputLimitBytes > MAX_COMMAND_PROVIDER_OUTPUT_LIMIT_BYTES ||
      !isSafeLabel(providerId) ||
      !isSafeLabel(route) ||
      !isSafeLabel(implementationVersion)
    ) {
      throw new Error();
    }
    return Object.freeze({
      executable,
      argv: Object.freeze(argv) as string[],
      envAllowlist: Object.freeze(envAllowlist) as string[],
      outputLimitBytes,
      providerId,
      route,
      implementationVersion,
    });
  } catch {
    throw new RunnerError("provider_invalid", "command provider configuration is invalid");
  }
}

async function invokeCommandProvider(
  options: ValidatedCommandProviderOptions,
  sourceRequest: ProviderModelRequest,
  sourceContext: ProviderAdapterContext,
  signal: AbortSignal | undefined,
): Promise<ProviderResponse> {
  const invocation = assertInvocationContext(sourceRequest, sourceContext);
  const { request, context } = invocation;
  const { approval, phase, sanitizerRequirement } = context;
  assertActive(signal);
  let imageBytes: Buffer | undefined;
  let schemaBytes: Buffer | undefined;
  let systemBytes: Buffer | undefined;
  let instructionBytes: Buffer | undefined;
  let requestRoot: string | undefined;
  let workingRoot: string | undefined;
  try {
    imageBytes = await readInputBytes(request.image.readBytes, approval, signal);
    schemaBytes = await readInputBytes(request.schemaInput.readBytes, approval, signal);
    systemBytes = await readInputText(request.system.readText, approval, signal);
    instructionBytes = await readInputText(
      request.instruction.readText,
      approval,
      signal,
    );
    const inputBytes = {
      image: imageBytes,
      schema: schemaBytes,
      system: systemBytes,
      instruction: instructionBytes,
    };
    validateInputBytes(inputBytes, request, context);
    const environment = snapshotAllowedEnvironment(options);
    const manifest = createRequestManifest(
      options,
      request,
      context,
      phase,
      sanitizerRequirement,
      approval,
    );
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8");
    if (manifestBytes.byteLength > MAX_REQUEST_MANIFEST_BYTES) throw new Error();
    const materializeRequest = async (
      assertReleaseActive: () => void = () => undefined,
    ): Promise<string> => {
      assertReleaseActive();
      if (requestRoot !== undefined) throw new Error();
      requestRoot = await mkdtemp(path.join(tmpdir(), "svbench-command-request-"));
      assertReleaseActive();
      await chmod(requestRoot, DIRECTORY_MODE);
      assertReleaseActive();
      await assertPrivateDirectory(requestRoot);
      assertReleaseActive();
      const requestDirectory = path.join(requestRoot, "request");
      await mkdir(requestDirectory, { mode: DIRECTORY_MODE });
      assertReleaseActive();
      await assertPrivateDirectory(requestDirectory);
      assertReleaseActive();
      await writePrivateFile(path.join(requestDirectory, INPUT_FILES.image), inputBytes.image);
      assertReleaseActive();
      await writePrivateFile(path.join(requestDirectory, INPUT_FILES.schema), inputBytes.schema);
      assertReleaseActive();
      await writePrivateFile(path.join(requestDirectory, INPUT_FILES.system), inputBytes.system);
      assertReleaseActive();
      await writePrivateFile(
        path.join(requestDirectory, INPUT_FILES.instruction),
        inputBytes.instruction,
      );
      assertReleaseActive();
      await writePrivateFile(path.join(requestDirectory, REQUEST_FILE), manifestBytes);
      assertReleaseActive();
      await assertRequestDirectory(requestDirectory);
      assertReleaseActive();
      return requestDirectory;
    };

    workingRoot = await mkdtemp(path.join(tmpdir(), "svbench-command-work-"));
    await chmod(workingRoot, DIRECTORY_MODE);
    await assertPrivateDirectory(workingRoot);
    const workingDirectory = workingRoot;
    if ((await readdir(workingDirectory)).length !== 0) throw new Error();
    const responseBytes =
      approval === null
        ? await runCommand(
            options,
            await materializeRequest(),
            workingDirectory,
            environment,
            null,
            signal,
          )
        : await runApprovedCommand(
            options,
            workingDirectory,
            environment,
            approval,
            materializeRequest,
            signal,
          );
    const response = parseResponse(
      responseBytes,
      options,
      context,
      phase,
      sanitizerRequirement,
      approval,
    );
    return {
      rawDocument: response.document,
      ...(response.approval === null ? {} : { approval: response.approval }),
      respondedModel: response.responded.model,
      effectiveEffort: response.responded.effort,
      usage: response.responded.usage,
      stopReason: response.responded.stopReason,
    };
  } finally {
    imageBytes?.fill(0);
    schemaBytes?.fill(0);
    systemBytes?.fill(0);
    instructionBytes?.fill(0);
    await removeTemporaryRoots([requestRoot, workingRoot]);
  }
}

async function readInputBytes(
  reader: () => Promise<Buffer>,
  approval: ApprovalResponse | null,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertInputAccessActive(approval, signal);
  const value = await invokeInputCallback(
    reader,
    approval,
    signal,
    zeroReturnedBuffer,
  );
  if (!Buffer.isBuffer(value)) throw new Error();
  try {
    assertInputAccessActive(approval, signal);
    if (value.byteLength > MAX_PROVIDER_INPUT_BYTES) throw new Error();
    return Buffer.from(value);
  } finally {
    Buffer.prototype.fill.call(value, 0);
  }
}

async function readInputText(
  reader: () => Promise<string>,
  approval: ApprovalResponse | null,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertInputAccessActive(approval, signal);
  const value = await invokeInputCallback(reader, approval, signal);
  assertInputAccessActive(approval, signal);
  if (typeof value !== "string") throw new Error();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > MAX_PROVIDER_INPUT_BYTES) {
    bytes.fill(0);
    throw new Error();
  }
  return bytes;
}

function invokeInputCallback<T>(
  reader: () => Promise<T>,
  approval: ApprovalResponse | null,
  signal: AbortSignal | undefined,
  disposeLateValue?: (value: T) => void,
): Promise<T> {
  assertInputAccessActive(approval, signal);
  const pending = Promise.resolve().then(() => {
    assertInputAccessActive(approval, signal);
    return reader();
  });
  if (signal === undefined) return pending;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const removeAbortListener = (): void => {
      signal.removeEventListener("abort", abort);
    };
    const abort = (): void => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      reject(new Error());
    };
    signal.addEventListener("abort", abort, { once: true });
    void pending.then(
      (value) => {
        if (settled) {
          try {
            disposeLateValue?.(value);
          } catch {
            // Late callback disposal is best effort after the public call has settled.
          }
          return;
        }
        settled = true;
        removeAbortListener();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        removeAbortListener();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}

function zeroReturnedBuffer(value: Buffer): void {
  if (Buffer.isBuffer(value)) Buffer.prototype.fill.call(value, 0);
}

function assertInputAccessActive(
  approval: ApprovalResponse | null,
  signal: AbortSignal | undefined,
): void {
  assertActive(signal);
  assertApprovalActive(approval);
}

function assertInvocationContext(
  sourceRequest: ProviderModelRequest,
  sourceContext: ProviderAdapterContext,
): ValidatedInvocation {
  const request = snapshotProviderModelRequest(sourceRequest);
  const context = snapshotProviderAdapterContext(sourceContext);
  const identity = computeCaseInputIdentity({
    caseId: context.caseInputIdentity.caseId,
    documentKind: context.caseInputIdentity.documentKind,
    preparedImage: { ...context.caseInputIdentity.preparedImage },
  });
  if (
    context.bundle.version !== 1 ||
    !isDigest(context.bundle.manifestDigest) ||
    !isSafeLabel(context.phase) ||
    !isCaseId(context.caseId) ||
    !isSafeLabel(context.documentKind) ||
    context.caseId !== identity.caseId ||
    context.documentKind !== identity.documentKind ||
    context.caseInputIdentity.identityVersion !== identity.identityVersion ||
    context.caseInputIdentity.digest !== identity.digest ||
    context.caseInputIdentity.preparedImage.mediaType !== request.image.mediaType ||
    context.caseInputIdentity.preparedImage.sha256 !== context.inputDigests.image ||
    context.requested.model !== request.requested.model ||
    context.requested.effort !== request.requested.effort ||
    context.requested.maxTokens !== request.requested.maxTokens ||
    context.sanitizerRequirement.sanitizerRequired ||
    context.sanitizerRequirement.policyRequired
  ) {
    throw new Error();
  }
  if (context.approval !== null) {
    assertApprovalActive(context.approval);
    if (
      context.approval.phase !== context.phase ||
      context.approval.requirementVerifierId !==
        context.sanitizerRequirement.requirementVerifierId ||
      context.approval.requirementVerifierVersion !==
        context.sanitizerRequirement.requirementVerifierVersion ||
      context.approval.consumerSourceCommit !==
        context.sanitizerRequirement.consumerSourceCommit ||
      context.approval.requirementDecisionDigest !==
        context.sanitizerRequirement.requirementDecisionDigest ||
      context.approval.sanitizerRequirementVersion !==
        context.sanitizerRequirement.sanitizerRequirementVersion ||
      context.approval.sanitizerRequired !==
        context.sanitizerRequirement.sanitizerRequired ||
      context.approval.policyRequired !== context.sanitizerRequirement.policyRequired ||
      context.approval.sanitizerRequirementReason !==
        context.sanitizerRequirement.sanitizerRequirementReason
    ) {
      throw new Error();
    }
  }
  return Object.freeze({ request, context });
}

function snapshotProviderModelRequest(value: unknown): ProviderModelRequest {
  const source = requiredRuntimeObject(value);
  assertRuntimeKeys(source, [
    "image",
    "schema",
    "schemaInput",
    "system",
    "instruction",
    "requested",
  ]);
  const imageValue = source.image;
  const schemaValue = source.schema;
  const schemaInputValue = source.schemaInput;
  const systemValue = source.system;
  const instructionValue = source.instruction;
  const requestedValue = source.requested;
  const image = snapshotBinaryInput(imageValue);
  const schema = deepFreeze(
    normalizeJsonValue(schemaValue, "command provider schema", MAX_PROVIDER_INPUT_BYTES),
  );
  const schemaInput = snapshotBinaryInput(schemaInputValue);
  const system = snapshotTextInput(systemValue);
  const instruction = snapshotTextInput(instructionValue);
  const requested = snapshotRequestedSettings(requestedValue);
  return Object.freeze({
    image,
    schema,
    schemaInput,
    system,
    instruction,
    requested,
  });
}

function snapshotBinaryInput(value: unknown): ProviderModelRequest["image"] {
  const input = requiredRuntimeObject(value);
  assertRuntimeKeys(input, ["mediaType", "readBytes"]);
  const mediaType = input.mediaType;
  const readBytes = input.readBytes;
  if (!isBoundedText(mediaType) || typeof readBytes !== "function") throw new Error();
  return Object.freeze({
    mediaType,
    readBytes: readBytes as () => Promise<Buffer>,
  });
}

function snapshotTextInput(value: unknown): ProviderModelRequest["system"] {
  const input = requiredRuntimeObject(value);
  assertRuntimeKeys(input, ["mediaType", "readText"]);
  const mediaType = input.mediaType;
  const readText = input.readText;
  if (!isBoundedText(mediaType) || typeof readText !== "function") throw new Error();
  return Object.freeze({
    mediaType,
    readText: readText as () => Promise<string>,
  });
}

function snapshotProviderAdapterContext(value: unknown): ProviderAdapterContext {
  const source = requiredRuntimeObject(value);
  assertRuntimeKeys(source, [
    "phase",
    "bundle",
    "caseId",
    "documentKind",
    "caseInputIdentity",
    "inputDigests",
    "requested",
    "provenance",
    "sanitizerRequirement",
    "approval",
  ]);
  const phase = source.phase;
  const bundleValue = source.bundle;
  const caseId = source.caseId;
  const documentKind = source.documentKind;
  const caseInputIdentityValue = source.caseInputIdentity;
  const inputDigestsValue = source.inputDigests;
  const requestedValue = source.requested;
  const provenanceValue = source.provenance;
  const sanitizerRequirementValue = source.sanitizerRequirement;
  const approvalValue = source.approval;
  if (!isSafeLabel(phase) || !isCaseId(caseId) || !isSafeLabel(documentKind)) {
    throw new Error();
  }
  const bundle = snapshotBundleIdentity(bundleValue);
  const caseInputIdentity = snapshotCaseInputIdentity(caseInputIdentityValue);
  const inputDigests = snapshotInputDigests(inputDigestsValue);
  const requested = snapshotRequestedSettings(requestedValue);
  const provenance = snapshotProvenance(provenanceValue);
  const sanitizerRequirement = snapshotSanitizerRequirement(
    sanitizerRequirementValue,
  );
  const approval =
    approvalValue === null ? null : snapshotApprovalResponse(approvalValue);
  return Object.freeze({
    phase,
    bundle,
    caseId,
    documentKind,
    caseInputIdentity,
    inputDigests,
    requested,
    provenance,
    sanitizerRequirement,
    approval,
  });
}

function snapshotBundleIdentity(value: unknown): ProviderAdapterContext["bundle"] {
  const bundle = requiredRuntimeObject(value);
  assertRuntimeKeys(bundle, ["version", "manifestDigest"]);
  const version = bundle.version;
  const manifestDigest = bundle.manifestDigest;
  if (version !== 1 || !isDigest(manifestDigest)) throw new Error();
  return Object.freeze({ version: 1, manifestDigest });
}

function snapshotCaseInputIdentity(
  value: unknown,
): ProviderAdapterContext["caseInputIdentity"] {
  const identity = requiredRuntimeObject(value);
  assertRuntimeKeys(identity, [
    "identityVersion",
    "caseId",
    "documentKind",
    "preparedImage",
    "digest",
  ]);
  const identityVersion = identity.identityVersion;
  const caseId = identity.caseId;
  const documentKind = identity.documentKind;
  const preparedImageValue = identity.preparedImage;
  const identityDigest = identity.digest;
  const preparedImage = requiredRuntimeObject(preparedImageValue);
  assertRuntimeKeys(preparedImage, ["mediaType", "sha256"]);
  const mediaType = preparedImage.mediaType;
  const sha256 = preparedImage.sha256;
  if (
    identityVersion !== 1 ||
    !isCaseId(caseId) ||
    !isSafeLabel(documentKind) ||
    !isBoundedText(mediaType) ||
    !isDigest(sha256) ||
    !isDigest(identityDigest)
  ) {
    throw new Error();
  }
  return deepFreeze({
    identityVersion: 1,
    caseId,
    documentKind,
    preparedImage: { mediaType, sha256 },
    digest: identityDigest,
  });
}

function snapshotInputDigests(
  value: unknown,
): ProviderAdapterContext["inputDigests"] {
  const inputs = requiredRuntimeObject(value);
  assertRuntimeKeys(inputs, ["image", "schema", "system", "instruction"]);
  const image = inputs.image;
  const schema = inputs.schema;
  const system = inputs.system;
  const instruction = inputs.instruction;
  if (
    !isDigest(image) ||
    !isDigest(schema) ||
    !isDigest(system) ||
    !isDigest(instruction)
  ) {
    throw new Error();
  }
  return Object.freeze({ image, schema, system, instruction });
}

function snapshotProvenance(value: unknown): ProviderAdapterContext["provenance"] {
  const provenance = requiredRuntimeObject(value);
  assertRuntimeKeys(provenance, [
    "harnessVersion",
    "harnessCommit",
    "promptVersion",
    "preprocessVersion",
    "sourceCommit",
  ]);
  const harnessVersion = provenance.harnessVersion;
  const harnessCommit = provenance.harnessCommit;
  const promptVersion = provenance.promptVersion;
  const preprocessVersion = provenance.preprocessVersion;
  const sourceCommit = provenance.sourceCommit;
  if (
    !isSafeLabel(harnessVersion) ||
    !isNullableSafeLabel(harnessCommit) ||
    !isSafeLabel(promptVersion) ||
    !isSafeLabel(preprocessVersion) ||
    !isNullableSafeLabel(sourceCommit)
  ) {
    throw new Error();
  }
  return Object.freeze({
    harnessVersion,
    harnessCommit,
    promptVersion,
    preprocessVersion,
    sourceCommit,
  });
}

function validateInputBytes(
  inputs: { image: Buffer; schema: Buffer; system: Buffer; instruction: Buffer },
  request: ProviderModelRequest,
  context: ProviderAdapterContext,
): void {
  if (
    digest(inputs.image) !== context.inputDigests.image ||
    digest(inputs.schema) !== context.inputDigests.schema ||
    digest(inputs.system) !== context.inputDigests.system ||
    digest(inputs.instruction) !== context.inputDigests.instruction ||
    request.image.mediaType.length === 0 ||
    request.schemaInput.mediaType.length === 0 ||
    request.system.mediaType.length === 0 ||
    request.instruction.mediaType.length === 0
  ) {
    throw new Error();
  }
  const schema = parseJson(
    decodeUtf8Strict(inputs.schema, "command provider schema"),
    "command provider schema",
  );
  if (!jsonEqual(schema, request.schema)) throw new Error();
}

function createRequestManifest(
  options: ValidatedCommandProviderOptions,
  request: ProviderModelRequest,
  context: ProviderAdapterContext,
  phase: string,
  sanitizerRequirement: SanitizerRequirementDecisionV1,
  approval: ApprovalResponse | null,
): CommandProviderRequestManifestV1 {
  return deepFreeze({
    requestVersion: 1,
    phase,
    provider: {
      id: options.providerId,
      route: options.route,
      implementationVersion: options.implementationVersion,
      protocolVersion: COMMAND_PROVIDER_PROTOCOL_VERSION,
    },
    bundle: { ...context.bundle },
    case: { id: context.caseId, documentKind: context.documentKind },
    caseInputIdentity: {
      identityVersion: context.caseInputIdentity.identityVersion,
      caseId: context.caseInputIdentity.caseId,
      documentKind: context.caseInputIdentity.documentKind,
      preparedImage: { ...context.caseInputIdentity.preparedImage },
      digest: context.caseInputIdentity.digest,
    },
    inputs: {
      image: inputReference(INPUT_FILES.image, request.image.mediaType, context.inputDigests.image),
      schema: inputReference(
        INPUT_FILES.schema,
        request.schemaInput.mediaType,
        context.inputDigests.schema,
      ),
      system: inputReference(
        INPUT_FILES.system,
        request.system.mediaType,
        context.inputDigests.system,
      ),
      instruction: inputReference(
        INPUT_FILES.instruction,
        request.instruction.mediaType,
        context.inputDigests.instruction,
      ),
    },
    requested: { ...request.requested },
    provenance: { ...context.provenance },
    sanitizerRequirement: { ...sanitizerRequirement },
    approval,
  });
}

function inputReference(
  inputPath: string,
  mediaType: string,
  sha256: string,
): CommandProviderInputReference {
  return { path: inputPath, mediaType, sha256 };
}

async function assertPrivateDirectory(directory: string): Promise<void> {
  const info = await stat(directory);
  if (
    !info.isDirectory() ||
    (process.platform !== "win32" && (info.mode & 0o077) !== 0)
  ) {
    throw new Error();
  }
}

async function writePrivateFile(filePath: string, bytes: Buffer): Promise<void> {
  const handle = await open(filePath, EXCLUSIVE_WRITE, FILE_MODE);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
    const info = await handle.stat();
    if (!info.isFile() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) {
      throw new Error();
    }
  } finally {
    await handle.close();
  }
}

async function assertRequestDirectory(directory: string): Promise<void> {
  const names = (await readdir(directory)).sort();
  const expected = [...Object.values(INPUT_FILES), REQUEST_FILE].sort();
  if (!jsonEqual(names, expected)) throw new Error();
}

async function runCommand(
  options: ValidatedCommandProviderOptions,
  requestDirectory: string,
  workingDirectory: string,
  allowedEnvironment: ReadonlyArray<readonly [string, string]>,
  approval: ApprovalResponse | null,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  assertApprovalActive(approval);
  return runChildProcess(
    options,
    workingDirectory,
    createChildEnvironment(allowedEnvironment, "invoke", requestDirectory),
    undefined,
    signal,
  );
}

async function runApprovedCommand(
  options: ValidatedCommandProviderOptions,
  workingDirectory: string,
  allowedEnvironment: ReadonlyArray<readonly [string, string]>,
  approval: ApprovalResponse,
  materializeRequest: (assertReleaseActive?: () => void) => Promise<string>,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  assertApprovalActive(approval);
  const transportRequest: CommandProviderTransportRequestV1 = {
    requestVersion: 1,
    operation: "prepareTransport",
    approval,
  };
  const transportRequestBytes = Buffer.from(`${JSON.stringify(transportRequest)}\n`, "utf8");
  if (transportRequestBytes.byteLength > MAX_REQUEST_MANIFEST_BYTES) throw new Error();
  try {
    return await runApprovedChildProcess(
      options,
      workingDirectory,
      createChildEnvironment(allowedEnvironment, "invoke"),
      transportRequestBytes,
      approval,
      materializeRequest,
      signal,
    );
  } finally {
    transportRequestBytes.fill(0);
  }
}

async function prepareCommandTransport(
  options: ValidatedCommandProviderOptions,
  approval: ApprovalResponse,
  signal?: AbortSignal,
  existingEnvironment?: ReadonlyArray<readonly [string, string]>,
): Promise<ApprovalResponse> {
  let temporaryRoot: string | undefined;
  let requestBytes: Buffer | undefined;
  try {
    assertActive(signal);
    assertApprovalActive(approval);
    temporaryRoot = await mkdtemp(path.join(tmpdir(), "svbench-command-transport-"));
    await chmod(temporaryRoot, DIRECTORY_MODE);
    await assertPrivateDirectory(temporaryRoot);
    const workingDirectory = path.join(temporaryRoot, "work");
    await mkdir(workingDirectory, { mode: DIRECTORY_MODE });
    await assertPrivateDirectory(workingDirectory);
    if ((await readdir(workingDirectory)).length !== 0) throw new Error();
    const allowedEnvironment = existingEnvironment ?? snapshotAllowedEnvironment(options);
    const request: CommandProviderTransportRequestV1 = {
      requestVersion: 1,
      operation: "prepareTransport",
      approval,
    };
    requestBytes = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
    if (requestBytes.byteLength > MAX_REQUEST_MANIFEST_BYTES) throw new Error();
    const responseBytes = await runChildProcess(
      options,
      workingDirectory,
      createChildEnvironment(allowedEnvironment, "prepare-transport"),
      requestBytes,
      signal,
    );
    const parsed = parseJson(
      decodeUtf8Strict(responseBytes, "command provider transport response"),
      "command provider transport response",
    );
    const response = snapshotApprovalResponse(parsed);
    if (!approvalEqual(response, approval)) throw new Error();
    assertApprovalActive(response);
    if ((await readdir(workingDirectory)).length !== 0) throw new Error();
    return response;
  } finally {
    requestBytes?.fill(0);
    if (temporaryRoot !== undefined) {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
}

async function removeTemporaryRoots(roots: Array<string | undefined>): Promise<void> {
  let failed = false;
  for (const root of roots) {
    if (root === undefined) continue;
    try {
      await rm(root, { recursive: true, force: true });
    } catch {
      failed = true;
    }
  }
  if (failed) throw new Error();
}

function snapshotAllowedEnvironment(
  options: ValidatedCommandProviderOptions,
): ReadonlyArray<readonly [string, string]> {
  const entries: Array<readonly [string, string]> = [];
  for (const name of options.envAllowlist) {
    const value = process.env[name];
    if (value !== undefined) entries.push(Object.freeze([name, value]) as readonly [string, string]);
  }
  return Object.freeze(entries);
}

function createChildEnvironment(
  allowed: ReadonlyArray<readonly [string, string]>,
  operation: "prepare-transport" | "invoke",
  requestDirectory?: string,
): NodeJS.ProcessEnv {
  const environment = Object.create(null) as NodeJS.ProcessEnv;
  for (const [name, value] of allowed) environment[name] = value;
  environment[COMMAND_PROVIDER_OPERATION_ENV] = operation;
  if (requestDirectory !== undefined) {
    environment[COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV] = requestDirectory;
  }
  return environment;
}

async function runApprovedChildProcess(
  options: ValidatedCommandProviderOptions,
  workingDirectory: string,
  environment: NodeJS.ProcessEnv,
  transportRequestBytes: Buffer,
  approval: ApprovalResponse,
  materializeRequest: (assertReleaseActive?: () => void) => Promise<string>,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  let child;
  try {
    child = spawn(options.executable, options.argv, {
      cwd: workingDirectory,
      env: environment,
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    throw new Error();
  }

  let outputBytes = 0;
  let failed = false;
  let exited = false;
  let requestReleased = false;
  let termination: Promise<void> | undefined;
  let rejectFailure!: (error: Error) => void;
  const failure = new Promise<never>((_resolve, reject) => {
    rejectFailure = reject;
  });
  void failure.catch(() => undefined);
  const terminate = (): void => {
    if (failed) return;
    failed = true;
    termination = terminateProcessTree(child).finally(() => {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    });
    rejectFailure(new Error());
  };
  const addOutputBytes = (count: number): void => {
    outputBytes += count;
    if (outputBytes > options.outputLimitBytes) {
      terminate();
      throw new Error();
    }
  };
  const close = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve) => {
      child.once("close", (code, childSignal) => resolve({ code, signal: childSignal }));
    },
  );
  const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve) => {
      child.once("exit", (code, childSignal) => {
        exited = true;
        if (!requestReleased) terminate();
        resolve({ code, signal: childSignal });
      });
    },
  );
  const prematureClose = async (): Promise<never> => {
    await close;
    throw new Error();
  };
  const prematureExit = async (): Promise<never> => {
    await exit;
    throw new Error();
  };
  const assertChildRunning = (): void => {
    if (exited || child.exitCode !== null || child.signalCode !== null) throw new Error();
  };
  const abort = (): void => terminate();
  signal?.addEventListener("abort", abort, { once: true });
  child.once("error", terminate);
  child.stdin.once("error", terminate);
  child.stderr.on("data", (chunk: Buffer) => {
    try {
      addOutputBytes(chunk.length);
    } catch {
      // addOutputBytes already failed and terminated the child.
    }
  });

  try {
    const stdout = child.stdout[Symbol.asyncIterator]();
    await Promise.race([
      writeChildInput(child.stdin, transportRequestBytes, false),
      failure,
      prematureExit(),
      prematureClose(),
    ]);
    const attestationBytes = await Promise.race([
      readStrictLine(stdout, addOutputBytes),
      failure,
      prematureExit(),
      prematureClose(),
    ]);
    const parsed = parseJson(
      decodeUtf8Strict(attestationBytes, "command provider transport response"),
      "command provider transport response",
    );
    const response = snapshotApprovalResponse(parsed);
    if (!approvalEqual(response, approval)) throw new Error();
    assertApprovalActive(response);
    if (
      (
        await Promise.race([
          readdir(workingDirectory),
          failure,
          prematureExit(),
          prematureClose(),
        ])
      ).length !== 0
    ) {
      throw new Error();
    }
    await Promise.race([
      new Promise<void>((resolve) => {
        setImmediate(() => setImmediate(resolve));
      }),
      failure,
      prematureExit(),
      prematureClose(),
    ]);
    assertChildRunning();

    const assertReleaseActive = (): void => {
      assertChildRunning();
      assertActive(signal);
      assertApprovalActive(response);
    };
    const materialization = materializeRequest(assertReleaseActive);
    let requestDirectory: string;
    try {
      requestDirectory = await Promise.race([
        materialization,
        failure,
        prematureExit(),
        prematureClose(),
      ]);
    } catch {
      await materialization.catch(() => undefined);
      throw new Error();
    }
    assertChildRunning();
    assertActive(signal);
    assertApprovalActive(response);
    const invokeRequest: CommandProviderInvokeRequestV1 = {
      requestVersion: 1,
      operation: "invoke",
      requestDirectory,
    };
    const invokeRequestBytes = Buffer.from(`${JSON.stringify(invokeRequest)}\n`, "utf8");
    try {
      if (invokeRequestBytes.byteLength > MAX_REQUEST_MANIFEST_BYTES) throw new Error();
      await Promise.race([
        writeChildInput(child.stdin, invokeRequestBytes, true),
        failure,
        prematureExit(),
        prematureClose(),
      ]);
      assertChildRunning();
      requestReleased = true;
    } finally {
      invokeRequestBytes.fill(0);
    }

    const responseBytes = await Promise.race([
      readRemaining(stdout, addOutputBytes),
      failure,
    ]);
    const status = await close;
    await termination;
    if (failed || status.code !== 0 || status.signal !== null) throw new Error();
    return responseBytes;
  } catch {
    terminate();
    await termination;
    await close;
    throw new Error();
  } finally {
    signal?.removeEventListener("abort", abort);
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
  }
}

async function writeChildInput(
  input: NodeJS.WritableStream,
  bytes: Buffer,
  end: boolean,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const callback = (error?: Error | null): void => {
      if (error === undefined || error === null) resolve();
      else reject(error);
    };
    if (end) input.end(bytes, callback);
    else input.write(bytes, callback);
  });
}

async function readStrictLine(
  stdout: AsyncIterator<Buffer | string>,
  addOutputBytes: (count: number) => void,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for (;;) {
    const next = await stdout.next();
    if (next.done) throw new Error();
    const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
    addOutputBytes(chunk.length);
    const newline = chunk.indexOf(0x0a);
    if (newline === -1) {
      chunks.push(Buffer.from(chunk));
      continue;
    }
    if (newline !== chunk.length - 1) throw new Error();
    chunks.push(Buffer.from(chunk.subarray(0, newline)));
    return Buffer.concat(chunks);
  }
}

async function readRemaining(
  stdout: AsyncIterator<Buffer | string>,
  addOutputBytes: (count: number) => void,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for (;;) {
    const next = await stdout.next();
    if (next.done) return Buffer.concat(chunks);
    const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
    addOutputBytes(chunk.length);
    chunks.push(Buffer.from(chunk));
  }
}

async function runChildProcess(
  options: ValidatedCommandProviderOptions,
  workingDirectory: string,
  environment: NodeJS.ProcessEnv,
  input: Buffer | undefined,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  return new Promise<Buffer>((resolve, reject) => {
    let child;
    try {
      child = spawn(options.executable, options.argv, {
        cwd: workingDirectory,
        env: environment,
        detached: process.platform !== "win32",
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      reject(new Error());
      return;
    }
    const stdout: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    let failed = false;
    let termination: Promise<void> | undefined;
    const finish = (error?: Error, bytes?: Buffer): void => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      if (error !== undefined) reject(error);
      else resolve(bytes!);
    };
    const fail = (): void => {
      if (failed) return;
      failed = true;
      termination = terminateProcessTree(child).finally(() => {
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
      });
    };
    const abort = (): void => fail();
    signal?.addEventListener("abort", abort, { once: true });
    child.on("error", () => {
      failed = true;
      finish(new Error());
    });
    child.stdin.on("error", () => fail());
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > options.outputLimitBytes) {
        fail();
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > options.outputLimitBytes) fail();
    });
    child.on("close", (code, childSignal) => {
      if (settled) return;
      void (async () => {
        await termination;
        if (failed || code !== 0 || childSignal !== null) {
          finish(new Error());
          return;
        }
        finish(undefined, Buffer.concat(stdout));
      })();
    });
    child.stdin.end(input);
    if (signal?.aborted) abort();
  });
}

async function terminateProcessTree(child: ReturnType<typeof spawn>): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-pid, "SIGKILL");
      return;
    } catch {
      child.kill("SIGKILL");
      return;
    }
  }
  const systemRoot = process.env.SystemRoot;
  if (systemRoot === undefined || !path.isAbsolute(systemRoot)) {
    child.kill("SIGKILL");
    return;
  }
  const treeKilled = await new Promise<boolean>((resolve) => {
    let killer;
    try {
      killer = spawn(path.join(systemRoot, "System32", "taskkill.exe"), [
        "/pid",
        String(pid),
        "/t",
        "/f",
      ], {
        env: Object.create(null) as NodeJS.ProcessEnv,
        shell: false,
        stdio: "ignore",
      });
    } catch {
      resolve(false);
      return;
    }
    killer.on("error", () => resolve(false));
    killer.on("close", (code, killerSignal) => resolve(code === 0 && killerSignal === null));
  });
  if (!treeKilled) child.kill("SIGKILL");
}

function parseResponse(
  bytes: Buffer,
  options: ValidatedCommandProviderOptions,
  context: ProviderAdapterContext,
  expectedPhase: string,
  expectedSanitizerRequirement: SanitizerRequirementDecisionV1,
  expectedApproval: ApprovalResponse | null,
): CommandProviderResponseV1 {
  const value = parseJson(
    decodeUtf8Strict(bytes, "command provider response"),
    "command provider response",
  );
  if (!isJsonObject(value)) throw new Error();
  assertKeys(value, [
    "responseVersion",
    "phase",
    "provider",
    "requested",
    "caseInputIdentity",
    "sanitizerRequirement",
    "approval",
    "document",
    "responded",
  ]);
  if (value.responseVersion !== 1 || value.phase !== expectedPhase) throw new Error();
  const provider = requiredObject(value.provider);
  assertKeys(provider, ["id", "route", "implementationVersion", "protocolVersion"]);
  if (
    provider.id !== options.providerId ||
    provider.route !== options.route ||
    provider.implementationVersion !== options.implementationVersion ||
    provider.protocolVersion !== COMMAND_PROVIDER_PROTOCOL_VERSION
  ) {
    throw new Error();
  }
  const requested = snapshotRequestedSettings(value.requested);
  if (!jsonEqual(requested, context.requested)) throw new Error();
  const caseInputIdentity = requiredObject(value.caseInputIdentity);
  assertKeys(caseInputIdentity, ["identityVersion", "digest"]);
  if (
    caseInputIdentity.identityVersion !== context.caseInputIdentity.identityVersion ||
    caseInputIdentity.digest !== context.caseInputIdentity.digest
  ) {
    throw new Error();
  }
  const sanitizerRequirement = requiredObject(value.sanitizerRequirement);
  assertSanitizerRequirement(sanitizerRequirement, expectedSanitizerRequirement);
  const approval =
    value.approval === null ? null : snapshotApprovalResponse(requiredObject(value.approval));
  if (!approvalEqual(approval, expectedApproval)) throw new Error();
  if (!Object.hasOwn(value, "document")) throw new Error();
  const responded = requiredObject(value.responded);
  assertKeys(responded, ["model", "effort", "usage", "stopReason"]);
  const model = nullableSafeLabel(responded.model);
  const effort = nullableSafeLabel(responded.effort);
  const stopReason = nullableSafeLabel(responded.stopReason);
  const usage = snapshotUsage(responded.usage);
  return deepFreeze({
    responseVersion: 1,
    phase: expectedPhase,
    provider: {
      id: options.providerId,
      route: options.route,
      implementationVersion: options.implementationVersion,
      protocolVersion: COMMAND_PROVIDER_PROTOCOL_VERSION,
    },
    requested,
    caseInputIdentity: {
      identityVersion: context.caseInputIdentity.identityVersion,
      digest: context.caseInputIdentity.digest,
    },
    sanitizerRequirement: { ...expectedSanitizerRequirement },
    approval,
    document: value.document!,
    responded: { model, effort, usage, stopReason },
  });
}

function snapshotRequestedSettings(value: unknown): RequestedExecutionSettings {
  const requested = requiredObject(value);
  assertKeys(requested, ["model", "effort", "maxTokens"]);
  const model = nullableSafeLabel(requested.model);
  const effort = nullableSafeLabel(requested.effort);
  const maxTokens = requested.maxTokens;
  if (
    maxTokens !== null &&
    (typeof maxTokens !== "number" || !Number.isSafeInteger(maxTokens) || maxTokens < 1)
  ) {
    throw new Error();
  }
  return deepFreeze({ model, effort, maxTokens });
}

function assertApprovalActive(approval: ApprovalResponse | null): void {
  if (
    approval !== null &&
    (!approval.approved ||
      (approval.expiresAt !== undefined &&
        approval.expiresAt !== null &&
        Date.parse(approval.expiresAt) <= Date.now()))
  ) {
    throw new Error();
  }
}

function assertSanitizerRequirement(
  value: Record<string, JsonValue>,
  expected: SanitizerRequirementDecisionV1,
): void {
  const keys = [
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
    "consumerSourceCommit",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "requirementDecisionDigest",
  ];
  assertKeys(value, keys);
  for (const key of keys) {
    if (value[key] !== expected[key as keyof SanitizerRequirementDecisionV1]) {
      throw new Error();
    }
  }
}

function snapshotSanitizerRequirement(value: unknown): SanitizerRequirementDecisionV1 {
  const requirement = requiredObject(value);
  const keys = [
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
    "consumerSourceCommit",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "requirementDecisionDigest",
  ];
  assertKeys(requirement, keys);
  const sanitizerRequirementVersion = requirement.sanitizerRequirementVersion;
  const sanitizerRequired = requirement.sanitizerRequired;
  const policyRequired = requirement.policyRequired;
  const sanitizerRequirementReason = requirement.sanitizerRequirementReason;
  const consumerSourceCommit = requirement.consumerSourceCommit;
  const requirementVerifierId = requirement.requirementVerifierId;
  const requirementVerifierVersion = requirement.requirementVerifierVersion;
  const requirementDecisionDigest = requirement.requirementDecisionDigest;
  if (
    sanitizerRequirementVersion !== 1 ||
    typeof sanitizerRequired !== "boolean" ||
    typeof policyRequired !== "boolean" ||
    !isSafeLabel(sanitizerRequirementReason) ||
    !isNullableSafeLabel(consumerSourceCommit) ||
    !isSafeLabel(requirementVerifierId) ||
    !isSafeLabel(requirementVerifierVersion) ||
    !isDigest(requirementDecisionDigest)
  ) {
    throw new Error();
  }
  const expectedDigest = computeSanitizerRequirementDigest({
    sanitizerRequirementVersion: 1,
    sanitizerRequired,
    policyRequired,
    sanitizerRequirementReason,
    consumerSourceCommit,
    requirementVerifierId,
    requirementVerifierVersion,
  });
  if (requirementDecisionDigest !== expectedDigest) throw new Error();
  return deepFreeze({
    sanitizerRequirementVersion: 1,
    sanitizerRequired,
    policyRequired,
    sanitizerRequirementReason,
    consumerSourceCommit,
    requirementVerifierId,
    requirementVerifierVersion,
    requirementDecisionDigest,
  });
}

function snapshotApprovalResponse(value: unknown): ApprovalResponse {
  const approval = requiredObject(value);
  const required = [
    "responseVersion",
    "approved",
    "gateId",
    "protocolVersion",
    "snapshotDigest",
    "runtimeBindingDigest",
    "runtimeBindingIdentity",
    "approvedScopeDigest",
    "approvedScopeIdentity",
    "phase",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "consumerSourceCommit",
    "requirementDecisionDigest",
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
  ];
  const optional = ["checkedAt", "expiresAt", "reasonCode"];
  assertKeys(approval, required, optional);
  const responseVersion = approval.responseVersion;
  const approved = approval.approved;
  const gateId = approval.gateId;
  const protocolVersion = approval.protocolVersion;
  const snapshotDigest = approval.snapshotDigest;
  const runtimeBindingDigest = approval.runtimeBindingDigest;
  const runtimeBindingIdentity = approval.runtimeBindingIdentity;
  const approvedScopeDigest = approval.approvedScopeDigest;
  const approvedScopeIdentity = approval.approvedScopeIdentity;
  const phase = approval.phase;
  const requirementVerifierId = approval.requirementVerifierId;
  const requirementVerifierVersion = approval.requirementVerifierVersion;
  const consumerSourceCommit = approval.consumerSourceCommit;
  const requirementDecisionDigest = approval.requirementDecisionDigest;
  const sanitizerRequirementVersion = approval.sanitizerRequirementVersion;
  const sanitizerRequired = approval.sanitizerRequired;
  const policyRequired = approval.policyRequired;
  const sanitizerRequirementReason = approval.sanitizerRequirementReason;
  const checkedAt = Object.hasOwn(approval, "checkedAt") ? approval.checkedAt : undefined;
  const expiresAt = Object.hasOwn(approval, "expiresAt") ? approval.expiresAt : undefined;
  const reasonCode = Object.hasOwn(approval, "reasonCode") ? approval.reasonCode : undefined;
  if (
    responseVersion !== 1 ||
    typeof approved !== "boolean" ||
    !isSafeLabel(gateId) ||
    protocolVersion !== 1 ||
    !isDigest(snapshotDigest) ||
    !isDigest(runtimeBindingDigest) ||
    !isSafeLabel(runtimeBindingIdentity) ||
    !isDigest(approvedScopeDigest) ||
    !isSafeLabel(approvedScopeIdentity) ||
    !isSafeLabel(phase) ||
    !isSafeLabel(requirementVerifierId) ||
    !isSafeLabel(requirementVerifierVersion) ||
    !isNullableSafeLabel(consumerSourceCommit) ||
    !isDigest(requirementDecisionDigest) ||
    sanitizerRequirementVersion !== 1 ||
    typeof sanitizerRequired !== "boolean" ||
    typeof policyRequired !== "boolean" ||
    !isSafeLabel(sanitizerRequirementReason) ||
    !isOptionalDateTime(checkedAt) ||
    !isOptionalDateTime(expiresAt) ||
    (reasonCode !== undefined && !isSafeLabel(reasonCode))
  ) {
    throw new Error();
  }
  return deepFreeze({
    responseVersion: 1,
    approved,
    gateId,
    protocolVersion: 1,
    snapshotDigest,
    runtimeBindingDigest,
    runtimeBindingIdentity,
    approvedScopeDigest,
    approvedScopeIdentity,
    phase,
    requirementVerifierId,
    requirementVerifierVersion,
    consumerSourceCommit,
    requirementDecisionDigest,
    sanitizerRequirementVersion: 1,
    sanitizerRequired,
    policyRequired,
    sanitizerRequirementReason,
    ...(checkedAt === undefined ? {} : { checkedAt }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(reasonCode === undefined ? {} : { reasonCode }),
  });
}

function approvalEqual(left: ApprovalResponse | null, right: ApprovalResponse | null): boolean {
  if (left === null || right === null) return left === right;
  const keys = [
    "responseVersion",
    "approved",
    "gateId",
    "protocolVersion",
    "snapshotDigest",
    "runtimeBindingDigest",
    "runtimeBindingIdentity",
    "approvedScopeDigest",
    "approvedScopeIdentity",
    "phase",
    "requirementVerifierId",
    "requirementVerifierVersion",
    "consumerSourceCommit",
    "requirementDecisionDigest",
    "sanitizerRequirementVersion",
    "sanitizerRequired",
    "policyRequired",
    "sanitizerRequirementReason",
    "checkedAt",
    "expiresAt",
    "reasonCode",
  ] as const;
  return keys.every((key) => (left[key] ?? null) === (right[key] ?? null));
}

function snapshotUsage(value: JsonValue | undefined): ProviderUsage {
  const usage = requiredObject(value);
  assertKeys(usage, ["available"], [
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
    "totalTokens",
  ]);
  if (typeof usage.available !== "boolean") throw new Error();
  if (!usage.available) {
    if (Object.keys(usage).length !== 1) throw new Error();
    return { available: false };
  }
  const result: ProviderUsage = { available: true };
  for (const key of [
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
    "totalTokens",
  ] as const) {
    const entry = usage[key];
    if (entry === undefined) continue;
    if (entry !== null && (typeof entry !== "number" || !Number.isSafeInteger(entry) || entry < 0)) {
      throw new Error();
    }
    result[key] = entry;
  }
  return result;
}

function requiredObject(value: unknown): Record<string, JsonValue> {
  if (!isJsonObject(value)) throw new Error();
  return value;
}

function requiredRuntimeObject(value: unknown): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw new Error();
  }
  return value as Record<string, unknown>;
}

function assertRuntimeKeys(value: Record<string, unknown>, required: string[]): void {
  const allowed = new Set(required);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new Error();
  }
}

function assertKeys(
  value: Record<string, JsonValue>,
  required: string[],
  optional: string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new Error();
  }
}

function nullableSafeLabel(value: JsonValue | undefined): string | null {
  if (value === null) return null;
  if (!isSafeLabel(value)) throw new Error();
  return value;
}

function isNullableSafeLabel(value: unknown): value is string | null {
  return value === null || isSafeLabel(value);
}

function isOptionalDateTime(value: JsonValue | undefined): value is string | null | undefined {
  if (value === undefined || value === null) return true;
  if (typeof value !== "string") return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|([+-])(\d{2}):(\d{2}))$/u.exec(
      value,
    );
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  return match[7] === "Z" || (Number(match[9]) <= 23 && Number(match[10]) <= 59);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL_PATTERN.test(value);
}

function isCaseId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 128 &&
    /^[a-z0-9][a-z0-9._-]*$/u.test(value)
  );
}

function isBoundedText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertActive(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error();
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
