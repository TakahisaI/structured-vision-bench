import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, mkdir, mkdtemp, open, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  decodeUtf8Strict,
  isJsonObject,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../bundle/validate-bundle.js";
import { RunnerError } from "../runner/errors.js";
import {
  computeCaseInputIdentity,
  computeSanitizerRequirementDigest,
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

type ValidatedCommandProviderOptions = Readonly<{
  executable: string;
  argv: string[];
  envAllowlist: string[];
  outputLimitBytes: number;
  providerId: string;
  route: string;
  implementationVersion: string;
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
    if (
      typeof executable !== "string" ||
      executable.length === 0 ||
      executable.length > 240 ||
      !path.isAbsolute(executable) ||
      argv.some((argument) => typeof argument !== "string" || argument.length > 240) ||
      envAllowlist.some(
        (name) =>
          typeof name !== "string" ||
          !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name) ||
          name === COMMAND_PROVIDER_REQUEST_DIRECTORY_ENV ||
          name === COMMAND_PROVIDER_OPERATION_ENV,
      ) ||
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
  request: ProviderModelRequest,
  context: ProviderAdapterContext,
  signal: AbortSignal | undefined,
): Promise<ProviderResponse> {
  assertInvocationContext(options, request, context);
  assertActive(signal);
  let imageBytes: Buffer | undefined;
  let schemaBytes: Buffer | undefined;
  let systemBytes: Buffer | undefined;
  let instructionBytes: Buffer | undefined;
  let temporaryRoot: string | undefined;
  try {
    imageBytes = await readInputBytes(request.image.readBytes, signal);
    schemaBytes = await readInputBytes(request.schemaInput.readBytes, signal);
    systemBytes = await readInputText(request.system.readText, signal);
    instructionBytes = await readInputText(request.instruction.readText, signal);
    const inputBytes = {
      image: imageBytes,
      schema: schemaBytes,
      system: systemBytes,
      instruction: instructionBytes,
    };
    validateInputBytes(inputBytes, request, context);

    temporaryRoot = await mkdtemp(path.join(tmpdir(), "svbench-command-provider-"));
    await chmod(temporaryRoot, DIRECTORY_MODE);
    await assertPrivateDirectory(temporaryRoot);
    const requestDirectory = path.join(temporaryRoot, "request");
    const workingDirectory = path.join(temporaryRoot, "work");
    await mkdir(requestDirectory, { mode: DIRECTORY_MODE });
    await mkdir(workingDirectory, { mode: DIRECTORY_MODE });
    await assertPrivateDirectory(requestDirectory);
    await assertPrivateDirectory(workingDirectory);
    const manifest = createRequestManifest(options, request, context);
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8");
    if (manifestBytes.byteLength > MAX_REQUEST_MANIFEST_BYTES) throw new Error();
    await writePrivateFile(path.join(requestDirectory, INPUT_FILES.image), inputBytes.image);
    await writePrivateFile(path.join(requestDirectory, INPUT_FILES.schema), inputBytes.schema);
    await writePrivateFile(path.join(requestDirectory, INPUT_FILES.system), inputBytes.system);
    await writePrivateFile(
      path.join(requestDirectory, INPUT_FILES.instruction),
      inputBytes.instruction,
    );
    await writePrivateFile(
      path.join(requestDirectory, REQUEST_FILE),
      manifestBytes,
    );
    await assertRequestDirectory(requestDirectory);
    if ((await readdir(workingDirectory)).length !== 0) throw new Error();
    const environment = snapshotAllowedEnvironment(options);
    if (context.approval !== null) {
      await prepareCommandTransport(
        options,
        context.approval,
        signal,
        workingDirectory,
        environment,
      );
      if ((await readdir(workingDirectory)).length !== 0) throw new Error();
    }
    const responseBytes = await runCommand(
      options,
      requestDirectory,
      workingDirectory,
      environment,
      context.approval,
      signal,
    );
    const response = parseResponse(responseBytes, options, context);
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
    if (temporaryRoot !== undefined) {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
}

async function readInputBytes(
  reader: () => Promise<Buffer>,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  const value = await reader();
  if (!Buffer.isBuffer(value)) throw new Error();
  try {
    assertActive(signal);
    if (value.byteLength > MAX_PROVIDER_INPUT_BYTES) throw new Error();
    return Buffer.from(value);
  } finally {
    Buffer.prototype.fill.call(value, 0);
  }
}

async function readInputText(
  reader: () => Promise<string>,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  const value = await reader();
  assertActive(signal);
  if (typeof value !== "string") throw new Error();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > MAX_PROVIDER_INPUT_BYTES) {
    bytes.fill(0);
    throw new Error();
  }
  return bytes;
}

function assertInvocationContext(
  options: ValidatedCommandProviderOptions,
  request: ProviderModelRequest,
  context: ProviderAdapterContext,
): void {
  const identity = computeCaseInputIdentity({
    caseId: context.caseInputIdentity.caseId,
    documentKind: context.caseInputIdentity.documentKind,
    preparedImage: { ...context.caseInputIdentity.preparedImage },
  });
  const requirementDigest = computeSanitizerRequirementDigest({
    sanitizerRequirementVersion:
      context.sanitizerRequirement.sanitizerRequirementVersion,
    sanitizerRequired: context.sanitizerRequirement.sanitizerRequired,
    policyRequired: context.sanitizerRequirement.policyRequired,
    sanitizerRequirementReason:
      context.sanitizerRequirement.sanitizerRequirementReason,
    consumerSourceCommit: context.sanitizerRequirement.consumerSourceCommit,
    requirementVerifierId: context.sanitizerRequirement.requirementVerifierId,
    requirementVerifierVersion:
      context.sanitizerRequirement.requirementVerifierVersion,
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
    !isDigest(context.inputDigests.schema) ||
    !isDigest(context.inputDigests.system) ||
    !isDigest(context.inputDigests.instruction) ||
    !isNullableSafeLabel(context.requested.model) ||
    !isNullableSafeLabel(context.requested.effort) ||
    (context.requested.maxTokens !== null &&
      (!Number.isSafeInteger(context.requested.maxTokens) ||
        context.requested.maxTokens < 1)) ||
    !isSafeLabel(context.provenance.harnessVersion) ||
    !isNullableSafeLabel(context.provenance.harnessCommit) ||
    !isSafeLabel(context.provenance.promptVersion) ||
    !isSafeLabel(context.provenance.preprocessVersion) ||
    !isNullableSafeLabel(context.provenance.sourceCommit) ||
    !isSafeLabel(context.sanitizerRequirement.sanitizerRequirementReason) ||
    !isSafeLabel(context.sanitizerRequirement.requirementVerifierId) ||
    !isSafeLabel(context.sanitizerRequirement.requirementVerifierVersion) ||
    !isNullableSafeLabel(context.sanitizerRequirement.consumerSourceCommit) ||
    context.requested.model !== request.requested.model ||
    context.requested.effort !== request.requested.effort ||
    context.requested.maxTokens !== request.requested.maxTokens ||
    context.sanitizerRequirement.sanitizerRequired ||
    context.sanitizerRequirement.policyRequired ||
    context.sanitizerRequirement.requirementDecisionDigest !== requirementDigest
  ) {
    throw new Error();
  }
  if (context.approval !== null) {
    const approval = snapshotApprovalResponse(context.approval);
    if (
      approval.phase !== context.phase ||
      approval.requirementVerifierId !==
        context.sanitizerRequirement.requirementVerifierId ||
      approval.requirementVerifierVersion !==
        context.sanitizerRequirement.requirementVerifierVersion ||
      approval.consumerSourceCommit !== context.sanitizerRequirement.consumerSourceCommit ||
      approval.requirementDecisionDigest !==
        context.sanitizerRequirement.requirementDecisionDigest ||
      approval.sanitizerRequirementVersion !==
        context.sanitizerRequirement.sanitizerRequirementVersion ||
      approval.sanitizerRequired !== context.sanitizerRequirement.sanitizerRequired ||
      approval.policyRequired !== context.sanitizerRequirement.policyRequired ||
      approval.sanitizerRequirementReason !==
        context.sanitizerRequirement.sanitizerRequirementReason
    ) {
      throw new Error();
    }
  }
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
): CommandProviderRequestManifestV1 {
  return deepFreeze({
    requestVersion: 1,
    phase: context.phase,
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
    sanitizerRequirement: { ...context.sanitizerRequirement },
    approval: context.approval === null ? null : snapshotApprovalResponse(context.approval),
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

async function prepareCommandTransport(
  options: ValidatedCommandProviderOptions,
  approval: ApprovalResponse,
  signal?: AbortSignal,
  existingWorkingDirectory?: string,
  existingEnvironment?: ReadonlyArray<readonly [string, string]>,
): Promise<ApprovalResponse> {
  let temporaryRoot: string | undefined;
  let requestBytes: Buffer | undefined;
  try {
    assertActive(signal);
    assertApprovalActive(approval);
    let workingDirectory = existingWorkingDirectory;
    if (workingDirectory === undefined) {
      temporaryRoot = await mkdtemp(path.join(tmpdir(), "svbench-command-transport-"));
      await chmod(temporaryRoot, DIRECTORY_MODE);
      await assertPrivateDirectory(temporaryRoot);
      workingDirectory = path.join(temporaryRoot, "work");
      await mkdir(workingDirectory, { mode: DIRECTORY_MODE });
      await assertPrivateDirectory(workingDirectory);
    }
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
  if (value.responseVersion !== 1 || value.phase !== context.phase) throw new Error();
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
  assertSanitizerRequirement(sanitizerRequirement, context);
  const approval =
    value.approval === null ? null : snapshotApprovalResponse(requiredObject(value.approval));
  if (!approvalEqual(approval, context.approval)) throw new Error();
  if (!Object.hasOwn(value, "document")) throw new Error();
  const responded = requiredObject(value.responded);
  assertKeys(responded, ["model", "effort", "usage", "stopReason"]);
  const model = nullableSafeLabel(responded.model);
  const effort = nullableSafeLabel(responded.effort);
  const stopReason = nullableSafeLabel(responded.stopReason);
  const usage = snapshotUsage(responded.usage);
  return deepFreeze({
    responseVersion: 1,
    phase: context.phase,
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
    sanitizerRequirement: { ...context.sanitizerRequirement },
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
    approval.expiresAt !== undefined &&
    approval.expiresAt !== null &&
    Date.parse(approval.expiresAt) <= Date.now()
  ) {
    throw new Error();
  }
}

function assertSanitizerRequirement(
  value: Record<string, JsonValue>,
  context: ProviderAdapterContext,
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
    const expected = context.sanitizerRequirement[
      key as keyof ProviderAdapterContext["sanitizerRequirement"]
    ];
    if (value[key] !== expected) throw new Error();
  }
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
  if (
    approval.responseVersion !== 1 ||
    typeof approval.approved !== "boolean" ||
    !isSafeLabel(approval.gateId) ||
    approval.protocolVersion !== 1 ||
    !isDigest(approval.snapshotDigest) ||
    !isDigest(approval.runtimeBindingDigest) ||
    !isSafeLabel(approval.runtimeBindingIdentity) ||
    !isDigest(approval.approvedScopeDigest) ||
    !isSafeLabel(approval.approvedScopeIdentity) ||
    !isSafeLabel(approval.phase) ||
    !isSafeLabel(approval.requirementVerifierId) ||
    !isSafeLabel(approval.requirementVerifierVersion) ||
    !isNullableSafeLabel(approval.consumerSourceCommit) ||
    !isDigest(approval.requirementDecisionDigest) ||
    approval.sanitizerRequirementVersion !== 1 ||
    typeof approval.sanitizerRequired !== "boolean" ||
    typeof approval.policyRequired !== "boolean" ||
    !isSafeLabel(approval.sanitizerRequirementReason) ||
    !isOptionalDateTime(approval.checkedAt) ||
    !isOptionalDateTime(approval.expiresAt) ||
    (approval.reasonCode !== undefined && !isSafeLabel(approval.reasonCode))
  ) {
    throw new Error();
  }
  return deepFreeze({
    responseVersion: 1,
    approved: approval.approved,
    gateId: approval.gateId,
    protocolVersion: 1,
    snapshotDigest: approval.snapshotDigest,
    runtimeBindingDigest: approval.runtimeBindingDigest,
    runtimeBindingIdentity: approval.runtimeBindingIdentity,
    approvedScopeDigest: approval.approvedScopeDigest,
    approvedScopeIdentity: approval.approvedScopeIdentity,
    phase: approval.phase,
    requirementVerifierId: approval.requirementVerifierId,
    requirementVerifierVersion: approval.requirementVerifierVersion,
    consumerSourceCommit: approval.consumerSourceCommit,
    requirementDecisionDigest: approval.requirementDecisionDigest,
    sanitizerRequirementVersion: 1,
    sanitizerRequired: approval.sanitizerRequired,
    policyRequired: approval.policyRequired,
    sanitizerRequirementReason: approval.sanitizerRequirementReason,
    ...(approval.checkedAt === undefined ? {} : { checkedAt: approval.checkedAt }),
    ...(approval.expiresAt === undefined ? {} : { expiresAt: approval.expiresAt }),
    ...(approval.reasonCode === undefined ? {} : { reasonCode: approval.reasonCode }),
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
  assertKeys(usage, ["available"], ["inputTokens", "outputTokens", "totalTokens"]);
  if (typeof usage.available !== "boolean") throw new Error();
  if (!usage.available) {
    if (Object.keys(usage).length !== 1) throw new Error();
    return { available: false };
  }
  const result: ProviderUsage = { available: true };
  for (const key of ["inputTokens", "outputTokens", "totalTokens"] as const) {
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

function isNullableSafeLabel(value: JsonValue | undefined): value is string | null {
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
