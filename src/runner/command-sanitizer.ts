import { spawn } from "node:child_process";
import { chmod, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  decodeUtf8Strict,
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import { RunnerError } from "./errors.js";
import { computeCaseInputIdentity, computePolicyBindingDigest } from "./identity.js";
import type {
  JsonRecord,
  ProviderUsage,
  Sanitizer,
  SanitizerFinding,
  SanitizerRequest,
  SanitizerResponse,
} from "./types.js";

export const DEFAULT_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024;
export const MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024;
export const MAX_COMMAND_SANITIZER_REQUEST_BYTES = 16 * 1024 * 1024;

const DIRECTORY_MODE = 0o700;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const CASE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u;
const JSON_POINTER_PATTERN = /^(?:\/(?:[^~/]|~[01])*)*$/u;
const ABORT_SETTLING_COMMAND_SANITIZERS = new WeakSet<object>();

export type CommandSanitizerOptions = {
  executable: string;
  argv?: string[];
  envAllowlist?: string[];
  outputLimitBytes?: number;
  sanitizerId: string;
};

export type CommandSanitizerRequestV1 = {
  requestVersion: 1;
  caseInputIdentity: SanitizerRequest["caseInputIdentity"];
  documentKind: string;
  policyEnvelope: JsonRecord;
  policyVersion: number;
  policyDigest: string;
  policyBindingDigest: string;
  document: JsonValue;
  provider: SanitizerRequest["provider"];
  provenance: SanitizerRequest["provenance"];
};

export type CommandSanitizerResponseV1 = SanitizerResponse & {
  responseVersion: 1;
};

type ValidatedCommandSanitizerOptions = Readonly<{
  executable: string;
  argv: readonly string[];
  environment: ReadonlyArray<readonly [string, string]>;
  outputLimitBytes: number;
  sanitizerId: string;
}>;

type ValidatedAbortSignal = Readonly<{
  isAborted: () => boolean;
  addAbortListener: (listener: () => void) => void;
  removeAbortListener: (listener: () => void) => void;
}>;

/** Creates a shell-free sanitizer backed by a consumer-owned local process. */
export function createCommandSanitizer(options: CommandSanitizerOptions): Sanitizer {
  const validated = validateOptions(options);
  const sanitizer = Object.freeze({
    id: validated.sanitizerId,
    protocolVersion: 1 as const,
    async sanitize(request: SanitizerRequest, signal?: AbortSignal): Promise<SanitizerResponse> {
      try {
        const validatedSignal = validateAbortSignal(signal);
        assertActive(validatedSignal);
        const snapshot = snapshotRequest(request);
        return await invokeCommandSanitizer(validated, snapshot, validatedSignal);
      } catch {
        throw new Error("sanitizer command failed");
      }
    },
  });
  ABORT_SETTLING_COMMAND_SANITIZERS.add(sanitizer);
  return sanitizer;
}

function validateAbortSignal(signal: AbortSignal | undefined): ValidatedAbortSignal | undefined {
  if (signal === undefined) return undefined;
  const abortedGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
  if (abortedGetter === undefined) throw new Error();
  abortedGetter.call(signal);
  return Object.freeze({
    isAborted: () => abortedGetter.call(signal) as boolean,
    addAbortListener: (listener: () => void) => {
      EventTarget.prototype.addEventListener.call(signal, "abort", listener, { once: true });
    },
    removeAbortListener: (listener: () => void) => {
      EventTarget.prototype.removeEventListener.call(signal, "abort", listener);
    },
  });
}

/** @internal Read-only lifecycle capability check; registration is module-private. */
export function isAbortSettlingCommandSanitizer(value: object): boolean {
  return ABORT_SETTLING_COMMAND_SANITIZERS.has(value);
}

function validateOptions(options: CommandSanitizerOptions): ValidatedCommandSanitizerOptions {
  try {
    const value: unknown = options;
    if (value === null || typeof value !== "object") throw new Error();
    const candidate = value as Partial<CommandSanitizerOptions>;
    const executable = candidate.executable;
    const sourceArgv = candidate.argv ?? [];
    const sourceEnvAllowlist = candidate.envAllowlist ?? [];
    const outputLimitBytes =
      candidate.outputLimitBytes ?? DEFAULT_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES;
    const sanitizerId = candidate.sanitizerId;
    if (!Array.isArray(sourceArgv) || !Array.isArray(sourceEnvAllowlist)) throw new Error();
    const argvLength = sourceArgv.length;
    const envAllowlistLength = sourceEnvAllowlist.length;
    if (argvLength > 64 || envAllowlistLength > 64) throw new Error();

    const argv: string[] = [];
    for (let index = 0; index < argvLength; index += 1) {
      const argument: unknown = sourceArgv[index];
      if (typeof argument !== "string" || argument.length > 240) throw new Error();
      argv.push(argument);
    }

    const environment: Array<readonly [string, string]> = [];
    const normalizedNames = new Set<string>();
    for (let index = 0; index < envAllowlistLength; index += 1) {
      const name: unknown = sourceEnvAllowlist[index];
      if (typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name)) {
        throw new Error();
      }
      const normalized = name.toUpperCase();
      if (normalizedNames.has(normalized)) throw new Error();
      normalizedNames.add(normalized);
      const environmentValue = process.env[name];
      if (environmentValue !== undefined) environment.push(Object.freeze([name, environmentValue]));
    }

    if (
      typeof executable !== "string" ||
      executable.length === 0 ||
      executable.length > 240 ||
      !path.isAbsolute(executable) ||
      !Number.isSafeInteger(outputLimitBytes) ||
      outputLimitBytes < 1 ||
      outputLimitBytes > MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES ||
      !isSafeLabel(sanitizerId)
    ) {
      throw new Error();
    }
    return Object.freeze({
      executable,
      argv: Object.freeze(argv),
      environment: Object.freeze(environment),
      outputLimitBytes,
      sanitizerId,
    });
  } catch {
    throw new RunnerError(
      "sanitizer_configuration_invalid",
      "command sanitizer configuration is invalid",
    );
  }
}

function snapshotRequest(source: SanitizerRequest): CommandSanitizerRequestV1 {
  const normalized = normalizeJsonValue(
    source,
    "command sanitizer request",
    MAX_COMMAND_SANITIZER_REQUEST_BYTES,
  );
  if (!isJsonObject(normalized)) throw new Error();
  assertKeys(normalized, [
    "caseInputIdentity",
    "documentKind",
    "policyEnvelope",
    "policy",
    "policyVersion",
    "policyDigest",
    "policyBindingDigest",
    "document",
    "provider",
    "provenance",
  ]);

  const identity = requiredObject(normalized.caseInputIdentity);
  assertKeys(identity, ["identityVersion", "caseId", "documentKind", "preparedImage", "digest"]);
  const preparedImage = requiredObject(identity.preparedImage);
  assertKeys(preparedImage, ["mediaType", "sha256"]);
  if (
    identity.identityVersion !== 1 ||
    !isCaseId(identity.caseId) ||
    !isSafeLabel(identity.documentKind) ||
    !isMediaType(preparedImage.mediaType) ||
    !isDigest(preparedImage.sha256) ||
    !isDigest(identity.digest) ||
    normalized.documentKind !== identity.documentKind
  ) {
    throw new Error();
  }
  const computedIdentity = computeCaseInputIdentity({
    caseId: identity.caseId,
    documentKind: identity.documentKind,
    preparedImage: {
      mediaType: preparedImage.mediaType,
      sha256: preparedImage.sha256,
    },
  });
  if (computedIdentity.digest !== identity.digest) throw new Error();

  const policyEnvelope = requiredObject(normalized.policyEnvelope);
  assertKeys(policyEnvelope, ["envelopeVersion", "target", "policyVersion", "policy"]);
  const target = requiredObject(policyEnvelope.target);
  assertKeys(target, [
    "identityVersion",
    "caseId",
    "documentKind",
    "preparedImage",
    "caseInputIdentityDigest",
  ]);
  const targetImage = requiredObject(target.preparedImage);
  assertKeys(targetImage, ["mediaType", "sha256"]);
  const policy = requiredObject(normalized.policy);
  if (
    policyEnvelope.envelopeVersion !== 1 ||
    target.identityVersion !== 1 ||
    target.caseId !== identity.caseId ||
    target.documentKind !== identity.documentKind ||
    targetImage.mediaType !== preparedImage.mediaType ||
    targetImage.sha256 !== preparedImage.sha256 ||
    target.caseInputIdentityDigest !== identity.digest ||
    !Number.isSafeInteger(normalized.policyVersion) ||
    typeof normalized.policyVersion !== "number" ||
    normalized.policyVersion < 1 ||
    policyEnvelope.policyVersion !== normalized.policyVersion ||
    !jsonEqual(policyEnvelope.policy, policy) ||
    !isDigest(normalized.policyDigest) ||
    !isDigest(normalized.policyBindingDigest) ||
    computePolicyBindingDigest({
      caseInputIdentityDigest: identity.digest,
      policyVersion: normalized.policyVersion,
      policyDigest: normalized.policyDigest,
    }) !== normalized.policyBindingDigest
  ) {
    throw new Error();
  }

  const provider = snapshotProvider(normalized.provider);
  const provenance = snapshotProvenance(normalized.provenance);
  return deepFreeze({
    requestVersion: 1,
    caseInputIdentity: {
      identityVersion: 1,
      caseId: identity.caseId,
      documentKind: identity.documentKind,
      preparedImage: {
        mediaType: preparedImage.mediaType,
        sha256: preparedImage.sha256,
      },
      digest: identity.digest,
    },
    documentKind: identity.documentKind,
    policyEnvelope,
    policyVersion: normalized.policyVersion,
    policyDigest: normalized.policyDigest,
    policyBindingDigest: normalized.policyBindingDigest,
    document: normalized.document!,
    provider,
    provenance,
  });
}

function snapshotProvider(value: JsonValue | undefined): SanitizerRequest["provider"] {
  const provider = requiredObject(value);
  assertKeys(provider, [
    "id",
    "route",
    "requested",
    "respondedModel",
    "effectiveEffort",
    "usage",
    "stopReason",
  ]);
  const requested = requiredObject(provider.requested);
  assertKeys(requested, ["model", "effort", "maxTokens"]);
  const usage = snapshotUsage(provider.usage);
  if (
    !isSafeLabel(provider.id) ||
    !isSafeLabel(provider.route) ||
    !isNullableSafeLabel(requested.model) ||
    !isNullableSafeLabel(requested.effort) ||
    (requested.maxTokens !== null &&
      (typeof requested.maxTokens !== "number" ||
        !Number.isSafeInteger(requested.maxTokens) ||
        requested.maxTokens < 1)) ||
    !isNullableSafeLabel(provider.respondedModel) ||
    !isNullableSafeLabel(provider.effectiveEffort) ||
    !isNullableSafeLabel(provider.stopReason)
  ) {
    throw new Error();
  }
  return {
    id: provider.id,
    route: provider.route,
    requested: {
      model: requested.model,
      effort: requested.effort,
      maxTokens: requested.maxTokens,
    },
    respondedModel: provider.respondedModel,
    effectiveEffort: provider.effectiveEffort,
    usage,
    stopReason: provider.stopReason,
  };
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
    const tokenCount = usage[key];
    if (tokenCount === undefined) continue;
    if (
      tokenCount !== null &&
      (typeof tokenCount !== "number" || !Number.isSafeInteger(tokenCount) || tokenCount < 0)
    ) {
      throw new Error();
    }
    result[key] = tokenCount;
  }
  return result;
}

function snapshotProvenance(value: JsonValue | undefined): SanitizerRequest["provenance"] {
  const provenance = requiredObject(value);
  assertKeys(provenance, [
    "harnessVersion",
    "harnessCommit",
    "promptVersion",
    "preprocessVersion",
    "sourceCommit",
  ]);
  if (
    !isSafeLabel(provenance.harnessVersion) ||
    !isNullableSafeLabel(provenance.harnessCommit) ||
    !isSafeLabel(provenance.promptVersion) ||
    !isSafeLabel(provenance.preprocessVersion) ||
    !isNullableSafeLabel(provenance.sourceCommit)
  ) {
    throw new Error();
  }
  return {
    harnessVersion: provenance.harnessVersion,
    harnessCommit: provenance.harnessCommit,
    promptVersion: provenance.promptVersion,
    preprocessVersion: provenance.preprocessVersion,
    sourceCommit: provenance.sourceCommit,
  };
}

async function invokeCommandSanitizer(
  options: ValidatedCommandSanitizerOptions,
  request: CommandSanitizerRequestV1,
  signal: ValidatedAbortSignal | undefined,
): Promise<SanitizerResponse> {
  assertActive(signal);
  let workingDirectory: string | undefined;
  let requestBytes: Buffer | undefined;
  let responseBytes: Buffer | undefined;
  try {
    requestBytes = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
    assertActive(signal);
    workingDirectory = await mkdtemp(path.join(tmpdir(), "svbench-command-sanitizer-"));
    await chmod(workingDirectory, DIRECTORY_MODE);
    await assertPrivateEmptyDirectory(workingDirectory);
    assertActive(signal);
    const environment = Object.create(null) as NodeJS.ProcessEnv;
    for (const [name, value] of options.environment) environment[name] = value;
    responseBytes = await runChildProcess(
      options,
      workingDirectory,
      environment,
      requestBytes,
      signal,
    );
    return parseResponse(responseBytes, options.sanitizerId, request);
  } finally {
    requestBytes?.fill(0);
    responseBytes?.fill(0);
    if (workingDirectory !== undefined) {
      await rm(workingDirectory, { recursive: true, force: true });
    }
  }
}

async function runChildProcess(
  options: ValidatedCommandSanitizerOptions,
  workingDirectory: string,
  environment: NodeJS.ProcessEnv,
  input: Buffer,
  signal: ValidatedAbortSignal | undefined,
): Promise<Buffer> {
  assertActive(signal);
  return await new Promise<Buffer>((resolve, reject) => {
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
    let failed = false;
    let termination: Promise<void> | undefined;
    const terminate = (): void => {
      if (failed) return;
      failed = true;
      termination = terminateProcessGroup(child).finally(() => {
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
      });
    };
    const abort = (): void => terminate();
    try {
      signal?.addAbortListener(abort);
    } catch {
      terminate();
    }
    child.once("error", terminate);
    child.stdin.once("error", terminate);
    child.stdout.on("data", (chunk: Buffer) => {
      try {
        outputBytes += chunk.byteLength;
        if (outputBytes > options.outputLimitBytes) {
          terminate();
          return;
        }
        stdout.push(Buffer.from(chunk));
      } finally {
        Buffer.prototype.fill.call(chunk, 0);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      try {
        outputBytes += chunk.byteLength;
        if (outputBytes > options.outputLimitBytes) terminate();
      } finally {
        Buffer.prototype.fill.call(chunk, 0);
      }
    });
    child.once("close", (code, childSignal) => {
      void (async () => {
        signal?.removeAbortListener(abort);
        await termination;
        if (failed || code !== 0 || childSignal !== null) {
          for (const chunk of stdout) chunk.fill(0);
          reject(new Error());
          return;
        }
        const output = Buffer.concat(stdout);
        for (const chunk of stdout) chunk.fill(0);
        resolve(output);
      })();
    });
    child.stdin.end(input);
    if (signal?.isAborted()) abort();
  });
}

async function terminateProcessGroup(child: ReturnType<typeof spawn>): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
    return;
  }
  const systemRoot = process.env.SystemRoot;
  if (systemRoot === undefined || !path.isAbsolute(systemRoot)) {
    child.kill("SIGKILL");
    return;
  }
  const killed = await new Promise<boolean>((resolve) => {
    let killer;
    try {
      killer = spawn(
        path.join(systemRoot, "System32", "taskkill.exe"),
        ["/pid", String(pid), "/t", "/f"],
        {
          env: Object.create(null) as NodeJS.ProcessEnv,
          shell: false,
          stdio: "ignore",
        },
      );
    } catch {
      resolve(false);
      return;
    }
    killer.once("error", () => resolve(false));
    killer.once("close", (code, killerSignal) =>
      resolve(code === 0 && killerSignal === null),
    );
  });
  if (!killed) child.kill("SIGKILL");
}

function parseResponse(
  bytes: Buffer,
  sanitizerId: string,
  request: CommandSanitizerRequestV1,
): SanitizerResponse {
  const parsed = parseJson(
    decodeUtf8Strict(bytes, "command sanitizer response"),
    "command sanitizer response",
  );
  const response = requiredObject(parsed);
  assertKeys(
    response,
    [
      "responseVersion",
      "sanitizedDocument",
      "sanitizerId",
      "protocolVersion",
      "policyVersion",
      "policyDigest",
      "caseInputIdentityVersion",
      "caseInputIdentityDigest",
      "policyTargetIdentityDigest",
      "policyBindingDigest",
    ],
    ["findings"],
  );
  if (
    response.responseVersion !== 1 ||
    response.sanitizerId !== sanitizerId ||
    response.protocolVersion !== 1 ||
    typeof response.policyVersion !== "number" ||
    !Number.isSafeInteger(response.policyVersion) ||
    response.policyVersion < 1 ||
    response.policyVersion !== request.policyVersion ||
    response.policyDigest !== request.policyDigest ||
    response.caseInputIdentityVersion !== 1 ||
    response.caseInputIdentityDigest !== request.caseInputIdentity.digest ||
    response.policyTargetIdentityDigest !== request.caseInputIdentity.digest ||
    response.policyBindingDigest !== request.policyBindingDigest
  ) {
    throw new Error();
  }
  const findings = snapshotFindings(response.findings);
  return deepFreeze({
    sanitizedDocument: response.sanitizedDocument!,
    sanitizerId: response.sanitizerId,
    protocolVersion: 1,
    policyVersion: response.policyVersion,
    policyDigest: response.policyDigest,
    caseInputIdentityVersion: 1,
    caseInputIdentityDigest: response.caseInputIdentityDigest,
    policyTargetIdentityDigest: response.policyTargetIdentityDigest,
    policyBindingDigest: response.policyBindingDigest,
    ...(findings === undefined ? {} : { findings }),
  });
}

function snapshotFindings(value: JsonValue | undefined): SanitizerFinding[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 100) throw new Error();
  return value.map((item) => {
    const finding = requiredObject(item);
    assertKeys(finding, ["code", "severity", "classification", "hardGate"], ["path"]);
    if (
      !isSafeLabel(finding.code) ||
      (finding.severity !== "info" &&
        finding.severity !== "warning" &&
        finding.severity !== "error") ||
      !isSafeLabel(finding.classification) ||
      typeof finding.hardGate !== "boolean" ||
      (finding.path !== undefined &&
        finding.path !== null &&
        (typeof finding.path !== "string" ||
          finding.path.length > 1024 ||
          !JSON_POINTER_PATTERN.test(finding.path)))
    ) {
      throw new Error();
    }
    return {
      code: finding.code,
      severity: finding.severity,
      classification: finding.classification,
      hardGate: finding.hardGate,
      ...(finding.path === undefined ? {} : { path: finding.path }),
    };
  });
}

async function assertPrivateEmptyDirectory(directory: string): Promise<void> {
  const metadata = await stat(directory);
  if (!metadata.isDirectory()) throw new Error();
  if (process.platform !== "win32" && (metadata.mode & 0o777) !== DIRECTORY_MODE) {
    throw new Error();
  }
  if ((await readdir(directory)).length !== 0) throw new Error();
}

function assertActive(signal: ValidatedAbortSignal | undefined): void {
  if (signal?.isAborted()) throw new Error();
}

function requiredObject(value: JsonValue | undefined): Record<string, JsonValue> {
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

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL_PATTERN.test(value);
}

function isNullableSafeLabel(value: unknown): value is string | null {
  return value === null || isSafeLabel(value);
}

function isCaseId(value: unknown): value is string {
  return typeof value === "string" && CASE_ID_PATTERN.test(value);
}

function isMediaType(value: unknown): value is string {
  return typeof value === "string" && MEDIA_TYPE_PATTERN.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function jsonEqual(left: JsonValue | undefined, right: JsonValue): boolean {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => jsonEqual(item, right[index]!))
    );
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && jsonEqual(left[key], right[key]!))
  );
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
