import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { Readable, Writable } from "node:stream";

import {
  decodeUtf8Strict,
  normalizeJsonValue,
  parseJson,
  stringifyJsonValue,
  type JsonValue,
} from "../bundle/json.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../bundle/validate-bundle.js";
import {
  abortController,
  abortControllerSignal,
  addAbortSignalListener,
  createAbortController,
  isAbortSignalAborted,
  removeAbortSignalListener,
} from "./abort-signal-intrinsics.js";
import {
  CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
  runCodexAppServerProtocol,
  type CodexAppServerProtocolConnection,
  type CodexAppServerProtocolReceivedMessage,
  type CodexAppServerProtocolResult,
} from "./codex-app-server.js";
import {
  createIntrinsicPromise,
  ignoreIntrinsicPromiseRejection,
  invokeIntrinsicPromiseCallback,
  invokeIntrinsicSynchronousCallback,
  raceIntrinsicPromises,
  resolveIntrinsicPromise,
  restoreIntrinsicPromiseConstructor,
  thenIntrinsicPromise,
} from "./promise-intrinsics.js";
import type { RequestedExecutionSettings } from "../runner/types.js";

export const CODEX_APP_SERVER_TOOL_PROFILE_VERSION = "codex-no-host-tools-v1";
export const DEFAULT_CODEX_APP_SERVER_TIMEOUT_MS = 120_000;
export const DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES = 384 * 1024 * 1024;

const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const HOST_PLATFORM = process.platform;
const SPAWN_DETACHED = HOST_PLATFORM !== "win32";
const applyIntrinsic = Reflect.apply;
const arrayIsArrayIntrinsic = Array.isArray;
const bindIntrinsic = Function.prototype.bind;
const bufferAllocIntrinsic = Buffer.alloc;
const bufferAllocUnsafeIntrinsic = Buffer.allocUnsafe;
const bufferByteLengthIntrinsic = Buffer.byteLength;
const bufferFromIntrinsic = Buffer.from;
const bufferIsBufferIntrinsic = Buffer.isBuffer;
const chmodIntrinsic = chmod;
const clearTimeoutIntrinsic = clearTimeout;
const createHashIntrinsic = createHash;
const dateNowIntrinsic = Date.now;
const definePropertyIntrinsic = Object.defineProperty;
const freezeIntrinsic = Object.freeze;
const functionHasInstanceIntrinsic = Function.prototype[Symbol.hasInstance];
const getOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const mkdirIntrinsic = mkdir;
const mkdtempIntrinsic = mkdtemp;
const mathMaxIntrinsic = Math.max;
const mathMinIntrinsic = Math.min;
const numberIsSafeIntegerIntrinsic = Number.isSafeInteger;
const objectCreateIntrinsic = Object.create;
const objectKeysIntrinsic = Object.keys;
const objectValuesIntrinsic = Object.values;
const eventEmitterOnIntrinsic = EventEmitter.prototype.on;
const eventEmitterOnceIntrinsic = EventEmitter.prototype.once;
const eventEmitterEmitIntrinsic = EventEmitter.prototype.emit;
const eventEmitterAddListenerIntrinsic = EventEmitter.prototype.addListener;
const eventEmitterRemoveListenerIntrinsic = EventEmitter.prototype.removeListener;
const eventEmitterOnDescriptor = getOwnPropertyDescriptorIntrinsic(EventEmitter.prototype, "on")!;
const eventEmitterOnceDescriptor = getOwnPropertyDescriptorIntrinsic(
  EventEmitter.prototype,
  "once",
)!;
const eventEmitterEmitDescriptor = getOwnPropertyDescriptorIntrinsic(
  EventEmitter.prototype,
  "emit",
)!;
const eventEmitterAddListenerDescriptor = getOwnPropertyDescriptorIntrinsic(
  EventEmitter.prototype,
  "addListener",
)!;
const eventEmitterRemoveListenerDescriptor = getOwnPropertyDescriptorIntrinsic(
  EventEmitter.prototype,
  "removeListener",
)!;
const hashPrototypeIntrinsic = Object.getPrototypeOf(createHashIntrinsic("sha256")) as {
  update: (...arguments_: unknown[]) => unknown;
  digest: (...arguments_: unknown[]) => unknown;
};
const hashUpdateIntrinsic = hashPrototypeIntrinsic.update;
const hashDigestIntrinsic = hashPrototypeIntrinsic.digest;
const pathDirnameIntrinsic = path.dirname;
const pathIsAbsoluteIntrinsic = path.isAbsolute;
const pathJoinIntrinsic = path.join;
const processKillIntrinsic = applyIntrinsic(bindIntrinsic, process.kill, [
  process,
]) as typeof process.kill;
const readFileIntrinsic = readFile;
const readdirIntrinsic = readdir;
const realpathIntrinsic = realpath;
const rmIntrinsic = rm;
const setTimeoutIntrinsic = setTimeout;
const spawnIntrinsic = spawn;
const readableAsyncIteratorIntrinsic = Readable.prototype[Symbol.asyncIterator];
const readableDestroyIntrinsic = Readable.prototype.destroy;
const writableDestroyIntrinsic = Writable.prototype.destroy;
const writableEndIntrinsic = Writable.prototype.end;
const writableWriteIntrinsic = Writable.prototype.write;
const writeFileIntrinsic = writeFile;
const uint8ArrayFillIntrinsic = Uint8Array.prototype.fill;
const uint8ArrayIndexOfIntrinsic = Uint8Array.prototype.indexOf;
const uint8ArraySetIntrinsic = Uint8Array.prototype.set;
const uint8ArraySubarrayIntrinsic = Uint8Array.prototype.subarray;
const Uint8ArrayIntrinsic = Uint8Array;
const typedArrayPrototypeIntrinsic = Object.getPrototypeOf(Uint8ArrayIntrinsic.prototype);
const typedArrayByteLengthGetterIntrinsic = getOwnPropertyDescriptorIntrinsic(
  typedArrayPrototypeIntrinsic,
  "byteLength",
)!.get!;
const MAX_STDERR_BYTES = 1024 * 1024;
export const MAX_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES = 512 * 1024 * 1024;
const PRIVATE_TEMP_PARENT = "/tmp";
const MAX_ARGUMENTS = 8;
const MAX_ARGUMENT_BYTES = 4096;
const PROCESS_GROUP_SETTLE_TIMEOUT_MS = 2_000;
const PROCESS_GROUP_SETTLE_INTERVAL_MS = 10;
const MAX_JSONL_LINE_BYTES = CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES + 1024 * 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const RESERVED_ENVIRONMENT_NAMES = freezeIntrinsic([
  "APPDATA",
  "CODEX_HOME",
  "HOME",
  "LOCALAPPDATA",
  "PATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
]);
const DISABLED_FEATURES = freezeIntrinsic([
  "apps",
  "code_mode",
  "code_mode_host",
  "hooks",
  "image_generation",
  "in_app_browser",
  "multi_agent",
  "multi_agent_v2",
  "plugins",
  "remote_plugin",
  "shell_snapshot",
  "shell_tool",
  "skill_search",
  "tool_call_mcp_elicitation",
  "unbounded_connection_retries",
  "unified_exec",
  "view_image",
]);
const REASONING_EFFORTS = freezeIntrinsic([
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
  "ultra",
]);

export type CodexAppServerLazyInput = Readonly<{
  sha256: string;
  readBytes(): Promise<Uint8Array>;
}>;

export type CodexAppServerProcessRequest = Readonly<{
  image: CodexAppServerLazyInput & Readonly<{ mediaType: string }>;
  schema: CodexAppServerLazyInput;
  system: CodexAppServerLazyInput;
  instruction: CodexAppServerLazyInput;
  requested: RequestedExecutionSettings;
}>;

export type CodexAppServerProcessOptions = Readonly<{
  executable: string;
  executableArguments?: readonly string[];
  envAllowlist?: readonly string[];
  codexHome?: string;
  timeoutMs?: number;
  outputLimitBytes?: number;
}>;

export type CodexAppServerProcessStartAuthorization = Readonly<{
  allowedEnvironment: readonly (readonly [string, string])[];
  finalize(): undefined;
}>;

export type CodexAppServerProcessStartGuard = (
  signal: AbortSignal,
) => Promise<CodexAppServerProcessStartAuthorization>;

export type LinuxProcessTable = Readonly<{
  listProcessIds(): Promise<readonly string[]>;
  readProcessStat(processId: string): Promise<string>;
}>;

type ValidatedOptions = Readonly<{
  executable: string;
  executableArguments: readonly string[];
  envAllowlist: readonly string[];
  codexHome: string | null;
  timeoutMs: number;
  outputLimitBytes: number;
}>;

type RequestSnapshot = Readonly<{
  image: CodexAppServerLazyInput & Readonly<{ mediaType: string }>;
  schema: CodexAppServerLazyInput;
  system: CodexAppServerLazyInput;
  instruction: CodexAppServerLazyInput;
  requested: RequestedExecutionSettings & Readonly<{ model: string }>;
}>;

type PrivateWorkspace = Readonly<{
  root: string;
  workspace: string;
  catalog: string;
  environment: NodeJS.ProcessEnv;
}>;

/** Runs one pinned app-server process in a private, empty workspace. */
export async function runCodexAppServerProcess(
  optionsValue: CodexAppServerProcessOptions,
  requestValue: CodexAppServerProcessRequest,
  signal?: AbortSignal,
  startGuard?: CodexAppServerProcessStartGuard,
): Promise<CodexAppServerProtocolResult> {
  let workspace: PrivateWorkspace | undefined;
  const materialized: Buffer[] = [];
  try {
    const options = validateOptions(optionsValue);
    const request = snapshotRequest(requestValue);
    if (startGuard !== undefined && typeof startGuard !== "function") throw new Error();
    assertActive(signal);
    workspace = await createPrivateWorkspace(options.codexHome);
    const activeWorkspace = workspace;
    await writeFileIntrinsic(activeWorkspace.catalog, createToolCatalog(request.requested), {
      encoding: "utf8",
      flag: "wx",
      mode: FILE_MODE,
    });
    return await runConnectedProcess(
      options,
      activeWorkspace,
      async (processSignal) => {
        const image = await readInput(
          request.image,
          materialized,
          options.timeoutMs,
          processSignal,
        );
        const schemaBytes = await readInput(
          request.schema,
          materialized,
          options.timeoutMs,
          processSignal,
        );
        const systemBytes = await readInput(
          request.system,
          materialized,
          options.timeoutMs,
          processSignal,
        );
        const instructionBytes = await readInput(
          request.instruction,
          materialized,
          options.timeoutMs,
          processSignal,
        );
        const schema = normalizeJsonValue(
          parseJson(
            decodeUtf8Strict(schemaBytes, "codex app-server schema"),
            "codex app-server schema",
          ),
          "codex app-server schema",
          MAX_PROVIDER_INPUT_BYTES,
        );
        return {
          workspace: activeWorkspace.workspace,
          image: { mediaType: request.image.mediaType, bytes: image },
          schema,
          system: decodeUtf8Strict(systemBytes, "codex app-server system"),
          instruction: decodeUtf8Strict(
            instructionBytes,
            "codex app-server instruction",
          ),
          requested: request.requested,
        };
      },
      signal,
      startGuard,
    );
  } catch {
    throw new Error("codex app-server process failed");
  } finally {
    for (let index = 0; index < materialized.length; index += 1) {
      zeroReturnedBytes(materialized[index]!);
    }
    if (workspace !== undefined) {
      try {
        await rmIntrinsic(workspace.root, { force: true, recursive: true });
      } catch {
        throw new Error("codex app-server process failed");
      }
    }
  }
}

function validateOptions(value: CodexAppServerProcessOptions): ValidatedOptions {
  if (value === null || typeof value !== "object") throw new Error();
  // Node does not expose a Windows Job Object primitive. Refuse to start on a
  // platform where an exited leader would make complete tree reclamation
  // unverifiable; a taskkill-by-PID fallback is not a durable tree identity.
  if (HOST_PLATFORM !== "darwin" && HOST_PLATFORM !== "linux") throw new Error();
  const executable = value.executable;
  if (typeof executable !== "string" || !pathIsAbsoluteIntrinsic(executable)) throw new Error();
  const executableArguments = snapshotStrings(value.executableArguments ?? [], MAX_ARGUMENTS);
  const names = snapshotStrings(value.envAllowlist ?? [], 64);
  const codexHome = value.codexHome;
  if (
    codexHome !== undefined &&
    (typeof codexHome !== "string" ||
      !pathIsAbsoluteIntrinsic(codexHome) ||
      bufferByteLengthIntrinsic(codexHome, "utf8") > MAX_ARGUMENT_BYTES ||
      codexHome.includes("\0"))
  ) {
    throw new Error();
  }
  const seen: string[] = [];
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index]!;
    if (
      !ENVIRONMENT_NAME_PATTERN.test(name) ||
      stringArrayContains(RESERVED_ENVIRONMENT_NAMES, name) ||
      stringArrayContains(seen, name)
    ) {
      throw new Error();
    }
    seen[seen.length] = name;
  }
  const timeoutMs = value.timeoutMs ?? DEFAULT_CODEX_APP_SERVER_TIMEOUT_MS;
  const outputLimitBytes =
    value.outputLimitBytes ?? DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES;
  if (
    !numberIsSafeIntegerIntrinsic(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 15 * 60_000 ||
    !numberIsSafeIntegerIntrinsic(outputLimitBytes) ||
    outputLimitBytes < 1024 ||
    outputLimitBytes > MAX_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES
  ) {
    throw new Error();
  }
  return freezeIntrinsic({
    executable,
    executableArguments: freezeIntrinsic(executableArguments),
    envAllowlist: freezeIntrinsic(names),
    codexHome: codexHome ?? null,
    timeoutMs,
    outputLimitBytes,
  });
}

function snapshotStrings(value: readonly string[], limit: number): string[] {
  if (!arrayIsArrayIntrinsic(value) || value.length > limit) throw new Error();
  const output: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      bufferByteLengthIntrinsic(entry, "utf8") > MAX_ARGUMENT_BYTES ||
      entry.includes("\0")
    ) {
      throw new Error();
    }
    output[output.length] = entry;
  }
  return output;
}

function stringArrayContains(values: readonly string[], expected: string): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function snapshotRequest(value: CodexAppServerProcessRequest): RequestSnapshot {
  if (value === null || typeof value !== "object") throw new Error();
  const requested = value.requested;
  if (requested === null || typeof requested !== "object") throw new Error();
  const model = requested.model;
  const effort = requested.effort;
  if (
    typeof model !== "string" ||
    !SAFE_LABEL_PATTERN.test(model) ||
    (effort !== null && (typeof effort !== "string" || !SAFE_LABEL_PATTERN.test(effort))) ||
    requested.maxTokens !== null
  ) {
    throw new Error();
  }
  return freezeIntrinsic({
    image: snapshotInput(value.image, true),
    schema: snapshotInput(value.schema, false),
    system: snapshotInput(value.system, false),
    instruction: snapshotInput(value.instruction, false),
    requested: freezeIntrinsic({ model, effort, maxTokens: null }),
  });
}

function snapshotInput(
  value: CodexAppServerLazyInput & Partial<{ mediaType: string }>,
  image: boolean,
): CodexAppServerLazyInput & Readonly<{ mediaType: string }> {
  if (value === null || typeof value !== "object") throw new Error();
  const sha256 = value.sha256;
  const readBytes = value.readBytes;
  const mediaType = image ? value.mediaType : "application/octet-stream";
  if (
    typeof sha256 !== "string" ||
    !DIGEST_PATTERN.test(sha256) ||
    typeof readBytes !== "function" ||
    typeof mediaType !== "string" ||
    (image && !/^image\/[A-Za-z0-9.+-]{1,64}$/u.test(mediaType))
  ) {
    throw new Error();
  }
  return freezeIntrinsic({
    sha256,
    mediaType,
    readBytes: applyIntrinsic(bindIntrinsic, readBytes, [value]) as () => Promise<Uint8Array>,
  });
}

async function createPrivateWorkspace(codexHome: string | null): Promise<PrivateWorkspace> {
  const temporaryParent = await realpathIntrinsic(PRIVATE_TEMP_PARENT);
  if (!pathIsAbsoluteIntrinsic(temporaryParent)) throw new Error();
  const root = await mkdtempIntrinsic(pathJoinIntrinsic(temporaryParent, "svbench-codex-"));
  try {
    const canonicalRoot = await realpathIntrinsic(root);
    if (pathDirnameIntrinsic(canonicalRoot) !== temporaryParent) throw new Error();
    await chmodIntrinsic(root, DIRECTORY_MODE);
    const directories = {
      home: pathJoinIntrinsic(root, "home"),
      codexHome: pathJoinIntrinsic(root, "codex-home"),
      config: pathJoinIntrinsic(root, "config"),
      cache: pathJoinIntrinsic(root, "cache"),
      workspace: pathJoinIntrinsic(root, "workspace"),
      executablePath: pathJoinIntrinsic(root, "empty-path"),
      temporary: pathJoinIntrinsic(root, "tmp"),
    };
    const directoryValues = objectValuesIntrinsic(directories);
    for (let index = 0; index < directoryValues.length; index += 1) {
      await mkdirIntrinsic(directoryValues[index]!, { mode: DIRECTORY_MODE });
    }
    const environment = objectCreateIntrinsic(null) as NodeJS.ProcessEnv;
    environment.HOME = directories.home;
    environment.USERPROFILE = directories.home;
    environment.CODEX_HOME = codexHome ?? directories.codexHome;
    environment.XDG_CONFIG_HOME = directories.config;
    environment.XDG_CACHE_HOME = directories.cache;
    environment.APPDATA = directories.config;
    environment.LOCALAPPDATA = directories.cache;
    environment.PATH = directories.executablePath;
    environment.TMPDIR = directories.temporary;
    environment.TMP = directories.temporary;
    environment.TEMP = directories.temporary;
    return freezeIntrinsic({
      root,
      workspace: directories.workspace,
      catalog: pathJoinIntrinsic(root, "model-catalog.json"),
      environment,
    });
  } catch {
    try {
      await rmIntrinsic(root, { force: true, recursive: true });
    } catch {
      // Preserve the stable workspace-creation error below.
    }
    throw new Error();
  }
}

async function readInput(
  input: CodexAppServerLazyInput,
  materialized: Buffer[],
  timeoutMs: number,
  parentSignal: AbortSignal | undefined,
): Promise<Buffer> {
  const controller = createAbortController();
  const controllerSignal = abortControllerSignal(controller);
  const abort = (): void => abortController(controller);
  addAbortSignalListener(parentSignal, abort);
  const timer = setTimeoutIntrinsic(abort, timeoutMs);
  try {
    assertActive(parentSignal);
    const value = await invokeLazyInput(input.readBytes, controllerSignal);
    if (!isUint8Array(value)) throw new Error();
    try {
      if (typedArrayByteLength(value) > MAX_PROVIDER_INPUT_BYTES) throw new Error();
      const bytes = bufferFromIntrinsic(value);
      materialized[materialized.length] = bytes;
      if (sha256(bytes) !== input.sha256) {
        throw new Error();
      }
      return bytes;
    } finally {
      zeroReturnedBytes(value);
    }
  } finally {
    clearTimeoutIntrinsic(timer);
    removeAbortSignalListener(parentSignal, abort);
  }
}

function invokeLazyInput(
  reader: () => Promise<Uint8Array>,
  signal: AbortSignal,
): Promise<Uint8Array> {
  assertActive(signal);
  const pending = thenIntrinsicPromise(resolveIntrinsicPromise(undefined), () => {
    assertActive(signal);
    return invokeIntrinsicPromiseCallback<Uint8Array>(() => {
      try {
        return reader();
      } finally {
        restoreEventEmitterIntrinsics();
      }
    });
  });
  return createIntrinsicPromise((resolve, reject) => {
    let settled = false;
    const removeAbortListener = (): void => removeAbortSignalListener(signal, abort);
    const abort = (): void => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      reject(new Error());
    };
    addAbortSignalListener(signal, abort);
    void thenIntrinsicPromise(
      pending,
      (value) => {
        restoreEventEmitterIntrinsics();
        if (settled) {
          try {
            if (isUint8Array(value)) zeroReturnedBytes(value);
          } catch {
            // Disposal is best effort after the public process call has settled.
          }
          return;
        }
        settled = true;
        removeAbortListener();
        resolve(value);
      },
      (error: unknown) => {
        restoreEventEmitterIntrinsics();
        if (settled) return;
        settled = true;
        removeAbortListener();
        reject(error);
      },
    );
    if (isAbortSignalAborted(signal)) abort();
  });
}

function zeroReturnedBytes(value: Uint8Array): void {
  applyIntrinsic(uint8ArrayFillIntrinsic, value, [0]);
}

function isUint8Array(value: unknown): value is Uint8Array {
  return applyIntrinsic(functionHasInstanceIntrinsic, Uint8ArrayIntrinsic, [value]) as boolean;
}

function typedArrayByteLength(value: Uint8Array): number {
  return applyIntrinsic(typedArrayByteLengthGetterIntrinsic, value, []) as number;
}

function sha256(value: Uint8Array): string {
  const hash = createHashIntrinsic("sha256");
  applyIntrinsic(hashUpdateIntrinsic, hash, [value]);
  return applyIntrinsic(hashDigestIntrinsic, hash, ["hex"]) as string;
}

function createToolCatalog(requested: RequestedExecutionSettings & { model: string }): string {
  const efforts: string[] = [];
  for (let index = 0; index < REASONING_EFFORTS.length; index += 1) {
    efforts[efforts.length] = REASONING_EFFORTS[index]!;
  }
  if (
    requested.effort !== null &&
    !stringArrayContains(efforts, requested.effort)
  ) {
    efforts[efforts.length] = requested.effort;
  }
  const supportedReasoningLevels: Array<{ effort: string; description: string }> = [];
  for (let index = 0; index < efforts.length; index += 1) {
    supportedReasoningLevels[supportedReasoningLevels.length] = {
      effort: efforts[index]!,
      description: "fixed extraction effort",
    };
  }
  const defaultEffort = requested.effort ?? "medium";
  return `${stringifyJsonValue({
    models: [
      {
        slug: requested.model,
        base_instructions: "",
        display_name: requested.model,
        description: null,
        default_reasoning_level: defaultEffort,
        supported_reasoning_levels: supportedReasoningLevels,
        shell_type: "disabled",
        visibility: "list",
        supported_in_api: true,
        priority: 1,
        additional_speed_tiers: [],
        service_tiers: [],
        default_service_tier: null,
        availability_nux: null,
        upgrade: null,
        model_messages: null,
        include_skills_usage_instructions: false,
        include_plugin_usage_instructions: false,
        include_apps_usage_instructions: false,
        supports_reasoning_summary_parameter: true,
        default_reasoning_summary: "none",
        support_verbosity: false,
        default_verbosity: null,
        apply_patch_tool_type: null,
        web_search_tool_type: "text",
        truncation_policy: { mode: "bytes", limit: 10_000 },
        supports_image_detail_original: false,
        context_window: null,
        max_context_window: null,
        auto_compact_token_limit: null,
        comp_hash: null,
        effective_context_window_percent: 95,
        experimental_supported_tools: [],
        input_modalities: ["text", "image"],
        supports_search_tool: false,
        use_responses_lite: false,
        node_repl_auto_review_required: false,
        node_repl_disabled: true,
        auto_review_model_override: null,
        model_specialty: null,
        tool_mode: "direct",
        multi_agent_version: "disabled",
      },
    ],
  })}\n`;
}

function appServerArguments(
  options: ValidatedOptions,
  workspace: PrivateWorkspace,
): string[] {
  const arguments_: string[] = [];
  for (let index = 0; index < options.executableArguments.length; index += 1) {
    arguments_[arguments_.length] = options.executableArguments[index]!;
  }
  arguments_[arguments_.length] = "app-server";
  arguments_[arguments_.length] = "--stdio";
  arguments_[arguments_.length] = "--strict-config";
  for (let index = 0; index < DISABLED_FEATURES.length; index += 1) {
    arguments_[arguments_.length] = "--disable";
    arguments_[arguments_.length] = DISABLED_FEATURES[index]!;
  }
  const overrides = [
    `model_catalog_json=${stringifyJsonValue(workspace.catalog)}`,
    'personality="none"',
    "include_permissions_instructions=false",
    "include_environment_context=false",
    "include_collaboration_mode_instructions=false",
    "include_apps_instructions=false",
    "skills.include_instructions=false",
    "skills.bundled.enabled=false",
    "analytics.enabled=false",
    'web_search="disabled"',
    "tools.web_search=false",
    "tools.update_plan.enabled=false",
    "tools.experimental_request_user_input.enabled=false",
    "agents.enabled=false",
    "project_root_markers=[]",
    "project_doc_max_bytes=0",
    "mcp_servers={}",
    "hooks={}",
    "notify=[]",
  ];
  for (let index = 0; index < overrides.length; index += 1) {
    arguments_[arguments_.length] = "-c";
    arguments_[arguments_.length] = overrides[index]!;
  }
  return arguments_;
}

async function runConnectedProcess(
  options: ValidatedOptions,
  workspace: PrivateWorkspace,
  prepareRequest: (
    signal: AbortSignal,
  ) => Promise<Parameters<typeof runCodexAppServerProtocol>[1]>,
  parentSignal: AbortSignal | undefined,
  startGuard: CodexAppServerProcessStartGuard | undefined,
): Promise<CodexAppServerProtocolResult> {
  const controller = createAbortController();
  const controllerSignal = abortControllerSignal(controller);
  const guardController =
    startGuard === undefined ? undefined : createAbortController();
  const guardSignal =
    guardController === undefined ? undefined : abortControllerSignal(guardController);
  let abortRequested = false;
  const abort = (): void => {
    abortRequested = true;
    abortController(controller);
    abortController(guardController);
  };
  addAbortSignalListener(parentSignal, abort);
  const timer = setTimeoutIntrinsic(abort, options.timeoutMs);
  let child: ChildProcessWithoutNullStreams | undefined;
  let close: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
  let termination: Promise<void> | undefined;
  const terminate = (): Promise<void> => {
    if (child === undefined) return resolveIntrinsicPromise(undefined);
    if (termination === undefined) {
      termination = terminateProcessTree(child);
      destroyChildStreams(child);
    }
    return termination;
  };
  try {
    const arguments_ = appServerArguments(options, workspace);
    assertActive(parentSignal);
    let environment: NodeJS.ProcessEnv;
    if (startGuard === undefined) {
      environment = snapshotSpawnEnvironment(
        snapshotAllowedEnvironment(options.envAllowlist),
        workspace.environment,
      );
    } else {
      let authorizationValue: CodexAppServerProcessStartAuthorization;
      try {
        authorizationValue = await invokeIntrinsicPromiseCallback<
          CodexAppServerProcessStartAuthorization
        >(() => {
          try {
            return startGuard(guardSignal!);
          } finally {
            restoreEventEmitterIntrinsics();
          }
        });
      } finally {
        restoreEventEmitterIntrinsics();
      }
      const authorization = snapshotStartAuthorization(
        authorizationValue,
        options.envAllowlist,
      );
      environment = snapshotSpawnEnvironment(
        authorization.allowedEnvironment,
        workspace.environment,
      );
      let finalizerResult: unknown;
      try {
        finalizerResult = invokeIntrinsicSynchronousCallback(() => authorization.finalize());
      } finally {
        restoreIntrinsicPromiseConstructor();
        restoreEventEmitterIntrinsics();
      }
      if (finalizerResult !== undefined) {
        ignoreIntrinsicPromiseRejection(finalizerResult);
        throw new Error();
      }
      if (abortRequested) throw new Error();
    }
    restoreEventEmitterIntrinsics();
    child = spawnIntrinsic(options.executable, arguments_, {
      cwd: workspace.workspace,
      detached: SPAWN_DETACHED,
      env: environment,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    hardenEventEmitterInstance(child);
    hardenEventEmitterInstance(child.stdin);
    hardenEventEmitterInstance(child.stdout);
    hardenEventEmitterInstance(child.stderr);
    close = waitForClose(child);
    const processConnection = new JsonlProcessConnection(
      child,
      options.outputLimitBytes,
      close,
      terminate,
    );
    const request = await prepareRequest(controllerSignal);
    const result = await runCodexAppServerProtocol(
      processConnection,
      request,
      controllerSignal,
    );
    const status = await raceAbort(processConnection.waitForClose(), controllerSignal);
    await terminate();
    if (status.code !== 0 || status.signal !== null) throw new Error();
    return result;
  } catch {
    if (child !== undefined) {
      if (isAbortSignalAborted(controllerSignal)) {
        await waitForInterruptGrace(close);
      }
      if (close === undefined) {
        await terminate();
      } else {
        await awaitProcessCleanup(terminate, close);
      }
    }
    throw new Error();
  } finally {
    clearTimeoutIntrinsic(timer);
    removeAbortSignalListener(parentSignal, abort);
    if (child !== undefined) destroyChildStreams(child);
  }
}

class JsonlProcessConnection implements CodexAppServerProtocolConnection {
  private readonly iterator: AsyncIterator<Buffer | string>;
  private pending = bufferAllocIntrinsic(0);
  private pendingBytes = 0;
  private unread: Buffer | undefined;
  private outputBytes = 0;
  private stderrBytes = 0;
  private failed = false;
  private readonly close: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;

  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly outputLimitBytes: number,
    close: Promise<{ code: number | null; signal: NodeJS.Signals | null }>,
    private readonly terminate: () => Promise<void>,
  ) {
    this.iterator = applyIntrinsic(readableAsyncIteratorIntrinsic, child.stdout, []) as AsyncIterator<
      Buffer | string
    >;
    this.close = close;
    applyIntrinsic(eventEmitterOnceIntrinsic, child, ["error", () => this.fail()]);
    applyIntrinsic(eventEmitterOnceIntrinsic, child.stdin, ["error", () => this.fail()]);
    applyIntrinsic(eventEmitterOnIntrinsic, child.stderr, ["data", (chunk: Buffer | string) => {
      this.stderrBytes += bufferByteLengthIntrinsic(chunk);
      if (this.stderrBytes > MAX_STDERR_BYTES) this.fail();
    }]);
  }

  async send(message: JsonValue): Promise<void> {
    if (this.failed) throw new Error();
    const bytes = bufferFromIntrinsic(`${stringifyJsonValue(message)}\n`, "utf8");
    try {
      if (typedArrayByteLength(bytes) > this.outputLimitBytes) {
        this.fail();
        throw new Error();
      }
      await createIntrinsicPromise<void>((resolve, reject) => {
        applyIntrinsic(writableWriteIntrinsic, this.child.stdin, [bytes, (error: Error | null | undefined) => {
          if (error === null || error === undefined) resolve();
          else reject(error);
        }]);
      });
    } finally {
      zeroReturnedBytes(bytes);
    }
  }

  async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    for (;;) {
      if (this.failed) throw new Error();
      let chunk = this.unread;
      this.unread = undefined;
      if (chunk === undefined) {
        const next = await this.iterator.next();
        if (next.done) {
          if (this.pendingBytes !== 0) throw new Error();
          return undefined;
        }
        chunk = bufferIsBufferIntrinsic(next.value)
          ? next.value
          : bufferFromIntrinsic(next.value);
        this.outputBytes += typedArrayByteLength(chunk);
        if (this.outputBytes > this.outputLimitBytes) {
          this.fail();
          throw new Error();
        }
      }

      const newline = applyIntrinsic(uint8ArrayIndexOfIntrinsic, chunk, [0x0a]) as number;
      if (newline === -1) {
        this.appendPending(chunk);
        continue;
      }
      this.appendPending(
        applyIntrinsic(uint8ArraySubarrayIntrinsic, chunk, [0, newline]) as Buffer,
      );
      if (newline + 1 < typedArrayByteLength(chunk)) {
        this.unread = applyIntrinsic(uint8ArraySubarrayIntrinsic, chunk, [
          newline + 1,
        ]) as Buffer;
      }
      if (this.pendingBytes === 0 || this.pending[this.pendingBytes - 1] === 0x0d) {
        throw new Error();
      }
      try {
        const line = applyIntrinsic(uint8ArraySubarrayIntrinsic, this.pending, [
          0,
          this.pendingBytes,
        ]) as Buffer;
        return {
          message: normalizeJsonValue(
            parseJson(
              decodeUtf8Strict(line, "codex app-server message"),
              "codex app-server message",
            ),
            "codex app-server message",
            MAX_JSONL_LINE_BYTES,
          ),
          byteLength: this.pendingBytes + 1,
        };
      } finally {
        applyIntrinsic(uint8ArrayFillIntrinsic, this.pending, [0, 0, this.pendingBytes]);
        this.pendingBytes = 0;
      }
    }
  }

  private appendPending(chunk: Buffer): void {
    const chunkByteLength = typedArrayByteLength(chunk);
    if (chunkByteLength === 0) return;
    const required = this.pendingBytes + chunkByteLength;
    if (required > MAX_JSONL_LINE_BYTES) {
      this.fail();
      throw new Error();
    }
    const pendingByteLength = typedArrayByteLength(this.pending);
    if (required > pendingByteLength) {
      let capacity = mathMaxIntrinsic(4096, pendingByteLength);
      while (capacity < required) {
        capacity = mathMinIntrinsic(MAX_JSONL_LINE_BYTES, capacity * 2);
      }
      const grown = bufferAllocUnsafeIntrinsic(capacity);
      applyIntrinsic(uint8ArraySetIntrinsic, grown, [
        applyIntrinsic(uint8ArraySubarrayIntrinsic, this.pending, [
          0,
          this.pendingBytes,
        ]),
        0,
      ]);
      zeroReturnedBytes(this.pending);
      this.pending = grown;
    }
    applyIntrinsic(uint8ArraySetIntrinsic, this.pending, [chunk, this.pendingBytes]);
    this.pendingBytes = required;
  }

  closeInput(): void {
    applyIntrinsic(writableEndIntrinsic, this.child.stdin, []);
  }

  async waitForClose(): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
    const status = await this.close;
    if (this.failed) throw new Error();
    return status;
  }

  private fail(): void {
    if (this.failed) return;
    this.failed = true;
    void this.terminate();
  }
}

function waitForClose(
  child: ChildProcessWithoutNullStreams,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return createIntrinsicPromise((resolve) => {
    applyIntrinsic(eventEmitterOnceIntrinsic, child, [
      "close",
      (code: number | null, childSignal: NodeJS.Signals | null) =>
        resolve({ code, signal: childSignal }),
    ]);
  });
}

function restoreEventEmitterIntrinsics(): void {
  definePropertyIntrinsic(EventEmitter.prototype, "on", eventEmitterOnDescriptor);
  definePropertyIntrinsic(EventEmitter.prototype, "once", eventEmitterOnceDescriptor);
  definePropertyIntrinsic(EventEmitter.prototype, "emit", eventEmitterEmitDescriptor);
  definePropertyIntrinsic(
    EventEmitter.prototype,
    "addListener",
    eventEmitterAddListenerDescriptor,
  );
  definePropertyIntrinsic(
    EventEmitter.prototype,
    "removeListener",
    eventEmitterRemoveListenerDescriptor,
  );
}

function hardenEventEmitterInstance(value: EventEmitter): void {
  definePropertyIntrinsic(value, "on", fixedMethod(eventEmitterOnIntrinsic));
  definePropertyIntrinsic(value, "once", fixedMethod(eventEmitterOnceIntrinsic));
  definePropertyIntrinsic(value, "emit", fixedMethod(eventEmitterEmitIntrinsic));
  definePropertyIntrinsic(value, "addListener", fixedMethod(eventEmitterAddListenerIntrinsic));
  definePropertyIntrinsic(
    value,
    "removeListener",
    fixedMethod(eventEmitterRemoveListenerIntrinsic),
  );
}

function fixedMethod(value: unknown): PropertyDescriptor {
  return { configurable: false, enumerable: false, value, writable: false };
}

async function terminateProcessTree(child: ChildProcessWithoutNullStreams): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  try {
    processKillIntrinsic(-pid, "SIGKILL");
  } catch (error) {
    if (objectWithCode(error).code !== "ESRCH") throw error;
  }
  await waitForProcessGroupSettlement(pid);
}

function snapshotSpawnEnvironment(
  allowed: readonly (readonly [string, string])[],
  privateEnvironment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const environment = objectCreateIntrinsic(null) as NodeJS.ProcessEnv;
  for (let index = 0; index < allowed.length; index += 1) {
    const entry = allowed[index]!;
    environment[entry[0]] = entry[1];
  }
  const privateNames = objectKeysIntrinsic(privateEnvironment);
  for (let index = 0; index < privateNames.length; index += 1) {
    const name = privateNames[index]!;
    const value = privateEnvironment[name];
    if (value !== undefined) environment[name] = value;
  }
  return environment;
}

function snapshotAllowedEnvironment(
  allowlist: readonly string[],
): readonly (readonly [string, string])[] {
  const allowed: Array<readonly [string, string]> = [];
  for (let index = 0; index < allowlist.length; index += 1) {
    const name = allowlist[index]!;
    const value = process.env[name];
    if (value !== undefined) {
      allowed[allowed.length] = freezeIntrinsic([name, value]);
    }
  }
  return freezeIntrinsic(allowed);
}

function snapshotStartAuthorization(
  value: CodexAppServerProcessStartAuthorization,
  allowlist: readonly string[],
): CodexAppServerProcessStartAuthorization {
  if (value === null || typeof value !== "object") throw new Error();
  const finalize = value.finalize;
  const source = value.allowedEnvironment;
  if (typeof finalize !== "function" || !arrayIsArrayIntrinsic(source)) throw new Error();
  const seen: string[] = [];
  const allowed: Array<readonly [string, string]> = [];
  for (let index = 0; index < source.length; index += 1) {
    const entry = source[index];
    if (!arrayIsArrayIntrinsic(entry)) throw new Error();
    const length = entry.length;
    const name = entry[0];
    const environmentValue = entry[1];
    if (
      length !== 2 ||
      typeof name !== "string" ||
      typeof environmentValue !== "string" ||
      !stringArrayContains(allowlist, name) ||
      stringArrayContains(seen, name)
    ) {
      throw new Error();
    }
    seen[seen.length] = name;
    allowed[allowed.length] = freezeIntrinsic([name, environmentValue]);
  }
  return freezeIntrinsic({
    allowedEnvironment: freezeIntrinsic(allowed),
    finalize: applyIntrinsic(bindIntrinsic, finalize, [undefined]),
  });
}

async function waitForProcessGroupSettlement(processGroupId: number): Promise<void> {
  const deadline = dateNowIntrinsic() + PROCESS_GROUP_SETTLE_TIMEOUT_MS;
  while (await processGroupHasLiveMember(processGroupId)) {
    if (dateNowIntrinsic() >= deadline) throw new Error();
    await createIntrinsicPromise<void>((resolve) => {
      setTimeoutIntrinsic(resolve, PROCESS_GROUP_SETTLE_INTERVAL_MS);
    });
  }
}

async function processGroupHasLiveMember(processGroupId: number): Promise<boolean> {
  try {
    processKillIntrinsic(-processGroupId, 0);
  } catch (error) {
    return processGroupProbeFailureIndicatesLive(error);
  }
  if (HOST_PLATFORM !== "linux") return true;
  return linuxProcessGroupHasLiveMember(processGroupId);
}

/** @internal Classifies the POSIX signal-zero process-group probe without weakening cleanup. */
export function processGroupProbeFailureIndicatesLive(error: unknown): boolean {
  const code = objectWithCode(error).code;
  if (code === "ESRCH") return false;
  if (code === "EPERM") return true;
  throw error;
}

const DEFAULT_LINUX_PROCESS_TABLE: LinuxProcessTable = freezeIntrinsic({
  async listProcessIds(): Promise<readonly string[]> {
    const processIds: string[] = [];
    const entries = await readdirIntrinsic("/proc", { withFileTypes: true });
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index]!;
      if (entry.isDirectory() && /^[1-9][0-9]*$/u.test(entry.name)) {
        processIds[processIds.length] = entry.name;
      }
    }
    return processIds;
  },
  async readProcessStat(processId: string): Promise<string> {
    return readFileIntrinsic(`/proc/${processId}/stat`, "utf8");
  },
});

export async function linuxProcessGroupHasLiveMember(
  processGroupId: number,
  processTable: LinuxProcessTable = DEFAULT_LINUX_PROCESS_TABLE,
): Promise<boolean> {
  const processIds = await processTable.listProcessIds();
  for (let index = 0; index < processIds.length; index += 1) {
    const processId = processIds[index]!;
    let source: string;
    try {
      source = await processTable.readProcessStat(processId);
    } catch (error) {
      const code = objectWithCode(error).code;
      if (code === "ENOENT" || code === "EACCES" || code === "EPERM") continue;
      throw error;
    }
    const stateOffset = source.lastIndexOf(") ");
    if (stateOffset < 0) continue;
    const fields = source.slice(stateOffset + 2).split(" ");
    if (
      Number(fields[2]) === processGroupId &&
      fields[0] !== "Z" &&
      fields[0] !== "X"
    ) {
      return true;
    }
  }
  return false;
}

export async function awaitProcessCleanup(
  terminate: () => Promise<void>,
  close: Promise<unknown>,
): Promise<void> {
  let terminationError: unknown;
  try {
    await terminate();
  } catch (error) {
    terminationError = error;
  }
  await close;
  if (terminationError !== undefined) throw terminationError;
}

async function waitForInterruptGrace(
  close: Promise<unknown> | undefined,
): Promise<void> {
  if (close === undefined) return;
  let timer: NodeJS.Timeout | undefined;
  try {
    await raceIntrinsicPromises(
      close,
      createIntrinsicPromise<void>((resolve) => {
        timer = setTimeoutIntrinsic(resolve, 50);
      }),
    );
  } finally {
    if (timer !== undefined) clearTimeoutIntrinsic(timer);
  }
}

function objectWithCode(value: unknown): { code?: string } {
  return value !== null && typeof value === "object" ? (value as { code?: string }) : {};
}

function destroyChildStreams(child: ChildProcessWithoutNullStreams): void {
  applyIntrinsic(writableDestroyIntrinsic, child.stdin, []);
  applyIntrinsic(readableDestroyIntrinsic, child.stdout, []);
  applyIntrinsic(readableDestroyIntrinsic, child.stderr, []);
}

function assertActive(signal: AbortSignal | undefined): void {
  if (isAbortSignalAborted(signal)) throw new Error();
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (isAbortSignalAborted(signal)) throw new Error();
  let rejectAbort!: () => void;
  const aborted = createIntrinsicPromise<never>((_resolve, reject) => {
    rejectAbort = () => reject(new Error());
  });
  addAbortSignalListener(signal, rejectAbort);
  try {
    return await raceIntrinsicPromises(promise, aborted);
  } finally {
    removeAbortSignalListener(signal, rejectAbort);
  }
}
