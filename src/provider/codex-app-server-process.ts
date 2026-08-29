import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
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

import {
  decodeUtf8Strict,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../bundle/validate-bundle.js";
import {
  addAbortSignalListener,
  isAbortSignalAborted,
  removeAbortSignalListener,
} from "./abort-signal-intrinsics.js";
import {
  CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
  CODEX_APP_SERVER_CLI_VERSION,
  runCodexAppServerProtocol,
  type CodexAppServerProtocolConnection,
  type CodexAppServerProtocolReceivedMessage,
  type CodexAppServerProtocolResult,
} from "./codex-app-server.js";
import type { RequestedExecutionSettings } from "../runner/types.js";

export const CODEX_APP_SERVER_TOOL_PROFILE_VERSION = "codex-no-host-tools-v1";
export const CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION =
  "codex-app-server-isolation-v1";
export const DEFAULT_CODEX_APP_SERVER_TIMEOUT_MS = 120_000;
export const DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES = 384 * 1024 * 1024;

const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
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
const RESERVED_ENVIRONMENT_NAMES = new Set([
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
const DISABLED_FEATURES = Object.freeze([
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
const REASONING_EFFORTS = Object.freeze([
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
    workspace = await createPrivateWorkspace();
    const activeWorkspace = workspace;
    await writeFile(activeWorkspace.catalog, createToolCatalog(request.requested), {
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
    for (const bytes of materialized) bytes.fill(0);
    if (workspace !== undefined) {
      try {
        await rm(workspace.root, { force: true, recursive: true });
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
  if (process.platform !== "darwin" && process.platform !== "linux") throw new Error();
  const executable = value.executable;
  if (typeof executable !== "string" || !path.isAbsolute(executable)) throw new Error();
  const executableArguments = snapshotStrings(value.executableArguments ?? [], MAX_ARGUMENTS);
  const names = snapshotStrings(value.envAllowlist ?? [], 64);
  const seen = new Set<string>();
  for (const name of names) {
    if (
      !ENVIRONMENT_NAME_PATTERN.test(name) ||
      RESERVED_ENVIRONMENT_NAMES.has(name) ||
      seen.has(name)
    ) {
      throw new Error();
    }
    seen.add(name);
  }
  const timeoutMs = value.timeoutMs ?? DEFAULT_CODEX_APP_SERVER_TIMEOUT_MS;
  const outputLimitBytes =
    value.outputLimitBytes ?? DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 15 * 60_000 ||
    !Number.isSafeInteger(outputLimitBytes) ||
    outputLimitBytes < 1024 ||
    outputLimitBytes > MAX_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES
  ) {
    throw new Error();
  }
  return Object.freeze({
    executable,
    executableArguments: Object.freeze(executableArguments),
    envAllowlist: Object.freeze(names),
    timeoutMs,
    outputLimitBytes,
  });
}

function snapshotStrings(value: readonly string[], limit: number): string[] {
  if (!Array.isArray(value) || value.length > limit) throw new Error();
  const output: string[] = [];
  for (const entry of value) {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      Buffer.byteLength(entry, "utf8") > MAX_ARGUMENT_BYTES ||
      entry.includes("\0")
    ) {
      throw new Error();
    }
    output.push(entry);
  }
  return output;
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
  return Object.freeze({
    image: snapshotInput(value.image, true),
    schema: snapshotInput(value.schema, false),
    system: snapshotInput(value.system, false),
    instruction: snapshotInput(value.instruction, false),
    requested: Object.freeze({ model, effort, maxTokens: null }),
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
  return Object.freeze({
    sha256,
    mediaType,
    readBytes: Function.prototype.bind.call(readBytes, value) as () => Promise<Uint8Array>,
  });
}

async function createPrivateWorkspace(): Promise<PrivateWorkspace> {
  const temporaryParent = await realpath(PRIVATE_TEMP_PARENT);
  if (!path.isAbsolute(temporaryParent)) throw new Error();
  const root = await mkdtemp(path.join(temporaryParent, "svbench-codex-"));
  try {
    const canonicalRoot = await realpath(root);
    if (path.dirname(canonicalRoot) !== temporaryParent) throw new Error();
    await chmod(root, DIRECTORY_MODE);
    const directories = {
      home: path.join(root, "home"),
      codexHome: path.join(root, "codex-home"),
      config: path.join(root, "config"),
      cache: path.join(root, "cache"),
      workspace: path.join(root, "workspace"),
      executablePath: path.join(root, "empty-path"),
      temporary: path.join(root, "tmp"),
    };
    await Promise.all(
      Object.values(directories).map((directory) =>
        mkdir(directory, { mode: DIRECTORY_MODE }),
      ),
    );
    const environment = Object.create(null) as NodeJS.ProcessEnv;
    environment.HOME = directories.home;
    environment.USERPROFILE = directories.home;
    environment.CODEX_HOME = directories.codexHome;
    environment.XDG_CONFIG_HOME = directories.config;
    environment.XDG_CACHE_HOME = directories.cache;
    environment.APPDATA = directories.config;
    environment.LOCALAPPDATA = directories.cache;
    environment.PATH = directories.executablePath;
    environment.TMPDIR = directories.temporary;
    environment.TMP = directories.temporary;
    environment.TEMP = directories.temporary;
    return Object.freeze({
      root,
      workspace: directories.workspace,
      catalog: path.join(root, "model-catalog.json"),
      environment,
    });
  } catch {
    await rm(root, { force: true, recursive: true }).catch(() => undefined);
    throw new Error();
  }
}

async function readInput(
  input: CodexAppServerLazyInput,
  materialized: Buffer[],
  timeoutMs: number,
  parentSignal: AbortSignal | undefined,
): Promise<Buffer> {
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  addAbortSignalListener(parentSignal, abort);
  const timer = setTimeout(abort, timeoutMs);
  try {
    assertActive(parentSignal);
    const value = await invokeLazyInput(input.readBytes, controller.signal);
    if (!(value instanceof Uint8Array)) throw new Error();
    try {
      if (value.byteLength > MAX_PROVIDER_INPUT_BYTES) throw new Error();
      const bytes = Buffer.from(value);
      materialized.push(bytes);
      if (createHash("sha256").update(bytes).digest("hex") !== input.sha256) {
        throw new Error();
      }
      return bytes;
    } finally {
      zeroReturnedBytes(value);
    }
  } finally {
    clearTimeout(timer);
    removeAbortSignalListener(parentSignal, abort);
  }
}

function invokeLazyInput(
  reader: () => Promise<Uint8Array>,
  signal: AbortSignal,
): Promise<Uint8Array> {
  assertActive(signal);
  const pending = Promise.resolve().then(() => {
    assertActive(signal);
    return reader();
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const removeAbortListener = (): void => removeAbortSignalListener(signal, abort);
    const abort = (): void => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      reject(new Error());
    };
    addAbortSignalListener(signal, abort);
    void pending.then(
      (value) => {
        if (settled) {
          try {
            if (value instanceof Uint8Array) zeroReturnedBytes(value);
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
  Uint8Array.prototype.fill.call(value, 0);
}

function createToolCatalog(requested: RequestedExecutionSettings & { model: string }): string {
  const efforts = new Set(REASONING_EFFORTS);
  if (requested.effort !== null) efforts.add(requested.effort);
  const defaultEffort = requested.effort ?? "medium";
  return `${JSON.stringify({
    models: [
      {
        slug: requested.model,
        base_instructions: "",
        display_name: requested.model,
        description: null,
        default_reasoning_level: defaultEffort,
        supported_reasoning_levels: [...efforts].map((effort) => ({
          effort,
          description: "fixed extraction effort",
        })),
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
  const arguments_ = [...options.executableArguments, "app-server", "--stdio", "--strict-config"];
  for (const feature of DISABLED_FEATURES) arguments_.push("--disable", feature);
  const overrides = [
    `model_catalog_json=${JSON.stringify(workspace.catalog)}`,
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
  for (const override of overrides) arguments_.push("-c", override);
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
  const controller = new AbortController();
  const guardController = startGuard === undefined ? undefined : new AbortController();
  let abortRequested = false;
  const abort = (): void => {
    abortRequested = true;
    controller.abort();
    guardController?.abort();
  };
  addAbortSignalListener(parentSignal, abort);
  const timer = setTimeout(abort, options.timeoutMs);
  let child: ChildProcessWithoutNullStreams | undefined;
  let close: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
  let termination: Promise<void> | undefined;
  const terminate = (): Promise<void> => {
    if (child === undefined) return Promise.resolve();
    if (termination === undefined) {
      termination = terminateProcessTree(child);
      destroyChildStreams(child);
    }
    return termination;
  };
  try {
    const arguments_ = appServerArguments(options, workspace);
    assertActive(parentSignal);
    let allowedEnvironment: readonly (readonly [string, string])[];
    if (startGuard === undefined) {
      allowedEnvironment = snapshotAllowedEnvironment(options.envAllowlist);
    } else {
      const authorization = snapshotStartAuthorization(
        await startGuard(guardController!.signal),
        options.envAllowlist,
      );
      const finalizerResult: unknown = authorization.finalize();
      if (finalizerResult !== undefined) {
        void Promise.resolve(finalizerResult).catch(() => undefined);
        throw new Error();
      }
      if (abortRequested) throw new Error();
      allowedEnvironment = authorization.allowedEnvironment;
    }
    const environment = snapshotSpawnEnvironment(
      allowedEnvironment,
      workspace.environment,
    );
    child = spawn(options.executable, arguments_, {
      cwd: workspace.workspace,
      detached: process.platform !== "win32",
      env: environment,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    close = waitForClose(child);
    const processConnection = new JsonlProcessConnection(
      child,
      options.outputLimitBytes,
      close,
      terminate,
    );
    const ready = await raceAbort(processConnection.receive(), controller.signal);
    assertIsolationReady(ready?.message);
    const request = await prepareRequest(controller.signal);
    const result = await runCodexAppServerProtocol(
      processConnection,
      request,
      controller.signal,
    );
    const status = await raceAbort(processConnection.waitForClose(), controller.signal);
    await terminate();
    if (status.code !== 0 || status.signal !== null) throw new Error();
    return result;
  } catch {
    if (child !== undefined) {
      if (isAbortSignalAborted(controller.signal)) {
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
    clearTimeout(timer);
    removeAbortSignalListener(parentSignal, abort);
    child?.stdin.destroy();
    child?.stdout.destroy();
    child?.stderr.destroy();
  }
}

function assertIsolationReady(value: JsonValue | undefined): void {
  if (
    value === undefined ||
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    Object.keys(value).length !== 2 ||
    value.method !== "svbench/isolation/ready"
  ) {
    throw new Error();
  }
  const params = value.params;
  if (
    params === null ||
    Array.isArray(params) ||
    typeof params !== "object" ||
    Object.keys(params).length !== 10 ||
    params.protocol !== CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION ||
    params.codexCliVersion !== CODEX_APP_SERVER_CLI_VERSION ||
    params.managedConfig !== "disabled" ||
    params.pluginStartupTasks !== "disabled" ||
    params.accountPromptContributors !== "disabled" ||
    params.telemetry !== "disabled" ||
    params.startupPrewarm !== "disabled" ||
    params.hostedRequestPolicy !== "single-no-retry-no-fallback" ||
    params.promptContract !== "fixed-extraction-only" ||
    params.processModel !== "single-process"
  ) {
    throw new Error();
  }
}

class JsonlProcessConnection implements CodexAppServerProtocolConnection {
  private readonly iterator: AsyncIterator<Buffer | string>;
  private pending = Buffer.alloc(0);
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
    this.iterator = child.stdout[Symbol.asyncIterator]();
    this.close = close;
    child.once("error", () => this.fail());
    child.stdin.once("error", () => this.fail());
    child.stderr.on("data", (chunk: Buffer | string) => {
      this.stderrBytes += Buffer.byteLength(chunk);
      if (this.stderrBytes > MAX_STDERR_BYTES) this.fail();
    });
  }

  async send(message: JsonValue): Promise<void> {
    if (this.failed) throw new Error();
    const bytes = Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
    try {
      if (bytes.byteLength > this.outputLimitBytes) {
        this.fail();
        throw new Error();
      }
      await new Promise<void>((resolve, reject) => {
        this.child.stdin.write(bytes, (error) => {
          if (error === null || error === undefined) resolve();
          else reject(error);
        });
      });
    } finally {
      bytes.fill(0);
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
        chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
        this.outputBytes += chunk.byteLength;
        if (this.outputBytes > this.outputLimitBytes) {
          this.fail();
          throw new Error();
        }
      }

      const newline = chunk.indexOf(0x0a);
      if (newline === -1) {
        this.appendPending(chunk);
        continue;
      }
      this.appendPending(chunk.subarray(0, newline));
      if (newline + 1 < chunk.byteLength) this.unread = chunk.subarray(newline + 1);
      if (this.pendingBytes === 0 || this.pending[this.pendingBytes - 1] === 0x0d) {
        throw new Error();
      }
      try {
        const line = this.pending.subarray(0, this.pendingBytes);
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
        this.pending.fill(0, 0, this.pendingBytes);
        this.pendingBytes = 0;
      }
    }
  }

  private appendPending(chunk: Buffer): void {
    if (chunk.byteLength === 0) return;
    const required = this.pendingBytes + chunk.byteLength;
    if (required > MAX_JSONL_LINE_BYTES) {
      this.fail();
      throw new Error();
    }
    if (required > this.pending.byteLength) {
      let capacity = Math.max(4096, this.pending.byteLength);
      while (capacity < required) capacity = Math.min(MAX_JSONL_LINE_BYTES, capacity * 2);
      const grown = Buffer.allocUnsafe(capacity);
      this.pending.copy(grown, 0, 0, this.pendingBytes);
      this.pending.fill(0);
      this.pending = grown;
    }
    chunk.copy(this.pending, this.pendingBytes);
    this.pendingBytes = required;
  }

  closeInput(): void {
    this.child.stdin.end();
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
  return new Promise((resolve) => {
    child.once("close", (code, childSignal) => resolve({ code, signal: childSignal }));
  });
}

async function terminateProcessTree(child: ChildProcessWithoutNullStreams): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch (error) {
    if (objectWithCode(error).code !== "ESRCH") throw error;
  }
  await waitForProcessGroupSettlement(pid);
}

function snapshotSpawnEnvironment(
  allowed: readonly (readonly [string, string])[],
  privateEnvironment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const environment = Object.create(null) as NodeJS.ProcessEnv;
  for (const [name, value] of allowed) environment[name] = value;
  for (const name of Object.keys(privateEnvironment)) {
    const value = privateEnvironment[name];
    if (value !== undefined) environment[name] = value;
  }
  return environment;
}

function snapshotAllowedEnvironment(
  allowlist: readonly string[],
): readonly (readonly [string, string])[] {
  const allowed: Array<readonly [string, string]> = [];
  for (const name of allowlist) {
    const value = process.env[name];
    if (value !== undefined) allowed.push(Object.freeze([name, value]));
  }
  return Object.freeze(allowed);
}

function snapshotStartAuthorization(
  value: CodexAppServerProcessStartAuthorization,
  allowlist: readonly string[],
): CodexAppServerProcessStartAuthorization {
  if (value === null || typeof value !== "object") throw new Error();
  const finalize = value.finalize;
  const source = value.allowedEnvironment;
  if (typeof finalize !== "function" || !Array.isArray(source)) throw new Error();
  const allowedNames = new Set(allowlist);
  const seen = new Set<string>();
  const allowed: Array<readonly [string, string]> = [];
  for (const entry of source) {
    if (!Array.isArray(entry)) throw new Error();
    const length = entry.length;
    const name = entry[0];
    const environmentValue = entry[1];
    if (
      length !== 2 ||
      typeof name !== "string" ||
      typeof environmentValue !== "string" ||
      !allowedNames.has(name) ||
      seen.has(name)
    ) {
      throw new Error();
    }
    seen.add(name);
    allowed.push(Object.freeze([name, environmentValue]));
  }
  return Object.freeze({
    allowedEnvironment: Object.freeze(allowed),
    finalize: Function.prototype.bind.call(finalize, undefined),
  });
}

async function waitForProcessGroupSettlement(processGroupId: number): Promise<void> {
  const deadline = Date.now() + PROCESS_GROUP_SETTLE_TIMEOUT_MS;
  while (await processGroupHasLiveMember(processGroupId)) {
    if (Date.now() >= deadline) throw new Error();
    await new Promise<void>((resolve) => {
      setTimeout(resolve, PROCESS_GROUP_SETTLE_INTERVAL_MS);
    });
  }
}

async function processGroupHasLiveMember(processGroupId: number): Promise<boolean> {
  try {
    process.kill(-processGroupId, 0);
  } catch (error) {
    return processGroupProbeFailureIndicatesLive(error);
  }
  if (process.platform !== "linux") return true;
  return linuxProcessGroupHasLiveMember(processGroupId);
}

/** @internal Classifies the POSIX signal-zero process-group probe without weakening cleanup. */
export function processGroupProbeFailureIndicatesLive(error: unknown): boolean {
  const code = objectWithCode(error).code;
  if (code === "ESRCH") return false;
  if (code === "EPERM") return true;
  throw error;
}

const DEFAULT_LINUX_PROCESS_TABLE: LinuxProcessTable = Object.freeze({
  async listProcessIds(): Promise<readonly string[]> {
    const processIds: string[] = [];
    for (const entry of await readdir("/proc", { withFileTypes: true })) {
      if (entry.isDirectory() && /^[1-9][0-9]*$/u.test(entry.name)) {
        processIds.push(entry.name);
      }
    }
    return processIds;
  },
  async readProcessStat(processId: string): Promise<string> {
    return readFile(`/proc/${processId}/stat`, "utf8");
  },
});

export async function linuxProcessGroupHasLiveMember(
  processGroupId: number,
  processTable: LinuxProcessTable = DEFAULT_LINUX_PROCESS_TABLE,
): Promise<boolean> {
  for (const processId of await processTable.listProcessIds()) {
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
    await Promise.race([
      close,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 50);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function objectWithCode(value: unknown): { code?: string } {
  return value !== null && typeof value === "object" ? (value as { code?: string }) : {};
}

function destroyChildStreams(child: ChildProcessWithoutNullStreams): void {
  child.stdin.destroy();
  child.stdout.destroy();
  child.stderr.destroy();
}

function assertActive(signal: AbortSignal | undefined): void {
  if (isAbortSignalAborted(signal)) throw new Error();
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (isAbortSignalAborted(signal)) throw new Error();
  let rejectAbort!: () => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = () => reject(new Error());
  });
  addAbortSignalListener(signal, rejectAbort);
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    removeAbortSignalListener(signal, rejectAbort);
  }
}
