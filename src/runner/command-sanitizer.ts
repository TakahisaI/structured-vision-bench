import { spawn } from "node:child_process";
import { chmod, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  encodeCommandSanitizerRequest,
  parseCommandSanitizerResponse,
  snapshotCommandSanitizerRequest,
  type CommandSanitizerRequestV1,
} from "./command-sanitizer-wire.js";
import { RunnerError } from "./errors.js";
import type { Sanitizer, SanitizerRequest, SanitizerResponse } from "./types.js";

export {
  MAX_COMMAND_SANITIZER_REQUEST_BYTES,
  type CommandSanitizerRequestV1,
  type CommandSanitizerResponseV1,
} from "./command-sanitizer-wire.js";

export const DEFAULT_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024;
export const MAX_COMMAND_SANITIZER_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024;

const DIRECTORY_MODE = 0o700;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const ABORT_SETTLING_COMMAND_SANITIZERS = new WeakSet<object>();

export type CommandSanitizerOptions = {
  executable: string;
  argv?: string[];
  envAllowlist?: string[];
  outputLimitBytes?: number;
  sanitizerId: string;
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
        const snapshot = snapshotCommandSanitizerRequest(request);
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
      typeof sanitizerId !== "string" ||
      !SAFE_LABEL_PATTERN.test(sanitizerId)
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
    requestBytes = encodeCommandSanitizerRequest(request);
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
    return parseCommandSanitizerResponse(responseBytes, options.sanitizerId, request);
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
    killer.once("close", (code, killerSignal) => resolve(code === 0 && killerSignal === null));
  });
  if (!killed) child.kill("SIGKILL");
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
