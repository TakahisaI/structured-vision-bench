import { spawn } from "node:child_process";
import { tmpdir } from "node:os";

import { decodeUtf8Strict, isJsonObject, parseJson } from "../bundle/json.js";
import { RunnerError } from "./errors.js";
import type { ApprovalGate, ApprovalRequest, ApprovalResponse } from "./types.js";

export const APPROVAL_PROTOCOL_VERSION = 1 as const;
export const DEFAULT_APPROVAL_OUTPUT_LIMIT_BYTES = 64 * 1024;

export type CommandApprovalGateOptions = {
  executable: string;
  argv: string[];
  envAllowlist: string[];
  outputLimitBytes: number;
  gateId: string;
};

/** Runs a consumer-owned approval process without a shell or inherited environment. */
export function createCommandApprovalGate(options: CommandApprovalGateOptions): ApprovalGate {
  try {
    const executable = options.executable;
    const sourceArgv = options.argv;
    const sourceEnvAllowlist = options.envAllowlist;
    if (!Array.isArray(sourceArgv) || !Array.isArray(sourceEnvAllowlist)) throw new Error();
    const argv = [...sourceArgv];
    const envAllowlist = [...sourceEnvAllowlist];
    const outputLimitBytes = options.outputLimitBytes;
    const gateId = options.gateId;
    if (
      typeof executable !== "string" ||
      executable.length === 0 ||
      executable.length > 240 ||
      argv.length > 64 ||
      argv.some((value) => typeof value !== "string" || value.length > 240) ||
      envAllowlist.length > 64 ||
      envAllowlist.some(
        (value) =>
          typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(value),
      ) ||
      !Number.isSafeInteger(outputLimitBytes) ||
      outputLimitBytes < 1 ||
      outputLimitBytes > 16 * 1024 * 1024 ||
      typeof gateId !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/u.test(gateId)
    ) {
      throw new Error();
    }
    return Object.freeze({
      id: gateId,
      protocolVersion: APPROVAL_PROTOCOL_VERSION,
      approve: async (request: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalResponse> =>
        runApprovalCommand(
          executable,
          argv,
          envAllowlist,
          outputLimitBytes,
          request,
          signal,
        ),
    });
  } catch {
    throw new RunnerError(
      "approval_configuration_invalid",
      "approval command configuration is invalid",
    );
  }
}

async function runApprovalCommand(
  executable: string,
  argv: string[],
  envAllowlist: string[],
  outputLimitBytes: number,
  request: ApprovalRequest,
  signal: AbortSignal | undefined,
): Promise<ApprovalResponse> {
  if (signal?.aborted) throw new Error("approval command aborted");
  const environment: NodeJS.ProcessEnv = {};
  for (const name of envAllowlist) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  const requestBytes = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
  return new Promise<ApprovalResponse>((resolve, reject) => {
    let child;
    try {
      child = spawn(executable, argv, {
        cwd: tmpdir(),
        env: environment,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      reject(new Error("approval command failed"));
      return;
    }

    const stdout: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    const finish = (error?: Error, response?: ApprovalResponse): void => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      if (error !== undefined) reject(error);
      else resolve(response!);
    };
    const fail = (): void => {
      child.kill("SIGKILL");
      finish(new Error("approval command failed"));
    };
    const collect = (chunk: Buffer, keep: boolean): void => {
      outputBytes += chunk.byteLength;
      if (outputBytes > outputLimitBytes) {
        fail();
        return;
      }
      if (keep) stdout.push(Buffer.from(chunk));
    };
    const abort = (): void => {
      child.kill("SIGKILL");
      finish(new Error("approval command aborted"));
    };

    signal?.addEventListener("abort", abort, { once: true });
    child.once("error", () => finish(new Error("approval command failed")));
    child.stdout.on("data", (chunk: Buffer) => collect(chunk, true));
    child.stderr.on("data", (chunk: Buffer) => collect(chunk, false));
    child.stdin.once("error", fail);
    child.once("close", (code, closeSignal) => {
      if (settled) return;
      if (code !== 0 || closeSignal !== null) {
        finish(new Error("approval command failed"));
        return;
      }
      try {
        const parsed = parseJson(
          decodeUtf8Strict(Buffer.concat(stdout), "approval response"),
          "approval response",
        );
        if (!isJsonObject(parsed)) throw new Error();
        finish(undefined, parsed as unknown as ApprovalResponse);
      } catch {
        finish(new Error("approval command failed"));
      }
    });
    child.stdin.end(requestBytes);
  });
}
