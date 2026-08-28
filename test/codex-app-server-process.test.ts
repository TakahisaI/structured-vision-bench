import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, watch, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
} from "../src/provider/codex-app-server.js";
import {
  CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION,
  CODEX_APP_SERVER_TOOL_PROFILE_VERSION,
  DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES,
  awaitProcessCleanup,
  linuxProcessGroupHasLiveMember,
  runCodexAppServerProcess,
  type CodexAppServerProcessOptions,
  type CodexAppServerProcessRequest,
  type LinuxProcessTable,
} from "../src/provider/codex-app-server-process.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../src/bundle/validate-bundle.js";

const FIXTURE = path.join(
  process.cwd(),
  ".tmp",
  "build",
  "test",
  "support",
  "fake-codex-app-server.js",
);
const PROHIBITED_HOSTED_KEYS = [
  "approval",
  "bundle",
  "caseId",
  "comparison",
  "documentKind",
  "inputDigests",
  "provenance",
  "sanitizerRequirement",
  "truth",
];

test("ignores inaccessible unrelated entries while inspecting Linux process groups", async () => {
  const states = new Map([
    ["101", linuxProcessStat("S", 77)],
    ["102", linuxProcessStat("Z", 88)],
  ]);
  const processTable: LinuxProcessTable = {
    async listProcessIds() {
      return ["1", "101", "102", "103"];
    },
    async readProcessStat(processId) {
      if (processId === "1") throw errorWithCode("EACCES");
      if (processId === "103") throw errorWithCode("EPERM");
      const source = states.get(processId);
      assert.ok(source);
      return source;
    },
  };

  assert.equal(await linuxProcessGroupHasLiveMember(77, processTable), true);
  assert.equal(await linuxProcessGroupHasLiveMember(88, processTable), false);
});

test("waits for leader close when process-group settlement inspection fails", async () => {
  let closeLeader: (() => void) | undefined;
  const close = new Promise<void>((resolve) => {
    closeLeader = resolve;
  });
  let settled = false;
  const running = awaitProcessCleanup(
    async () => {
      throw errorWithCode("EACCES");
    },
    close,
  ).finally(() => {
    settled = true;
  });

  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  assert.ok(closeLeader);
  closeLeader();
  await assert.rejects(running, (error: unknown) => objectWithCode(error).code === "EACCES");
  assert.equal(settled, true);
});

test("runs one fixed app-server process in an isolated empty workspace", async () => {
  await withFixture("success", async ({ options, capture, canary }) => {
    const previousParent = process.env.SVBENCH_PARENT_CANARY;
    const previousAllowed = process.env.SVBENCH_ALLOWED_CANARY;
    process.env.SVBENCH_PARENT_CANARY = "synthetic-parent-secret-canary";
    process.env.SVBENCH_ALLOWED_CANARY = "synthetic-explicit-canary";
    try {
      const reads = readCounter();
      const result = await runCodexAppServerProcess(
        { ...options, envAllowlist: ["SVBENCH_ALLOWED_CANARY"] },
        request(reads),
      );
      assert.deepEqual(result, {
        document: { documentKind: "synthetic_invoice", totalAmount: 0 },
        respondedModel: "synthetic-model",
        effectiveEffort: "medium",
        usage: {
          available: true,
          inputTokens: 11,
          outputTokens: 7,
          totalTokens: 18,
        },
        stopReason: null,
      });
      assert.deepEqual(reads, { image: 1, schema: 1, system: 1, instruction: 1 });

      const records = await readCapture(capture);
      const boundary = records.find((record) => record.phase === "app-server");
      assert.ok(boundary);
      assert.equal(boundary.rootMode, process.platform === "win32" ? boundary.rootMode : 0o700);
      assert.equal(
        boundary.workspaceMode,
        process.platform === "win32" ? boundary.workspaceMode : 0o700,
      );
      assert.deepEqual(boundary.workspaceEntries, []);
      assert.equal(boundary.parentCanary, null);
      assert.equal(boundary.allowedCanary, "synthetic-explicit-canary");
      assert.deepEqual(boundary.isolation, {
        home: true,
        codexHome: true,
        config: true,
        cache: true,
        path: true,
      });
      const environmentKeys = stringArray(boundary.environmentKeys);
      assert.equal(environmentKeys.includes("SVBENCH_PARENT_CANARY"), false);
      assert.equal(environmentKeys.includes("NODE_OPTIONS"), false);
      assertToolBoundary(boundary);
      assertProjectIsolation(boundary);
      await assertMissing(String(boundary.root));
      assert.equal(await readFile(canary, "utf8"), "synthetic canary unchanged\n");

      const threadStart = object(
        records.find((record) => record.threadStart !== undefined)?.threadStart,
      );
      const turnStart = object(
        records.find((record) => record.turnStart !== undefined)?.turnStart,
      );
      assert.equal(threadStart.baseInstructions, "synthetic system");
      assert.equal(threadStart.model, "synthetic-model");
      assert.equal(turnStart.model, "synthetic-model");
      assert.equal(turnStart.effort, "medium");
      assert.deepEqual(turnStart.outputSchema, schema());
      const input = array(turnStart.input);
      assert.equal(object(input[0]).text, "synthetic instruction");
      assert.match(String(object(input[1]).url), /^data:image\/png;base64,/u);
      for (const key of PROHIBITED_HOSTED_KEYS) {
        assert.equal(Object.hasOwn(threadStart, key), false, `thread.${key}`);
        assert.equal(Object.hasOwn(turnStart, key), false, `turn.${key}`);
      }
    } finally {
      restoreEnvironment("SVBENCH_PARENT_CANARY", previousParent);
      restoreEnvironment("SVBENCH_ALLOWED_CANARY", previousAllowed);
    }
  });
});

test("does not read provider inputs before request and in-process isolation proof", async () => {
  for (const scenario of [
    { mode: "success", mutate: (value: CodexAppServerProcessRequest) => ({
      ...value,
      requested: { ...value.requested, maxTokens: 1 },
    }) },
    { mode: "version-mismatch", mutate: (value: CodexAppServerProcessRequest) => value },
    { mode: "isolation-mismatch", mutate: (value: CodexAppServerProcessRequest) => value },
    {
      mode: "prompt-contract-mismatch",
      mutate: (value: CodexAppServerProcessRequest) => value,
    },
    { mode: "isolation-hang", mutate: (value: CodexAppServerProcessRequest) => value },
  ]) {
    await withFixture(scenario.mode, async ({ options }) => {
      const reads = readCounter();
      const startedAt = Date.now();
      await assert.rejects(
        runCodexAppServerProcess(
          { ...options, timeoutMs: 100 },
          scenario.mutate(request(reads)),
        ),
        stableProcessError,
        scenario.mode,
      );
      if (scenario.mode === "isolation-hang") {
        assert.ok(Date.now() - startedAt >= 75, "isolation proof must reach its timeout");
      }
      assert.deepEqual(
        reads,
        { image: 0, schema: 0, system: 0, instruction: 0 },
        scenario.mode,
      );
    });
  }
});

test("accepts a readiness value fragmented into single-byte writes", async () => {
  await withFixture("fragmented-ready", async ({ options }) => {
    const reads = readCounter();
    const result = await runCodexAppServerProcess(options, request(reads));
    assert.equal(result.respondedModel, "synthetic-model");
    assert.deepEqual(reads, { image: 1, schema: 1, system: 1, instruction: 1 });
  });
});

test("verifies every lazy input digest before process transport", async () => {
  await withFixture("success", async ({ options, capture }) => {
    const reads = readCounter();
    const valid = request(reads);
    const invalid = {
      ...valid,
      image: { ...valid.image, sha256: "0".repeat(64) },
    };
    await assert.rejects(runCodexAppServerProcess(options, invalid), stableProcessError);
    assert.deepEqual(reads, { image: 1, schema: 0, system: 0, instruction: 0 });
    const records = await readCapture(capture);
    assert.ok(records.some((record) => record.phase === "app-server"));
    assert.equal(records.some((record) => record.threadStart !== undefined), false);
  });
});

test("zeroes callback-returned bytes after success and digest failure", async () => {
  await withFixture("success", async ({ options }) => {
    for (const validDigest of [true, false]) {
      const reads = readCounter();
      const base = request(reads);
      const returned = Buffer.from("synthetic image");
      const value = {
        ...base,
        image: {
          ...base.image,
          sha256: validDigest ? base.image.sha256 : "0".repeat(64),
          async readBytes(): Promise<Buffer> {
            reads.image = (reads.image ?? 0) + 1;
            return returned;
          },
        },
      };
      if (validDigest) {
        await runCodexAppServerProcess(options, value);
      } else {
        await assert.rejects(runCodexAppServerProcess(options, value), stableProcessError);
      }
      assert.ok(returned.every((byte) => byte === 0));
    }
  });
});

test("zeroes a lazy input that resolves after timeout settlement", async () => {
  await withFixture("success", async ({ options }) => {
    const reads = readCounter();
    const base = request(reads);
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    let returned: Buffer | undefined;
    const pending = {
      ...base,
      system: {
        ...base.system,
        async readBytes(): Promise<Buffer> {
          reads.system = (reads.system ?? 0) + 1;
          markStarted();
          await blocked;
          returned = Buffer.from("synthetic late system");
          return returned;
        },
      },
    };
    const running = runCodexAppServerProcess(
      { ...options, timeoutMs: 750 },
      pending,
    );
    await started;
    await assert.rejects(running, stableProcessError);
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.ok(returned);
    assert.ok(returned.every((byte) => byte === 0));
  });
});

test("bounds a pending lazy input read without starting app-server", async () => {
  await withFixture("success", async ({ options, capture }) => {
    const reads = readCounter();
    const valid = request(reads);
    const pending = {
      ...valid,
      system: {
        ...valid.system,
        async readBytes(): Promise<Uint8Array> {
          reads.system = (reads.system ?? 0) + 1;
          return await new Promise(() => undefined);
        },
      },
    };
    await assert.rejects(
      runCodexAppServerProcess({ ...options, timeoutMs: 750 }, pending),
      stableProcessError,
    );
    assert.deepEqual(reads, { image: 1, schema: 1, system: 1, instruction: 0 });
    const records = await readCapture(capture);
    assert.ok(records.some((record) => record.phase === "app-server"));
    assert.equal(records.some((record) => record.threadStart !== undefined), false);
  });
});

test("classifies malformed output, overflow, crash, and timeout without diagnostics", async (t) => {
  for (const mode of [
    "malformed",
    "unterminated",
    "stdout-overflow",
    "stderr-overflow",
    "crash",
    "crash-descendant",
    "hang",
  ]) {
    await t.test(mode, { timeout: 5_000 }, async () => {
      await withFixture(mode, async ({ options, capture, canary }) => {
        await assert.rejects(
          runCodexAppServerProcess(
            {
              ...options,
              outputLimitBytes: 1024,
              timeoutMs: mode === "hang" ? 750 : 3_000,
            },
            request(readCounter()),
          ),
          (error: unknown) =>
            stableProcessError(error) &&
            !String(error).includes(canary) &&
            !String(error).includes("synthetic canary"),
          mode,
        );
        const boundary = (await readCapture(capture)).find(
          (record) => record.phase === "app-server",
        );
        assert.ok(boundary);
        await assertMissing(String(boundary.root));
        const descendant = (await readCapture(capture)).find(
          (record) => record.descendantPid !== undefined,
        );
        if (descendant !== undefined) {
          await assertProcessStopped(Number(descendant.descendantPid));
        }
      });
    });
  }
});

test("tears down while valid repeated user events overflow the total limit", async () => {
  await withFixture("success", async ({ options, capture }) => {
    const reads = readCounter();
    const base = request(reads);
    const image = Buffer.alloc(150 * 1024, 83);
    const instruction = Buffer.alloc(150 * 1024, 84);
    const large = {
      ...base,
      image: { ...lazy("image", image, reads), mediaType: "image/png" },
      instruction: lazy("instruction", instruction, reads),
    };
    await assert.rejects(
      runCodexAppServerProcess(
        { ...options, outputLimitBytes: 600 * 1024 },
        large,
      ),
      stableProcessError,
    );
    const boundary = (await readCapture(capture)).find(
      (record) => record.phase === "app-server",
    );
    assert.ok(boundary);
    await assertMissing(String(boundary.root));
  });
});

test("accepts JSON-escaped control text within the byte contract", async () => {
  await withFixture("success", async ({ options }) => {
    const reads = readCounter();
    const base = request(reads);
    const instruction = Buffer.alloc(256 * 1024, 0);
    const escaped = {
      ...base,
      instruction: lazy("instruction", instruction, reads),
    };
    const result = await runCodexAppServerProcess(
      { ...options, outputLimitBytes: 6 * 1024 * 1024 },
      escaped,
    );
    assert.equal(result.respondedModel, "synthetic-model");
    assert.deepEqual(reads, { image: 1, schema: 1, system: 1, instruction: 1 });
  });
});

test("reclaims descendants after successful app-server and isolation prelude", async (t) => {
  for (const mode of ["success-descendant", "isolation-success-descendant"]) {
    await t.test(mode, async () => {
      await withFixture(mode, async ({ options, capture }) => {
        const result = await runCodexAppServerProcess(options, request(readCounter()));
        assert.equal(result.respondedModel, "synthetic-model");
        const descendant = (await readCapture(capture)).find(
          (record) =>
            record.descendantPid !== undefined ||
            record.isolationDescendantPid !== undefined,
        );
        assert.ok(descendant);
        await assertProcessStopped(
          Number(descendant.descendantPid ?? descendant.isolationDescendantPid),
        );
      });
    });
  }
});

test("reclaims isolation descendants after a nonzero leader exit", async () => {
  await withFixture("isolation-failure-descendant", async ({ options, capture }) => {
    await assert.rejects(
      runCodexAppServerProcess(options, request(readCounter())),
      stableProcessError,
    );
    const descendant = (await readCapture(capture)).find(
      (record) => record.isolationDescendantPid !== undefined,
    );
    assert.ok(descendant);
    await assertProcessStopped(Number(descendant.isolationDescendantPid));
  });
});

test("cancellation sends interrupt before process tree and workspace teardown", async () => {
  await withFixture("cancel-turn", async ({ options, capture }) => {
    const controller = new AbortController();
    const running = runCodexAppServerProcess(
      { ...options, timeoutMs: 10_000 },
      request(readCounter()),
      controller.signal,
    );
    const records = await waitForCapture(
      capture,
      (values) => values.some((value) => value.ready === true),
    );
    controller.abort();
    await assert.rejects(running, stableProcessError);
    const finalRecords = await readCapture(capture);
    const boundary = records.find((record) => record.phase === "app-server");
    const descendant = records.find((record) => record.descendantPid !== undefined);
    assert.ok(boundary);
    assert.ok(descendant);
    assert.equal(finalRecords.filter((record) => record.interrupt !== undefined).length, 1);
    await assertMissing(String(boundary.root));
    await assertProcessStopped(Number(descendant.descendantPid));
  });
});

test("never executes host tools requested by the fake app-server", async (t) => {
  for (const mode of [
    "tool-approval",
    "tool-shell",
    "tool-apply-patch",
    "tool-view-image",
    "tool-code-mode",
    "tool-child-turn",
  ]) {
    await t.test(mode, { timeout: 5_000 }, async () => {
      await withFixture(mode, async ({ options, capture, canary }) => {
        await assert.rejects(
          runCodexAppServerProcess(options, request(readCounter())),
          stableProcessError,
          mode,
        );
        assert.equal(await readFile(canary, "utf8"), "synthetic canary unchanged\n");
        const boundary = (await readCapture(capture)).find(
          (record) => record.phase === "app-server",
        );
        assert.ok(boundary);
        await assertMissing(String(boundary.root));
      });
    });
  }
});

test("pins the process tool profile identity", () => {
  assert.equal(CODEX_APP_SERVER_TOOL_PROFILE_VERSION, "codex-no-host-tools-v1");
  assert.equal(
    CODEX_APP_SERVER_ISOLATION_PROTOCOL_VERSION,
    "codex-app-server-isolation-v1",
  );
  const maximumEscapedTextBytes = 6 * MAX_PROVIDER_INPUT_BYTES + 2;
  const maximumUserItemBytes =
    Math.ceil(MAX_PROVIDER_INPUT_BYTES / 3) * 4 + maximumEscapedTextBytes;
  const requiredEchoAndFinalBytes =
    2 * maximumUserItemBytes + 4 * MAX_PROVIDER_INPUT_BYTES;
  const envelopeAllowance = 1024 * 1024;
  assert.ok(
    CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES >
      maximumUserItemBytes + envelopeAllowance,
  );
  assert.ok(
    DEFAULT_CODEX_APP_SERVER_OUTPUT_LIMIT_BYTES >
      requiredEchoAndFinalBytes + envelopeAllowance,
  );
});

test("disables project instruction discovery above the private workspace", async () => {
  await withFixture("ancestor-config", async ({ options, capture }) => {
    const result = await runCodexAppServerProcess(options, request(readCounter()));
    assert.equal(result.respondedModel, "synthetic-model");
    const boundary = (await readCapture(capture)).find(
      (record) => record.phase === "app-server",
    );
    assert.ok(boundary);
    assert.equal(boundary.ancestorCanary, "synthetic ancestor instruction\n");
    assertProjectIsolation(boundary);
  });
});

test("ignores ambient temporary-directory settings", async () => {
  await withFixture("success", async ({ options, capture }) => {
    const previous = process.env.TMPDIR;
    for (const ambient of [path.dirname(capture), "relative-synthetic-temp"]) {
      process.env.TMPDIR = ambient;
      try {
        const result = await runCodexAppServerProcess(options, request(readCounter()));
        assert.equal(result.respondedModel, "synthetic-model");
        const boundaries = (await readCapture(capture)).filter(
          (record) => record.phase === "app-server",
        );
        const boundary = boundaries[boundaries.length - 1];
        assert.ok(boundary);
        const relative = path.relative(path.dirname(capture), String(boundary.root));
        assert.ok(relative === ".." || relative.startsWith(`..${path.sep}`));
      } finally {
        restoreEnvironment("TMPDIR", previous);
      }
    }
  });
});

function request(reads: Record<string, number>): CodexAppServerProcessRequest {
  const image = Buffer.from("synthetic image");
  const schemaBytes = Buffer.from(`${JSON.stringify(schema())}\n`);
  const system = Buffer.from("synthetic system");
  const instruction = Buffer.from("synthetic instruction");
  return {
    image: { ...lazy("image", image, reads), mediaType: "image/png" },
    schema: lazy("schema", schemaBytes, reads),
    system: lazy("system", system, reads),
    instruction: lazy("instruction", instruction, reads),
    requested: { model: "synthetic-model", effort: "medium", maxTokens: null },
  };
}

function lazy(
  name: string,
  bytes: Buffer,
  reads: Record<string, number>,
): { sha256: string; readBytes: () => Promise<Buffer> } {
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    async readBytes(): Promise<Buffer> {
      reads[name] = (reads[name] ?? 0) + 1;
      return Buffer.from(bytes);
    },
  };
}

function schema(): Record<string, unknown> {
  return {
    type: "object",
    additionalProperties: false,
    required: ["documentKind", "totalAmount"],
    properties: {
      documentKind: { const: "synthetic_invoice" },
      totalAmount: { type: "number" },
    },
  };
}

function readCounter(): Record<string, number> {
  return { image: 0, schema: 0, system: 0, instruction: 0 };
}

async function withFixture(
  mode: string,
  run: (fixture: {
    options: CodexAppServerProcessOptions;
    capture: string;
    canary: string;
  }) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), "svbench-process-test-"));
  const capture = path.join(root, "capture.jsonl");
  const canary = path.join(root, "synthetic-canary.txt");
  await writeFile(canary, "synthetic canary unchanged\n", { mode: 0o600 });
  try {
    await run({
      options: {
        executable: process.execPath,
        executableArguments: [FIXTURE, mode, capture, canary],
        timeoutMs: 3_000,
      },
      capture,
      canary,
    });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

async function readCapture(file: string): Promise<JsonObject[]> {
  let source: string;
  try {
    source = await readFile(file, "utf8");
  } catch (error) {
    if (objectWithCode(error).code === "ENOENT") return [];
    throw error;
  }
  return source
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => object(JSON.parse(line)));
}

async function waitForCapture(
  file: string,
  predicate: (values: JsonObject[]) => boolean,
): Promise<JsonObject[]> {
  const initial = await readCapture(file);
  if (predicate(initial)) return initial;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  const watcher = watch(path.dirname(file), { signal: controller.signal });
  try {
    for await (const _event of watcher) {
      const values = await readCapture(file);
      if (predicate(values)) return values;
    }
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  throw new Error("synthetic capture was not observed");
}

function assertToolBoundary(boundary: JsonObject): void {
  const model = object(boundary.catalogModel);
  assert.deepEqual(model, {
    slug: "synthetic-model",
    shellType: "disabled",
    applyPatch: null,
    toolMode: "direct",
    multiAgent: "disabled",
    experimentalTools: [],
    skills: false,
    plugins: false,
    apps: false,
    search: false,
    nodeReplDisabled: true,
  });
  const disabled = stringArray(boundary.disabledFeatures);
  for (const feature of [
    "code_mode_host",
    "multi_agent",
    "multi_agent_v2",
    "shell_snapshot",
    "shell_tool",
    "unbounded_connection_retries",
    "view_image",
  ]) {
    assert.ok(disabled.includes(feature), feature);
  }
  const overrides = object(boundary.overrides);
  assert.equal(overrides.personality, '"none"');
  assert.equal(overrides.include_permissions_instructions, "false");
  assert.equal(overrides.include_environment_context, "false");
  assert.equal(overrides.include_collaboration_mode_instructions, "false");
  assert.equal(overrides.include_apps_instructions, "false");
  assert.equal(overrides["skills.include_instructions"], "false");
  assert.equal(overrides["skills.bundled.enabled"], "false");
  assert.equal(overrides["analytics.enabled"], "false");
  assert.equal(overrides["tools.update_plan.enabled"], "false");
  assert.equal(overrides["tools.experimental_request_user_input.enabled"], "false");
  assert.equal(overrides.agents, undefined);
  assert.equal(overrides["agents.enabled"], "false");
  assert.equal(overrides.mcp_servers, "{}");
  assert.equal(overrides.hooks, "{}");
  assert.equal(overrides.notify, "[]");
}

function assertProjectIsolation(boundary: JsonObject): void {
  const overrides = object(boundary.overrides);
  assert.equal(overrides.project_root_markers, "[]");
  assert.equal(overrides.project_doc_max_bytes, "0");
}

async function assertMissing(target: string): Promise<void> {
  await assert.rejects(stat(target), (error: unknown) => objectWithCode(error).code === "ENOENT");
}

async function assertProcessStopped(pid: number): Promise<void> {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  try {
    process.kill(pid, 0);
  } catch (error: unknown) {
    assert.equal(objectWithCode(error).code, "ESRCH");
    return;
  }

  if (process.platform === "linux") {
    await readFile("/proc/self/stat", "utf8");
    let processStat: string;
    try {
      processStat = await readFile(`/proc/${pid}/stat`, "utf8");
    } catch (error: unknown) {
      assert.equal(objectWithCode(error).code, "ENOENT");
      return;
    }
    const stateOffset = processStat.lastIndexOf(") ") + 2;
    assert.ok(stateOffset >= 2, "unexpected Linux process stat format");
    assert.ok(
      processStat[stateOffset] === "Z" || processStat[stateOffset] === "X",
      "descendant process is still running",
    );
    return;
  }

  assert.fail("descendant process is still running");
}

function stableProcessError(error: unknown): boolean {
  return error instanceof Error && error.message === "codex app-server process failed";
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as JsonObject;
}

function objectWithCode(value: unknown): { code?: string } {
  if (value === null || typeof value !== "object") return {};
  return value as { code?: string };
}

function errorWithCode(code: string): Error & { code: string } {
  return Object.assign(new Error("synthetic process table failure"), { code });
}

function linuxProcessStat(state: string, processGroupId: number): string {
  return `999 (synthetic process) ${state} 1 ${processGroupId} 0 0`;
}

function array(value: unknown): unknown[] {
  assert.ok(Array.isArray(value));
  return value;
}

function stringArray(value: unknown): string[] {
  const values = array(value);
  assert.ok(values.every((entry) => typeof entry === "string"));
  return values as string[];
}
