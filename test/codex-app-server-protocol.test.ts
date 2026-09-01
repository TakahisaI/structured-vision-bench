import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { JsonValue } from "../src/bundle/json.js";
import {
  CODEX_APP_SERVER_CLI_VERSION,
  CODEX_APP_SERVER_GENERATED_SCHEMA_SHA256,
  CODEX_APP_SERVER_PROTOCOL_VERSION,
  CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
  runCodexAppServerProtocol,
  type CodexAppServerProtocolConnection,
  type CodexAppServerProtocolReceivedMessage,
  type CodexAppServerProtocolRequest,
} from "../src/provider/codex-app-server.js";
import type { RequestedExecutionSettings } from "../src/runner/types.js";

const WORKSPACE = path.resolve("synthetic-empty-workspace");

test("pins the Codex CLI and generated app-server protocol identity", () => {
  assert.equal(CODEX_APP_SERVER_CLI_VERSION, "0.149.1");
  assert.equal(
    CODEX_APP_SERVER_GENERATED_SCHEMA_SHA256,
    "9b3de71a5a2ffc980b792a18aa8f8dec3f85f48829560222a0264fe494b679a9",
  );
  assert.equal(
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    "codex-app-server-v2-9b3de71a5a2ffc98",
  );
});

test("sends only four extraction inputs and supported requested settings", async () => {
  const connection = new SyntheticConnection("success");
  const result = await runCodexAppServerProtocol(connection, request());
  assert.deepEqual(result, {
    document: syntheticDocument(),
    respondedModel: "synthetic-model",
    effectiveEffort: "medium",
    usage: {
      available: true,
      inputTokens: 11,
      cachedInputTokens: 5,
      cacheWriteInputTokens: 3,
      outputTokens: 7,
      totalTokens: 18,
    },
    stopReason: null,
  });

  const thread = connection.message("thread/start");
  const turn = connection.message("turn/start");
  const initialize = connection.message("initialize");
  assert.equal(thread.params.model, "synthetic-model");
  assert.equal(thread.params.baseInstructions, "synthetic system");
  assert.equal(thread.params.cwd, WORKSPACE);
  assert.equal(thread.params.approvalPolicy, "untrusted");
  assert.equal(thread.params.sandbox, "read-only");
  assert.equal(thread.params.ephemeral, true);
  const config = object(thread.params.config);
  assert.deepEqual(config.features, {
    code_mode_host: false,
    shell_snapshot: false,
    shell_tool: false,
    view_image: false,
  });
  assert.deepEqual(config.agents, { enabled: false });
  assert.deepEqual(config.mcp_servers, {});
  assert.deepEqual(config.hooks, {});
  assert.deepEqual(config.notify, []);
  assert.equal(config.model_reasoning_effort, "medium");
  const capabilities = object(object(initialize.params).capabilities);
  assert.ok(
    requiredArray(capabilities.optOutNotificationMethods).includes(
      "remoteControl/status/changed",
    ),
  );
  assert.ok(
    requiredArray(capabilities.optOutNotificationMethods).includes(
      "account/rateLimits/updated",
    ),
  );
  assert.ok(
    requiredArray(capabilities.optOutNotificationMethods).includes(
      "mcpServer/startupStatus/updated",
    ),
  );
  assert.ok(
    requiredArray(capabilities.optOutNotificationMethods).includes(
      "model/safetyBuffering/updated",
    ),
  );
  assert.ok(
    requiredArray(capabilities.optOutNotificationMethods).includes("warning"),
  );
  assert.deepEqual(turn.params.sandboxPolicy, {
    type: "readOnly",
    networkAccess: false,
  });
  assert.equal(turn.params.model, "synthetic-model");
  assert.equal(turn.params.effort, "medium");
  assert.deepEqual(turn.params.outputSchema, request().schema);
  const inputs = turn.params.input as Array<Record<string, unknown>>;
  assert.deepEqual(inputs[0], {
    type: "text",
    text: "synthetic instruction",
    text_elements: [],
  });
  assert.equal(inputs[1]?.type, "image");
  assert.equal(inputs[1]?.url, "data:image/png;base64,c3ludGhldGljLWltYWdl");
  assert.equal(inputs[1]?.detail, null);
  for (const prohibited of [
    "caseId",
    "documentKind",
    "manifestDigest",
    "inputDigests",
    "provenance",
    "approval",
    "sanitizerRequirement",
    "truth",
    "comparison",
    "attempt",
  ]) {
    assert.equal(Object.hasOwn(thread.params, prohibited), false, `thread.${prohibited}`);
    assert.equal(Object.hasOwn(turn.params, prohibited), false, `turn.${prohibited}`);
  }
});

test("accepts a provider-sized image after its canonical base64 projection", async () => {
  const large = request();
  large.image = {
    mediaType: "image/png",
    bytes: Buffer.alloc(13 * 1024 * 1024, 90),
  };
  const result = await runCodexAppServerProtocol(
    new SyntheticConnection("success"),
    large,
  );
  assert.deepEqual(result.document, syntheticDocument());
});

test("binds thread and turn effort to the requested value", async () => {
  const connection = new SyntheticConnection("success");
  const result = await runCodexAppServerProtocol(
    connection,
    request({ effort: "low" }),
  );
  assert.equal(result.effectiveEffort, "low");
  assert.equal(
    object(connection.message("thread/start").params.config)
      .model_reasoning_effort,
    "low",
  );
});

test("accepts the official CLI vscode session source", async () => {
  const result = await runCodexAppServerProtocol(
    new SyntheticConnection("vscode-source"),
    request(),
  );
  assert.deepEqual(result.document, syntheticDocument());
});

test("omits the thread effort override when the request leaves it unknown", async () => {
  const connection = new SyntheticConnection("success");
  const result = await runCodexAppServerProtocol(
    connection,
    request({ effort: null }),
  );
  assert.equal(result.effectiveEffort, "medium");
  assert.equal(
    Object.hasOwn(
      object(connection.message("thread/start").params.config),
      "model_reasoning_effort",
    ),
    false,
  );
});

test("rejects invalid request values before sending a protocol message", async () => {
  for (const invalid of [
    request({ maxTokens: 128 }),
    { ...request(), workspace: "synthetic-relative" },
    { ...request(), image: { mediaType: "text/plain", bytes: Buffer.from("synthetic") } },
  ]) {
    const connection = new SyntheticConnection("success");
    await assert.rejects(runCodexAppServerProtocol(connection, invalid));
    assert.equal(connection.sent.length, 0);
  }

  const oversizedSchema = {
    ...request(),
    schema: { synthetic: "x".repeat(16 * 1024 * 1024) },
  };
  const oversizedConnection = new SyntheticConnection("success");
  await assert.rejects(
    runCodexAppServerProtocol(oversizedConnection, oversizedSchema),
  );
  assert.equal(oversizedConnection.sent.length, 0);

  const hostile = {} as CodexAppServerProtocolConnection;
  Object.defineProperty(hostile, "send", {
    get: () => {
      throw new Error("synthetic getter canary");
    },
  });
  await assert.rejects(
    runCodexAppServerProtocol(hostile, request()),
    (error: unknown) =>
      error instanceof Error &&
      error.message === "codex app-server protocol failed" &&
      !error.message.includes("canary"),
  );
});

test("fails closed on requests, tools, files, identity drift, and trailing events", async () => {
  for (const mode of [
    "bad-response-id",
    "bad-sandbox",
    "bad-thread-cwd",
    "cli-version-mismatch",
    "instruction-source",
    "thread-notification-before-response",
    "missing-thread-started",
    "thread-snapshot-mismatch",
    "unexpected-thread-source",
    "active-thread",
    "missing-project-id",
    "persistent-thread",
    "turn-started-before-status",
    "missing-turn-started",
    "approval-request",
    "tool-request",
    "file-change",
    "mcp-startup-notification",
    "unexpected-event",
    "trailing-event",
    "raw-response",
    "duplicate-turn-response",
    "incomplete-turn",
    "completion-mismatch",
    "completion-tool-item",
    "invalid-user-content",
    "agent-before-user",
    "event-flood",
    "invalid-json-document",
  ]) {
    const connection = new SyntheticConnection(mode);
    await assert.rejects(
      runCodexAppServerProtocol(connection, request()),
      (error: unknown) =>
        error instanceof Error &&
        error.message === "codex app-server protocol failed" &&
        !error.message.includes("synthetic-secret-canary"),
      mode,
    );
    assert.equal(connection.closed, true, mode);
  }
});

test("rejects missing required nullable generated-schema fields", async () => {
  const cases: Array<{
    mode: string;
    keys: string[];
    select: (message: Record<string, JsonValue>) => Record<string, JsonValue> | undefined;
  }> = [
    {
      mode: "success",
      keys: [
        "forkedFromId",
        "parentThreadId",
        "section",
        "sectionEnteredAt",
        "projectId",
        "recencyAt",
        "path",
        "threadSource",
        "agentNickname",
        "agentRole",
        "gitInfo",
        "name",
      ],
      select: threadResponseTarget,
    },
    {
      mode: "success",
      keys: ["error", "startedAt", "completedAt", "durationMs"],
      select: turnResponseTarget,
    },
    {
      mode: "success",
      keys: ["serviceTier"],
      select: threadStartResultTarget,
    },
    {
      mode: "success",
      keys: ["clientId"],
      select: itemTarget("userMessage"),
    },
    {
      mode: "success",
      keys: ["phase", "memoryCitation", "delivery"],
      select: itemTarget("agentMessage"),
    },
    {
      mode: "reasoning-success",
      keys: ["summary", "content"],
      select: itemTarget("reasoning"),
    },
    {
      mode: "success",
      keys: ["modelContextWindow"],
      select: threadTokenUsageTarget,
    },
  ];

  for (const entry of cases) {
    for (const key of entry.keys) {
      const connection = new RequiredKeyDeletingConnection(
        entry.mode,
        key,
        entry.select,
      );
      await assert.rejects(
        runCodexAppServerProtocol(connection, request()),
        /codex app-server protocol failed/u,
      );
      assert.equal(connection.deleted, true, `${entry.mode}.${key}`);
      assert.equal(connection.closed, true, `${entry.mode}.${key}`);
    }
  }
});

test("bounds active item lifecycles and aggregate received bytes", async () => {
  for (const mode of [
    "active-item-flood",
    "startup-active-item-flood",
    "aggregate-byte-flood",
  ]) {
    const connection = new SyntheticConnection(mode);
    await assert.rejects(
      runCodexAppServerProtocol(connection, request()),
      /codex app-server protocol failed/u,
      mode,
    );
    assert.equal(connection.closed, true, mode);
  }
});

test("snapshots untrusted receive envelopes before normalizing messages", async () => {
  const underReported = await runCodexAppServerProtocol(
    new UnderReportingConnection(),
    request(),
  );
  assert.deepEqual(underReported.document, syntheticDocument());

  const overReported = new OverReportingConnection();
  await assert.rejects(
    runCodexAppServerProtocol(overReported, request()),
    /codex app-server protocol failed/u,
  );
  assert.equal(overReported.messageReads, 0);

  const byteLengthGetter = new ByteLengthGetterConnection();
  await assert.rejects(
    runCodexAppServerProtocol(byteLengthGetter, request()),
    /codex app-server protocol failed/u,
  );
  assert.equal(byteLengthGetter.byteLengthReads, 0);

  const messageGetter = new MessageGetterConnection();
  await assert.rejects(
    runCodexAppServerProtocol(messageGetter, request()),
    /codex app-server protocol failed/u,
  );
  assert.equal(messageGetter.messageReads, 0);
});

test("accepts every fixed turn-start response race while preserving status order", async () => {
  for (const mode of [
    "response-status-started",
    "status-response-started",
    "status-started-response",
    "status-started-user-response",
  ]) {
    const result = await runCodexAppServerProtocol(
      new SyntheticConnection(mode),
      request(),
    );
    assert.deepEqual(result.document, syntheticDocument(), mode);
  }
});

test("sends one best-effort interrupt and closes input when aborted", async () => {
  const connection = new SyntheticConnection("timeout");
  const controller = new AbortController();
  const running = runCodexAppServerProtocol(connection, request(), controller.signal);
  let rejectAccepted!: (error: Error) => void;
  const acceptedTimeout = setTimeout(
    () => rejectAccepted(new Error("synthetic turn was not accepted")),
    1_000,
  );
  await Promise.race([
    connection.turnAccepted,
    new Promise<never>((_resolve, reject) => {
      rejectAccepted = reject;
    }),
  ]);
  clearTimeout(acceptedTimeout);
  await new Promise<void>((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(running);
  assert.equal(connection.closed, true);
  assert.equal(
    connection.sent.filter((message) => message.method === "turn/interrupt").length,
    1,
  );
});

test(
  "keeps protocol cancellation independent of a replaced Array iterator",
  { timeout: 5_000 },
  async () => {
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      Symbol.iterator,
    );
    assert.ok(iteratorDescriptor?.value);
    const connection = new SyntheticConnection("timeout");
    const controller = new AbortController();
    const unhandledRejections: unknown[] = [];
    const recordUnhandledRejection = (reason: unknown): void => {
      unhandledRejections[unhandledRejections.length] = reason;
    };
    process.on("unhandledRejection", recordUnhandledRejection);

    try {
      Object.defineProperty(Array.prototype, Symbol.iterator, {
        configurable: true,
        writable: true,
        value: function* (this: unknown[]): Generator<unknown> {
          if (
            this.length === 2 &&
            this[0] instanceof Promise &&
            this[1] instanceof Promise
          ) {
            yield this[0];
            return;
          }
          for (let index = 0; index < this.length; index += 1) {
            yield this[index];
          }
        },
      });
      const running = runCodexAppServerProtocol(
        connection,
        request(),
        controller.signal,
      );
      await connection.turnAccepted;
      await new Promise<void>((resolve) => setImmediate(resolve));
      controller.abort();
      await assert.rejects(running, /codex app-server protocol failed/u);
      await new Promise<void>((resolve) => setImmediate(resolve));
    } finally {
      Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
      process.off("unhandledRejection", recordUnhandledRejection);
    }

    assert.deepEqual(unhandledRejections, []);
    assert.equal(connection.closed, true);
    assert.equal(
      connection.sent.filter((message) => message.method === "turn/interrupt").length,
      1,
    );
  },
);

test("shared Array iterator mutation cannot skip active flags or required keys", async () => {
  const iteratorDescriptor = Object.getOwnPropertyDescriptor(
    Array.prototype,
    Symbol.iterator,
  );
  const inheritedServiceTier = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "serviceTier",
  );
  assert.ok(iteratorDescriptor?.value);

  try {
    Object.defineProperty(Object.prototype, "serviceTier", {
      configurable: true,
      value: null,
      writable: true,
    });
    Object.defineProperty(Array.prototype, Symbol.iterator, {
      configurable: true,
      writable: true,
      value: function* (this: unknown[]): Generator<unknown> {
        if (
          (this.length === 1 && this[0] === "syntheticUnknownFlag") ||
          this.some((value) => value === "serviceTier")
        ) {
          return;
        }
        for (let index = 0; index < this.length; index += 1) {
          yield this[index];
        }
      },
    });

    const activeFlags = new SyntheticConnection("unknown-active-flag");
    await assert.rejects(
      runCodexAppServerProtocol(activeFlags, request()),
      /codex app-server protocol failed/u,
    );
    assert.equal(activeFlags.closed, true);

    const requiredKeys = new RequiredKeyDeletingConnection(
      "success",
      "serviceTier",
      threadStartResultTarget,
    );
    await assert.rejects(
      runCodexAppServerProtocol(requiredKeys, request()),
      /codex app-server protocol failed/u,
    );
    assert.equal(requiredKeys.deleted, true);
    assert.equal(requiredKeys.closed, true);
  } finally {
    Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
    if (inheritedServiceTier === undefined) {
      delete (Object.prototype as { serviceTier?: unknown }).serviceTier;
    } else {
      Object.defineProperty(Object.prototype, "serviceTier", inheritedServiceTier);
    }
  }
});

test("shared Object.hasOwn mutation cannot supply a required inherited field", async () => {
  const hasOwnDescriptor = Object.getOwnPropertyDescriptor(Object, "hasOwn");
  const inheritedServiceTier = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "serviceTier",
  );
  assert.ok(hasOwnDescriptor?.value);

  try {
    Object.defineProperty(Object.prototype, "serviceTier", {
      configurable: true,
      value: null,
      writable: true,
    });
    Object.defineProperty(Object, "hasOwn", {
      configurable: true,
      value: (value: object, key: PropertyKey) =>
        key === "serviceTier" ||
        Reflect.apply(hasOwnDescriptor.value as (value: object, key: PropertyKey) => boolean, Object, [
          value,
          key,
        ]),
      writable: true,
    });

    const connection = new RequiredKeyDeletingConnection(
      "success",
      "serviceTier",
      threadStartResultTarget,
    );
    await assert.rejects(
      runCodexAppServerProtocol(connection, request()),
      /codex app-server protocol failed/u,
    );
    assert.equal(connection.deleted, true);
    assert.equal(connection.closed, true);
  } finally {
    Object.defineProperty(Object, "hasOwn", hasOwnDescriptor);
    if (inheritedServiceTier === undefined) {
      delete (Object.prototype as { serviceTier?: unknown }).serviceTier;
    } else {
      Object.defineProperty(Object.prototype, "serviceTier", inheritedServiceTier);
    }
  }
});

test("protocol normalization and equality ignore replaced JSON and collection globals", async () => {
  const stringifyDescriptor = Object.getOwnPropertyDescriptor(JSON, "stringify");
  const freezeDescriptor = Object.getOwnPropertyDescriptor(Object, "freeze");
  const mapDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "map");
  const sortDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "sort");
  assert.ok(stringifyDescriptor?.value);
  assert.ok(freezeDescriptor?.value);
  assert.ok(mapDescriptor?.value);
  assert.ok(sortDescriptor?.value);
  const originalStringify = stringifyDescriptor.value as typeof JSON.stringify;
  let injectedStringifyCalls = 0;
  let freezeCalls = 0;
  let mapCalls = 0;
  let sortCalls = 0;
  let success: Awaited<ReturnType<typeof runCodexAppServerProtocol>> | undefined;
  let mismatchRejected = false;

  try {
    Object.defineProperty(JSON, "stringify", {
      configurable: true,
      value(value: unknown, ...arguments_: unknown[]) {
        if (
          typeof value === "object" &&
          value !== null &&
          (value as { method?: unknown }).method === "thread/start"
        ) {
          injectedStringifyCalls += 1;
          return '{"baseInstructions":"synthetic injected"}';
        }
        return Reflect.apply(originalStringify, JSON, [value, ...arguments_]);
      },
      writable: true,
    });
    Object.defineProperty(Object, "freeze", {
      configurable: true,
      value(value: unknown) {
        freezeCalls += 1;
        return value;
      },
      writable: true,
    });
    Object.defineProperty(Array.prototype, "map", {
      configurable: true,
      value() {
        mapCalls += 1;
        return [];
      },
      writable: true,
    });
    Object.defineProperty(Array.prototype, "sort", {
      configurable: true,
      value() {
        sortCalls += 1;
        return this;
      },
      writable: true,
    });

    success = await runCodexAppServerProtocol(
      new SyntheticConnection("success"),
      request(),
    );
    try {
      await runCodexAppServerProtocol(
        new SyntheticConnection("thread-snapshot-mismatch"),
        request(),
      );
    } catch {
      mismatchRejected = true;
    }
  } finally {
    Object.defineProperty(JSON, "stringify", stringifyDescriptor);
    Object.defineProperty(Object, "freeze", freezeDescriptor);
    Object.defineProperty(Array.prototype, "map", mapDescriptor);
    Object.defineProperty(Array.prototype, "sort", sortDescriptor);
  }

  assert.deepEqual(success?.document, syntheticDocument());
  assert.equal(mismatchRejected, true);
  assert.equal(injectedStringifyCalls, 0);
  assert.equal(freezeCalls, 0);
  assert.equal(mapCalls, 0);
  assert.equal(sortCalls, 0);
});

test("waits for a delayed interrupt send before closing input", async () => {
  const connection = new DelayedInterruptConnection();
  const controller = new AbortController();
  const running = runCodexAppServerProtocol(connection, request(), controller.signal);
  await connection.turnAccepted;
  await new Promise<void>((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(running, /codex app-server protocol failed/u);
  assert.equal(connection.closed, true);
  assert.equal(
    connection.sent.filter((message) => message.method === "turn/interrupt").length,
    1,
  );
});

test("keeps unavailable usage unknown and leaves schema validation to its caller", async () => {
  const unavailable = await runCodexAppServerProtocol(
    new SyntheticConnection("usage-unavailable"),
    request(),
  );
  assert.deepEqual(unavailable.usage, { available: false });

  const schemaInvalid = await runCodexAppServerProtocol(
    new SyntheticConnection("schema-invalid-document"),
    request(),
  );
  assert.deepEqual(schemaInvalid.document, { unexpected: true });
});

test("keeps unavailable cache usage details unknown", async () => {
  const nullCacheWrite = await runCodexAppServerProtocol(
    new SyntheticConnection("null-cache-write-usage"),
    request(),
  );
  assert.deepEqual(nullCacheWrite.usage, {
    available: true,
    inputTokens: 11,
    cachedInputTokens: 5,
    cacheWriteInputTokens: null,
    outputTokens: 7,
    totalTokens: 18,
  });

  const inheritedCachedInput = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "cachedInputTokens",
  );
  const inheritedCacheWriteInput = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "cacheWriteInputTokens",
  );
  try {
    Object.defineProperty(Object.prototype, "cachedInputTokens", {
      configurable: true,
      value: 9,
      writable: true,
    });
    Object.defineProperty(Object.prototype, "cacheWriteInputTokens", {
      configurable: true,
      value: 4,
      writable: true,
    });
    const missingCacheDetails = await runCodexAppServerProtocol(
      new SyntheticConnection("missing-cache-usage"),
      request(),
    );
    assert.deepEqual(missingCacheDetails.usage, {
      available: true,
      inputTokens: 11,
      cachedInputTokens: null,
      cacheWriteInputTokens: null,
      outputTokens: 7,
      totalTokens: 18,
    });
  } finally {
    if (inheritedCachedInput === undefined) {
      delete (Object.prototype as { cachedInputTokens?: unknown }).cachedInputTokens;
    } else {
      Object.defineProperty(Object.prototype, "cachedInputTokens", inheritedCachedInput);
    }
    if (inheritedCacheWriteInput === undefined) {
      delete (Object.prototype as { cacheWriteInputTokens?: unknown })
        .cacheWriteInputTokens;
    } else {
      Object.defineProperty(
        Object.prototype,
        "cacheWriteInputTokens",
        inheritedCacheWriteInput,
      );
    }
  }
});

function request(
  overrides: Partial<RequestedExecutionSettings> = {},
): CodexAppServerProtocolRequest {
  const requested: RequestedExecutionSettings = {
    model: "synthetic-model",
    effort: "medium",
    maxTokens: null,
    ...overrides,
  };
  return {
    workspace: WORKSPACE,
    image: { mediaType: "image/png", bytes: Buffer.from("synthetic-image") },
    schema: {
      type: "object",
      additionalProperties: false,
      required: ["documentKind"],
      properties: { documentKind: { const: "synthetic_invoice" } },
    },
    system: "synthetic system",
    instruction: "synthetic instruction",
    requested: { ...requested },
  };
}

class SyntheticConnection implements CodexAppServerProtocolConnection {
  readonly sent: Array<Record<string, JsonValue>> = [];
  closed = false;
  readonly turnAccepted: Promise<void>;
  private readonly mode: string;
  private readonly queue: JsonValue[] = [];
  private receiver:
    | ((value: CodexAppServerProtocolReceivedMessage | undefined) => void)
    | undefined;
  private resolveTurnAccepted!: () => void;

  constructor(mode: string) {
    this.mode = mode;
    this.turnAccepted = new Promise((resolve) => {
      this.resolveTurnAccepted = resolve;
    });
  }

  async send(value: JsonValue): Promise<void> {
    const message = cloneObject(value);
    this.sent.push(message);
    if (message.method === "initialize") {
      this.enqueue({
        id: this.mode === "bad-response-id" ? 77 : requiredValue(message.id),
        result: {
          userAgent: "synthetic-codex-app-server/0.149.1",
          codexHome: WORKSPACE,
          platformFamily: "synthetic",
          platformOs: "synthetic",
        },
      });
      return;
    }
    if (message.method === "thread/start") {
      const params = object(message.params);
      const thread = syntheticThread();
      if (this.mode === "active-thread") {
        thread.status = { type: "active", activeFlags: [] };
        thread.path = "/synthetic/persisted-thread";
      }
      if (this.mode === "bad-thread-cwd") thread.cwd = "/synthetic/other";
      if (this.mode === "cli-version-mismatch") thread.cliVersion = "0.149.0";
      if (this.mode === "missing-project-id") delete thread.projectId;
      if (this.mode === "persistent-thread") thread.ephemeral = false;
      if (this.mode === "vscode-source") thread.source = "vscode";
      if (this.mode === "unexpected-thread-source") thread.source = "cli";
      const response = {
        id: requiredValue(message.id),
        result: {
          thread,
          model: typeof params.model === "string" ? params.model : "synthetic-model",
          modelProvider: "synthetic-provider",
          serviceTier: null,
          cwd: WORKSPACE,
          instructionSources:
            this.mode === "instruction-source" ? ["synthetic-source"] : [],
          approvalPolicy: "untrusted",
          approvalsReviewer: "user",
          sandbox:
            this.mode === "bad-sandbox"
              ? { type: "workspaceWrite", networkAccess: false }
              : { type: "readOnly", networkAccess: false },
          reasoningEffort:
            object(params.config).model_reasoning_effort ?? "medium",
        },
      };
      const notification = {
        method: "thread/started",
        params: {
          thread:
            this.mode === "thread-snapshot-mismatch"
              ? { ...thread, preview: "mismatch" }
              : thread,
        },
      };
      if (this.mode === "thread-notification-before-response") {
        this.enqueue(notification);
        this.enqueue(response);
      } else {
        this.enqueue(response);
        this.enqueue(
          this.mode === "missing-thread-started"
            ? { method: "warning", params: { message: "synthetic" } }
            : notification,
        );
      }
      return;
    }
    if (message.method === "turn/start") {
      const turnParams = object(message.params);
      const sentInput = requiredArray(turnParams.input);
      const userItem = {
        id: "synthetic-user-item",
        type: "userMessage",
        content:
          this.mode === "invalid-user-content"
            ? ([{}] as JsonValue[])
            : sentInput,
        clientId: null,
      };
      const responseTurn = syntheticTurn("inProgress", [], "notLoaded", null);
      const notificationTurn = syntheticTurn("inProgress", [], "notLoaded", 1);
      const response = {
        id: requiredValue(message.id),
        result: { turn: responseTurn },
      };
      const notification = {
        method: "turn/started",
        params: { threadId: "synthetic-thread", turn: notificationTurn },
      };
      const status = {
        method: "thread/status/changed",
        params: {
          threadId: "synthetic-thread",
          status: {
            type: "active",
            activeFlags:
              this.mode === "unknown-active-flag" ? ["syntheticUnknownFlag"] : [],
          },
        },
      };
      if (this.mode === "turn-started-before-status") {
        this.enqueue(notification);
        this.enqueue(response);
        this.enqueue(status);
      } else if (this.mode === "status-response-started") {
        this.enqueue(status);
        this.enqueue(response);
        this.enqueue(notification);
      } else if (this.mode === "status-started-response") {
        this.enqueue(status);
        this.enqueue(notification);
        this.enqueue(response);
      } else if (this.mode === "status-started-user-response") {
        this.enqueue(status);
        this.enqueue(notification);
        this.enqueue(itemStartedWith(userItem));
        this.enqueue(response);
      } else if (this.mode === "startup-active-item-flood") {
        this.enqueue(status);
        this.enqueue(notification);
        this.enqueue(itemStartedWith(userItem));
        this.enqueue(itemCompletedWith(userItem));
        for (let index = 0; index < 17; index += 1) {
          this.enqueue(itemStartedWith(reasoningItem(`synthetic-reasoning-${index}`)));
        }
        return;
      } else if (this.mode === "timeout") {
        this.enqueue(status);
        this.enqueue(notification);
      } else {
        this.enqueue(response);
        this.enqueue(status);
        this.enqueue(
          this.mode === "missing-turn-started"
            ? { method: "warning", params: { message: "synthetic" } }
            : notification,
        );
      }
      if (this.mode === "mcp-startup-notification") {
        this.enqueue({ method: "mcpServer/startupStatus/updated", params: {} });
      }
      if (this.mode === "timeout") return;
      if (this.mode === "approval-request") {
        this.enqueue({
          method: "item/commandExecution/requestApproval",
          id: "synthetic-request",
          params: { threadId: "synthetic-thread", turnId: "synthetic-turn" },
        });
        return;
      }
      if (this.mode === "tool-request" || this.mode === "file-change") {
        this.enqueue(itemStarted(this.mode === "tool-request" ? "commandExecution" : "fileChange"));
        return;
      }
      if (this.mode === "unexpected-event") {
        this.enqueue({ method: "warning", params: { message: "synthetic" } });
        return;
      }
      if (this.mode === "incomplete-turn") {
        this.enqueue(turnCompleted([]));
        return;
      }
      if (this.mode === "event-flood") {
        for (let index = 0; index <= 4096; index += 1) {
          this.enqueue({
            method: "thread/status/changed",
            params: { threadId: "synthetic-thread", status: { type: "idle" } },
          });
        }
        return;
      }
      if (this.mode === "duplicate-turn-response") {
        this.enqueue(response);
        return;
      }
      const text =
        this.mode === "invalid-json-document"
          ? "synthetic-secret-canary invalid json"
          : JSON.stringify(
              this.mode === "schema-invalid-document"
                ? { unexpected: true }
                : syntheticDocument(),
            );
      const completedItem = agentItem(text);
      if (this.mode === "agent-before-user") {
        this.enqueue(itemStarted("agentMessage"));
      } else {
        if (this.mode !== "status-started-user-response") {
          this.enqueue(itemStartedWith(userItem));
        }
        this.enqueue(itemCompletedWith(userItem));
        if (this.mode === "active-item-flood") {
          for (let index = 0; index < 17; index += 1) {
            this.enqueue(itemStartedWith(reasoningItem(`synthetic-reasoning-${index}`)));
          }
          return;
        }
        if (this.mode === "aggregate-byte-flood") {
          for (let index = 0; index < 5; index += 1) {
            this.enqueue({
              method: "thread/status/changed",
              params: {
                threadId: "synthetic-thread",
                status: { type: "idle", syntheticIndex: index },
              },
            });
          }
          return;
        }
        if (this.mode === "reasoning-success") {
          const reasoning = reasoningItem("synthetic-reasoning");
          this.enqueue(itemStartedWith(reasoning));
          this.enqueue(itemCompletedWith(reasoning));
        }
        this.enqueue(itemStarted("agentMessage"));
      }
      this.enqueue({
        method: "item/completed",
        params: {
          threadId: "synthetic-thread",
          turnId: "synthetic-turn",
          completedAtMs: 2,
          item: completedItem,
        },
      });
      if (this.mode !== "usage-unavailable") {
        this.enqueue({
          method: "thread/tokenUsage/updated",
          params: {
            threadId: "synthetic-thread",
            turnId: "synthetic-turn",
            tokenUsage: {
              total:
                this.mode === "null-cache-write-usage"
                  ? {
                      ...object(tokenUsage(11, 7)),
                      cacheWriteInputTokens: null,
                    }
                  : this.mode === "missing-cache-usage"
                    ? withoutKeys(tokenUsage(11, 7), [
                        "cachedInputTokens",
                        "cacheWriteInputTokens",
                      ])
                  : tokenUsage(11, 7),
              last: tokenUsage(11, 7),
              modelContextWindow: 1024,
            },
          },
        });
      }
      if (this.mode === "raw-response") {
        const notification = {
          method: "rawResponse/completed",
          params: {
            threadId: "synthetic-thread",
            turnId: "synthetic-turn",
            responseId: "synthetic-response",
            usage: tokenUsage(11, 7),
          },
        };
        this.enqueue(notification);
      }
      const finalItems =
        this.mode === "completion-mismatch"
          ? [agentItem(JSON.stringify({ mismatch: true }))]
          : this.mode === "completion-tool-item"
            ? [{ id: "synthetic-tool", type: "commandExecution" }]
            : [completedItem];
      this.enqueue(turnCompleted(finalItems));
      if (this.mode === "trailing-event") {
        this.enqueue({ method: "warning", params: { message: "synthetic trailing" } });
      }
      return;
    }
  }

  async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const queued = this.queue.shift();
    if (queued !== undefined) {
      this.observe(queued);
      return this.received(queued);
    }
    if (this.closed) return undefined;
    return new Promise((resolve) => {
      this.receiver = resolve;
    });
  }

  closeInput(): void {
    this.closed = true;
    const receiver = this.receiver;
    this.receiver = undefined;
    receiver?.(undefined);
  }

  message(method: string): { params: Record<string, JsonValue> } {
    const message = this.sent.find((candidate) => candidate.method === method);
    assert.ok(message);
    return { params: object(message.params) };
  }

  private enqueue(value: JsonValue): void {
    const receiver = this.receiver;
    if (receiver === undefined) this.queue.push(value);
    else {
      this.receiver = undefined;
      this.observe(value);
      receiver(this.received(value));
    }
  }

  private observe(value: JsonValue): void {
    if (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value) &&
      (value.id === 3 || value.method === "turn/started")
    ) {
      this.resolveTurnAccepted();
    }
  }

  private received(value: JsonValue): CodexAppServerProtocolReceivedMessage {
    const message = object(value);
    const status =
      message.method === "thread/status/changed"
        ? nestedObject(message, ["params", "status"])
        : undefined;
    return {
      message: value,
      byteLength:
        this.mode === "aggregate-byte-flood" && status?.type === "idle"
          ? CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES
          : Buffer.byteLength(JSON.stringify(value), "utf8") + 1,
    };
  }
}

class RequiredKeyDeletingConnection extends SyntheticConnection {
  deleted = false;
  private readonly key: string;
  private readonly select: (
    message: Record<string, JsonValue>,
  ) => Record<string, JsonValue> | undefined;

  constructor(
    mode: string,
    key: string,
    select: (
      message: Record<string, JsonValue>,
    ) => Record<string, JsonValue> | undefined,
  ) {
    super(mode);
    this.key = key;
    this.select = select;
  }

  override async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const received = await super.receive();
    if (received === undefined || this.deleted) return received;
    const snapshot = cloneObject(received.message);
    const target = this.select(snapshot);
    if (target !== undefined && Object.hasOwn(target, this.key)) {
      delete target[this.key];
      this.deleted = true;
    }
    return { ...received, message: snapshot };
  }
}

class UnderReportingConnection extends SyntheticConnection {
  constructor() {
    super("success");
  }

  override async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const received = await super.receive();
    return received === undefined ? undefined : { ...received, byteLength: 1 };
  }
}

class OverReportingConnection extends SyntheticConnection {
  messageReads = 0;

  constructor() {
    super("success");
  }

  override async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const received = await super.receive();
    if (received === undefined) return undefined;
    const message = {};
    Object.defineProperty(message, "synthetic", {
      enumerable: true,
      get: () => {
        this.messageReads += 1;
        return "synthetic";
      },
    });
    return {
      message: message as JsonValue,
      byteLength: CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES * 4 + 1,
    };
  }
}

class ByteLengthGetterConnection extends SyntheticConnection {
  byteLengthReads = 0;

  constructor() {
    super("success");
  }

  override async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const received = await super.receive();
    if (received === undefined) return undefined;
    const envelope = { message: received.message } as {
      message: JsonValue;
      byteLength: number;
    };
    Object.defineProperty(envelope, "byteLength", {
      enumerable: true,
      get: () => {
        this.byteLengthReads += 1;
        return this.byteLengthReads === 1 ? 1 : Number.NaN;
      },
    });
    return envelope;
  }
}

class MessageGetterConnection extends SyntheticConnection {
  messageReads = 0;

  constructor() {
    super("success");
  }

  override async receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined> {
    const received = await super.receive();
    if (received === undefined) return undefined;
    const envelope = { byteLength: received.byteLength } as {
      message: JsonValue;
      byteLength: number;
    };
    Object.defineProperty(envelope, "message", {
      enumerable: true,
      get: () => {
        this.messageReads += 1;
        envelope.byteLength = Number.NaN;
        return received.message;
      },
    });
    return envelope;
  }
}

class DelayedInterruptConnection extends SyntheticConnection {
  constructor() {
    super("timeout");
  }

  override async send(value: JsonValue): Promise<void> {
    if (object(value).method === "turn/interrupt") {
      await new Promise<void>((resolve) => setImmediate(resolve));
      if (this.closed) throw new Error("synthetic input closed before interrupt");
    }
    await super.send(value);
  }
}

function itemStarted(type: string): JsonValue {
  return {
    method: "item/started",
    params: {
      threadId: "synthetic-thread",
      turnId: "synthetic-turn",
      startedAtMs: 1,
      item:
        type === "agentMessage"
          ? agentItem("")
          : { id: "synthetic-item", type },
    },
  };
}

function turnCompleted(items: JsonValue[]): JsonValue {
  return {
    method: "turn/completed",
    params: {
      threadId: "synthetic-thread",
      turn: syntheticTurn("completed", items, "summary", 1),
    },
  };
}

function syntheticThread(): Record<string, JsonValue> {
  return {
    id: "synthetic-thread",
    sessionId: "synthetic-session",
    forkedFromId: null,
    parentThreadId: null,
    preview: "",
    ephemeral: true,
    section: null,
    sectionEnteredAt: null,
    projectId: null,
    modelProvider: "synthetic-provider",
    createdAt: 1,
    updatedAt: 1,
    recencyAt: null,
    status: { type: "idle" },
    path: null,
    cwd: WORKSPACE,
    cliVersion: CODEX_APP_SERVER_CLI_VERSION,
    source: "appServer",
    threadSource: "structured_vision_bench",
    agentNickname: null,
    agentRole: null,
    gitInfo: null,
    name: null,
    turns: [],
  };
}

function syntheticTurn(
  status: "inProgress" | "completed",
  items: JsonValue[],
  itemsView: "notLoaded" | "summary",
  startedAt: number | null,
): Record<string, JsonValue> {
  return {
    id: "synthetic-turn",
    items,
    itemsView,
    status,
    error: null,
    startedAt,
    completedAt: status === "completed" ? 2 : null,
    durationMs: status === "completed" ? 1 : null,
  };
}

function itemStartedWith(item: JsonValue): JsonValue {
  return {
    method: "item/started",
    params: {
      threadId: "synthetic-thread",
      turnId: "synthetic-turn",
      startedAtMs: 1,
      item,
    },
  };
}

function itemCompletedWith(item: JsonValue): JsonValue {
  return {
    method: "item/completed",
    params: {
      threadId: "synthetic-thread",
      turnId: "synthetic-turn",
      completedAtMs: 2,
      item,
    },
  };
}

function agentItem(text: string): Record<string, JsonValue> {
  return {
    id: "synthetic-item",
    type: "agentMessage",
    text,
    phase: "final_answer",
    memoryCitation: null,
    delivery: null,
  };
}

function reasoningItem(id: string, summary = "synthetic reasoning"): Record<string, JsonValue> {
  return {
    id,
    type: "reasoning",
    summary: [summary],
    content: [],
  };
}

function tokenUsage(inputTokens: number, outputTokens: number): JsonValue {
  return {
    inputTokens,
    cachedInputTokens: 5,
    cacheWriteInputTokens: 3,
    outputTokens,
    reasoningOutputTokens: 0,
    totalTokens: inputTokens + outputTokens,
  };
}

function withoutKeys(value: JsonValue, keys: readonly string[]): JsonValue {
  const copy = cloneObject(value);
  for (const key of keys) delete copy[key];
  return copy;
}

function syntheticDocument(): JsonValue {
  return {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-APP-SERVER-001",
    totalAmount: 0,
  };
}

function cloneObject(value: JsonValue): Record<string, JsonValue> {
  return object(structuredClone(value));
}

function threadResponseTarget(
  message: Record<string, JsonValue>,
): Record<string, JsonValue> | undefined {
  return nestedObject(message, ["result", "thread"]);
}

function turnResponseTarget(
  message: Record<string, JsonValue>,
): Record<string, JsonValue> | undefined {
  return nestedObject(message, ["result", "turn"]);
}

function threadStartResultTarget(
  message: Record<string, JsonValue>,
): Record<string, JsonValue> | undefined {
  const result = nestedObject(message, ["result"]);
  return result !== undefined && Object.hasOwn(result, "thread") ? result : undefined;
}

function itemTarget(
  type: string,
): (message: Record<string, JsonValue>) => Record<string, JsonValue> | undefined {
  return (message) => {
    const item = nestedObject(message, ["params", "item"]);
    return item?.type === type ? item : undefined;
  };
}

function threadTokenUsageTarget(
  message: Record<string, JsonValue>,
): Record<string, JsonValue> | undefined {
  return nestedObject(message, ["params", "tokenUsage"]);
}

function nestedObject(
  value: Record<string, JsonValue>,
  keys: readonly string[],
): Record<string, JsonValue> | undefined {
  let current: JsonValue = value;
  for (const key of keys) {
    if (
      typeof current !== "object" ||
      current === null ||
      Array.isArray(current) ||
      !Object.hasOwn(current, key)
    ) {
      return undefined;
    }
    current = current[key] as JsonValue;
  }
  if (typeof current !== "object" || current === null || Array.isArray(current)) {
    return undefined;
  }
  return current;
}

function object(value: JsonValue | undefined): Record<string, JsonValue> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, JsonValue>;
}

function requiredArray(value: JsonValue | undefined): JsonValue[] {
  assert.ok(Array.isArray(value));
  return structuredClone(value);
}

function requiredValue(value: JsonValue | undefined): JsonValue {
  assert.notEqual(value, undefined);
  return value as JsonValue;
}
