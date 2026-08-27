import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { JsonValue } from "../src/bundle/json.js";
import {
  CODEX_APP_SERVER_CLI_VERSION,
  CODEX_APP_SERVER_GENERATED_SCHEMA_SHA256,
  CODEX_APP_SERVER_PROTOCOL_VERSION,
  runCodexAppServerProtocol,
  type CodexAppServerProtocolConnection,
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
    "instruction-source",
    "thread-notification-before-response",
    "missing-thread-started",
    "thread-snapshot-mismatch",
    "active-thread",
    "missing-project-id",
    "turn-started-before-status",
    "missing-turn-started",
    "approval-request",
    "tool-request",
    "file-change",
    "unexpected-event",
    "trailing-event",
    "raw-response",
    "duplicate-turn-response",
    "incomplete-turn",
    "completion-mismatch",
    "completion-tool-item",
    "invalid-user-content",
    "agent-before-user",
    "null-cache-write-usage",
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
  private receiver: ((value: JsonValue | undefined) => void) | undefined;
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
      if (this.mode === "missing-project-id") delete thread.projectId;
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
          status: { type: "active", activeFlags: [] },
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

  async receive(): Promise<JsonValue | undefined> {
    const queued = this.queue.shift();
    if (queued !== undefined) {
      this.observe(queued);
      return queued;
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
      receiver(value);
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

function tokenUsage(inputTokens: number, outputTokens: number): JsonValue {
  return {
    inputTokens,
    cachedInputTokens: 0,
    cacheWriteInputTokens: 0,
    outputTokens,
    reasoningOutputTokens: 0,
    totalTokens: inputTokens + outputTokens,
  };
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
