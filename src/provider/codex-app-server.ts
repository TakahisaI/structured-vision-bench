import path from "node:path";

import {
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  stringifyJsonValue,
  type JsonValue,
} from "../bundle/json.js";
import { MAX_PROVIDER_INPUT_BYTES } from "../bundle/validate-bundle.js";
import {
  addAbortSignalListener,
  isAbortSignalAborted,
  removeAbortSignalListener,
} from "./abort-signal-intrinsics.js";
import {
  createIntrinsicPromise,
  raceIntrinsicPromises,
} from "./promise-intrinsics.js";
import type { ProviderUsage, RequestedExecutionSettings } from "../runner/types.js";

export const CODEX_APP_SERVER_CLI_VERSION = "0.149.1";
export const CODEX_APP_SERVER_GENERATED_SCHEMA_SHA256 =
  "9b3de71a5a2ffc980b792a18aa8f8dec3f85f48829560222a0264fe494b679a9";
export const CODEX_APP_SERVER_PROTOCOL_VERSION =
  "codex-app-server-v2-9b3de71a5a2ffc98";

const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const SAFE_MEDIA_TYPE_PATTERN = /^[A-Za-z0-9!#$&^_.+/-]+$/u;
const MAX_WORKSPACE_PATH_LENGTH = 4096;
const MAX_FINAL_DOCUMENT_BYTES = 16 * 1024 * 1024;
// A maximum-sized instruction may expand sixfold when JSON escapes control
// bytes, and the matching user item also contains the base64 image. Keep the
// per-value bound above that canonical worst case instead of sizing it from
// the raw provider inputs.
export const CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES = 128 * 1024 * 1024;
const MAX_PROTOCOL_RECEIVED_BYTES = 512 * 1024 * 1024;
const MAX_PROTOCOL_EVENTS = 4096;
const MAX_ACTIVE_ITEMS = 16;
const CLIENT_NAME = "structured_vision_bench";
const CLIENT_TITLE = "structured-vision-bench";
const CLIENT_VERSION = "1";
const applyIntrinsic = Reflect.apply;
const arrayIsArrayIntrinsic = Array.isArray;
const arraySortIntrinsic = Array.prototype.sort;
const bindIntrinsic = Function.prototype.bind;
const bufferByteLengthIntrinsic = Buffer.byteLength;
const bufferFromIntrinsic = Buffer.from;
const bufferIsBufferIntrinsic = Buffer.isBuffer;
const bufferToStringIntrinsic = Buffer.prototype.toString;
const freezeIntrinsic = Object.freeze;
const objectGetOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const mapDeleteIntrinsic = Map.prototype.delete;
const mapGetIntrinsic = Map.prototype.get;
const mapHasIntrinsic = Map.prototype.has;
const mapSetIntrinsic = Map.prototype.set;
const mapSizeGetterIntrinsic = objectGetOwnPropertyDescriptorIntrinsic(
  Map.prototype,
  "size",
)!.get!;
const MapIntrinsic = Map;
const mathMaxIntrinsic = Math.max;
const mathMinIntrinsic = Math.min;
const numberIsSafeIntegerIntrinsic = Number.isSafeInteger;
const objectHasOwnIntrinsic = Object.hasOwn;
const objectKeysIntrinsic = Object.keys;
const pathIsAbsoluteIntrinsic = path.isAbsolute;
const regExpTestIntrinsic = RegExp.prototype.test;
const stringStartsWithIntrinsic = String.prototype.startsWith;
const uint8ArrayFillIntrinsic = Uint8Array.prototype.fill;
const typedArrayPrototypeIntrinsic = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetterIntrinsic = objectGetOwnPropertyDescriptorIntrinsic(
  typedArrayPrototypeIntrinsic,
  "byteLength",
)!.get!;

export type CodexAppServerProtocolConnection = Readonly<{
  send(message: JsonValue): Promise<void>;
  receive(): Promise<CodexAppServerProtocolReceivedMessage | undefined>;
  closeInput(): void;
}>;

export type CodexAppServerProtocolReceivedMessage = Readonly<{
  message: JsonValue;
  byteLength: number;
}>;

export type CodexAppServerProtocolRequest = {
  workspace: string;
  image: { mediaType: string; bytes: Buffer };
  schema: JsonValue;
  system: string;
  instruction: string;
  requested: RequestedExecutionSettings;
};

export type CodexAppServerProtocolResult = {
  document: JsonValue;
  respondedModel: string | null;
  effectiveEffort: string | null;
  usage: ProviderUsage;
  stopReason: null;
};

type ProtocolUsage = {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
};

type RequestSnapshot = Readonly<{
  workspace: string;
  imageDataUrl: string;
  schema: JsonValue;
  system: string;
  instruction: string;
  requested: RequestedExecutionSettings;
}>;

type ThreadState = {
  threadId: string;
  respondedModel: string;
  effectiveEffort: string | null;
  snapshot: JsonValue;
};

type ProtocolReceiveBudget = { remainingBytes: number };

type ActiveItemType = "userMessage" | "reasoning" | "agentMessage";

type TurnAccumulator = {
  finalText: string | undefined;
  usage: ProtocolUsage | undefined;
  userMessageSeen: boolean;
  finalItem: JsonValue | undefined;
  activeItems: Map<string, ActiveItemType>;
  result:
    | Omit<CodexAppServerProtocolResult, "stopReason">
    | undefined;
};

/** Runs the pinned one-thread, one-turn app-server message state machine. */
export async function runCodexAppServerProtocol(
  connectionValue: CodexAppServerProtocolConnection,
  requestValue: CodexAppServerProtocolRequest,
  signal?: AbortSignal,
): Promise<CodexAppServerProtocolResult> {
  let imageCopy: Buffer | undefined;
  let connection: CodexAppServerProtocolConnection | undefined;
  let threadId: string | undefined;
  let turnId: string | undefined;
  let inputClosed = false;
  let abortCleanup: Promise<void> | undefined;
  const closeInput = (): void => {
    if (inputClosed) return;
    inputClosed = true;
    try {
      connection?.closeInput();
    } catch {
      // The stable protocol failure below owns this boundary.
    }
  };
  const beginAbortCleanup = (): Promise<void> => {
    abortCleanup ??= (async () => {
      try {
        if (connection !== undefined && threadId !== undefined && turnId !== undefined) {
          await connection.send({
            method: "turn/interrupt",
            id: 99,
            params: { threadId, turnId },
          });
        }
      } catch {
        // Connection teardown remains authoritative.
      } finally {
        closeInput();
      }
    })();
    return abortCleanup;
  };
  const abort = (): void => void beginAbortCleanup();
  try {
    assertActive(signal);
    connection = snapshotConnection(connectionValue);
    const snapshot = snapshotRequest(requestValue);
    imageCopy = snapshot.imageCopy;
    const receiveBudget: ProtocolReceiveBudget = {
      remainingBytes: MAX_PROTOCOL_RECEIVED_BYTES,
    };
    addAbortSignalListener(signal, abort);

    await send(connection, initializeRequest(), signal);
    validateInitializeResponse(await nextResponse(connection, 1, receiveBudget, signal));
    await send(connection, { method: "initialized" }, signal);
    await send(
      connection,
      {
        method: "thread/start",
        id: 2,
        params: {
          model: snapshot.request.requested.model,
          cwd: snapshot.request.workspace,
          approvalPolicy: "untrusted",
          sandbox: "read-only",
          config: threadConfig(snapshot.request.requested.effort),
          baseInstructions: snapshot.request.system,
          developerInstructions: null,
          ephemeral: true,
          threadSource: CLIENT_NAME,
        },
      },
      signal,
    );
    const threadResponse = await nextResponse(connection, 2, receiveBudget, signal);
    const thread = validateThreadStartResponse(
      threadResponse,
      snapshot.request.workspace,
      snapshot.request.requested.effort,
    );
    threadId = thread.threadId;
    validateThreadStartedNotification(
      await nextNotification(connection, "thread/started", receiveBudget, signal),
      snapshot.request.workspace,
      thread,
    );

    const turnInput: JsonValue[] = [
      { type: "text", text: snapshot.request.instruction, text_elements: [] },
      { type: "image", url: snapshot.request.imageDataUrl, detail: null },
    ];
    await send(
      connection,
      {
        method: "turn/start",
        id: 3,
        params: {
          threadId,
          input: turnInput,
          cwd: snapshot.request.workspace,
          approvalPolicy: "untrusted",
          sandboxPolicy: { type: "readOnly", networkAccess: false },
          model: snapshot.request.requested.model,
          effort: snapshot.request.requested.effort,
          outputSchema: snapshot.request.schema,
        },
      },
      signal,
    );
    const turnStart = await collectTurnStart(
      connection,
      threadId,
      (knownTurnId) => {
        if (turnId !== undefined && turnId !== knownTurnId) throw new Error();
        turnId = knownTurnId;
      },
      thread,
      turnInput,
      receiveBudget,
      signal,
    );
    turnId = turnStart.turnId;
    const result = await consumeTurn(
      connection,
      threadId,
      turnId,
      thread,
      turnInput,
      turnStart.accumulator,
      turnStart.messageCount,
      receiveBudget,
      signal,
    );
    connection.closeInput();
    inputClosed = true;
    if ((await receive(connection, receiveBudget, signal)) !== undefined) throw new Error();
    return { ...result, stopReason: null };
  } catch {
    if (abortCleanup !== undefined || isAbortSignalAborted(signal)) {
      await (abortCleanup ?? beginAbortCleanup());
    } else {
      closeInput();
    }
    throw new Error("codex app-server protocol failed");
  } finally {
    removeAbortSignalListener(signal, abort);
    if (imageCopy !== undefined) {
      applyIntrinsic(uint8ArrayFillIntrinsic, imageCopy, [0]);
    }
  }
}

function snapshotConnection(
  value: CodexAppServerProtocolConnection,
): CodexAppServerProtocolConnection {
  if (value === null || typeof value !== "object") throw new Error();
  const sendValue = value.send;
  const receiveValue = value.receive;
  const closeValue = value.closeInput;
  if (
    typeof sendValue !== "function" ||
    typeof receiveValue !== "function" ||
    typeof closeValue !== "function"
  ) {
    throw new Error();
  }
  return freezeIntrinsic({
    send: applyIntrinsic(bindIntrinsic, sendValue, [value]) as (
      message: JsonValue,
    ) => Promise<void>,
    receive: applyIntrinsic(bindIntrinsic, receiveValue, [value]) as () => Promise<
      CodexAppServerProtocolReceivedMessage | undefined
    >,
    closeInput: applyIntrinsic(bindIntrinsic, closeValue, [value]) as () => void,
  });
}

function snapshotRequest(value: CodexAppServerProtocolRequest): {
  request: RequestSnapshot;
  imageCopy: Buffer;
} {
  const request = requiredObject(value);
  const image = requiredObject(request.image);
  const requested = snapshotRequested(request.requested);
  if (requested.maxTokens !== null) throw new Error();
  const workspace = request.workspace;
  const mediaType = boundedMediaType(image.mediaType);
  const bytes = image.bytes;
  if (
    typeof workspace !== "string" ||
    workspace.length === 0 ||
    workspace.length > MAX_WORKSPACE_PATH_LENGTH ||
    !pathIsAbsoluteIntrinsic(workspace) ||
    !applyIntrinsic(stringStartsWithIntrinsic, mediaType, ["image/"]) ||
    !bufferIsBufferIntrinsic(bytes) ||
    (applyIntrinsic(typedArrayByteLengthGetterIntrinsic, bytes, []) as number) >
      MAX_PROVIDER_INPUT_BYTES ||
    typeof request.system !== "string" ||
    bufferByteLengthIntrinsic(request.system, "utf8") > MAX_PROVIDER_INPUT_BYTES ||
    typeof request.instruction !== "string" ||
    bufferByteLengthIntrinsic(request.instruction, "utf8") > MAX_PROVIDER_INPUT_BYTES
  ) {
    throw new Error();
  }
  const imageCopy = bufferFromIntrinsic(bytes);
  try {
    return {
      request: freezeIntrinsic({
        workspace,
        imageDataUrl: `data:${mediaType};base64,${applyIntrinsic(
          bufferToStringIntrinsic,
          imageCopy,
          ["base64"],
        ) as string}`,
        schema: normalizeJsonValue(
          request.schema,
          "codex app-server schema",
          MAX_PROVIDER_INPUT_BYTES,
        ),
        system: request.system,
        instruction: request.instruction,
        requested,
      }),
      imageCopy,
    };
  } catch {
    applyIntrinsic(uint8ArrayFillIntrinsic, imageCopy, [0]);
    throw new Error();
  }
}

function initializeRequest(): JsonValue {
  return {
    method: "initialize",
    id: 1,
    params: {
      clientInfo: { name: CLIENT_NAME, title: CLIENT_TITLE, version: CLIENT_VERSION },
      capabilities: {
        experimentalApi: false,
        requestAttestation: false,
        mcpServerOpenaiFormElicitation: false,
        optOutNotificationMethods: [
          "account/rateLimits/updated",
          "mcpServer/startupStatus/updated",
          "model/safetyBuffering/updated",
          "remoteControl/status/changed",
          "warning",
          "item/agentMessage/delta",
          "item/reasoning/summaryTextDelta",
          "item/reasoning/summaryPartAdded",
          "item/reasoning/textDelta",
        ],
        extensions: null,
      },
    },
  };
}

function threadConfig(effort: string | null): JsonValue {
  const config: Record<string, JsonValue> = {
    analytics: { enabled: false },
    web_search: "disabled",
    tools: { web_search: false },
    features: {
      code_mode_host: false,
      shell_snapshot: false,
      shell_tool: false,
      view_image: false,
    },
    agents: { enabled: false },
    mcp_servers: {},
    hooks: {},
    notify: [],
    instructions: null,
    developer_instructions: null,
  };
  if (effort !== null) config.model_reasoning_effort = effort;
  return config;
}

async function consumeTurn(
  connection: CodexAppServerProtocolConnection,
  threadId: string,
  turnId: string,
  thread: { respondedModel: string | null; effectiveEffort: string | null },
  expectedUserContent: JsonValue[],
  accumulator: TurnAccumulator,
  initialMessageCount: number,
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<Omit<CodexAppServerProtocolResult, "stopReason">> {
  let eventCount = initialMessageCount;
  for (;;) {
    if (accumulator.result !== undefined) return accumulator.result;
    eventCount += 1;
    if (eventCount > MAX_PROTOCOL_EVENTS) throw new Error();
    const message = await nextMessage(connection, receiveBudget, signal);
    applyTurnNotification(
      accumulator,
      message,
      threadId,
      turnId,
      thread,
      expectedUserContent,
    );
  }
}

function createTurnAccumulator(): TurnAccumulator {
  return {
    finalText: undefined,
    usage: undefined,
    userMessageSeen: false,
    finalItem: undefined,
    activeItems: new MapIntrinsic(),
    result: undefined,
  };
}

function applyTurnNotification(
  accumulator: TurnAccumulator,
  message: Record<string, JsonValue>,
  threadId: string,
  turnId: string,
  thread: { respondedModel: string | null; effectiveEffort: string | null },
  expectedUserContent: JsonValue[],
): void {
  if (accumulator.result !== undefined || objectHasOwnIntrinsic(message, "id")) {
    throw new Error();
  }
  const method = message.method;
  const params = requiredObject(message.params);
  if (method === "turn/completed") {
    if (params.threadId !== threadId || accumulator.activeItems.size !== 0) {
      throw new Error();
    }
    const turn = validateTurnSnapshot(params.turn, "completed", "summary");
    if (
      turn.id !== turnId ||
      accumulator.finalText === undefined ||
      accumulator.finalItem === undefined ||
      !accumulator.userMessageSeen ||
      !jsonEqual(turn.items, [accumulator.finalItem]) ||
      bufferByteLengthIntrinsic(accumulator.finalText, "utf8") > MAX_FINAL_DOCUMENT_BYTES
    ) {
      throw new Error();
    }
    accumulator.result = {
      document: normalizeJsonValue(
        parseJson(accumulator.finalText, "codex app-server result"),
        "codex app-server result",
        MAX_FINAL_DOCUMENT_BYTES,
      ),
      respondedModel: thread.respondedModel,
      effectiveEffort: thread.effectiveEffort,
      usage:
        accumulator.usage === undefined
          ? { available: false }
          : {
              available: true,
              inputTokens: accumulator.usage.inputTokens,
              outputTokens: accumulator.usage.outputTokens,
              totalTokens: accumulator.usage.totalTokens,
            },
    };
    return;
  }
  if (method === "thread/status/changed") {
    if (params.threadId !== threadId) throw new Error();
    validateThreadStatus(params.status);
    return;
  }
  if (method === "item/started") {
    assertTurnIdentity(params, threadId, turnId);
    nonnegativeInteger(params.startedAtMs);
    const snapshot = validateSafeItem(params.item, expectedUserContent);
    const item = requiredObject(snapshot);
    const itemId = safeLabel(item.id);
    const itemType = safeItemType(item.type);
    if (itemType !== "userMessage" && !accumulator.userMessageSeen) {
      throw new Error();
    }
    if (itemType === "userMessage" && accumulator.userMessageSeen) {
      throw new Error();
    }
    if (
      applyIntrinsic(mapHasIntrinsic, accumulator.activeItems, [itemId]) ||
      (applyIntrinsic(mapSizeGetterIntrinsic, accumulator.activeItems, []) as number) >=
        MAX_ACTIVE_ITEMS
    ) {
      throw new Error();
    }
    applyIntrinsic(mapSetIntrinsic, accumulator.activeItems, [itemId, itemType]);
    return;
  }
  if (method === "item/completed") {
    assertTurnIdentity(params, threadId, turnId);
    nonnegativeInteger(params.completedAtMs);
    const snapshot = validateSafeItem(params.item, expectedUserContent);
    const item = requiredObject(snapshot);
    const itemId = safeLabel(item.id);
    const itemType = safeItemType(item.type);
    const started = applyIntrinsic(mapGetIntrinsic, accumulator.activeItems, [itemId]);
    if (started === undefined || started !== itemType) throw new Error();
    applyIntrinsic(mapDeleteIntrinsic, accumulator.activeItems, [itemId]);
    if (itemType === "userMessage") {
      if (accumulator.userMessageSeen) throw new Error();
      accumulator.userMessageSeen = true;
      return;
    }
    if (itemType === "reasoning") return;
    if (
      typeof item.text !== "string" ||
      (item.phase !== null && item.phase !== "final_answer") ||
      accumulator.finalText !== undefined
    ) {
      throw new Error();
    }
    accumulator.finalText = item.text;
    accumulator.finalItem = snapshot;
    return;
  }
  if (method === "thread/tokenUsage/updated") {
    assertTurnIdentity(params, threadId, turnId);
    const tokenUsage = requiredObject(params.tokenUsage);
    assertRequiredKeys(tokenUsage, ["total", "last", "modelContextWindow"]);
    accumulator.usage = snapshotProtocolUsage(tokenUsage.total);
    snapshotProtocolUsage(tokenUsage.last);
    if (
      tokenUsage.modelContextWindow !== null &&
      !isTokenCount(tokenUsage.modelContextWindow)
    ) {
      throw new Error();
    }
    return;
  }
  throw new Error();
}

function validateInitializeResponse(message: Record<string, JsonValue>): void {
  const result = requiredObject(message.result);
  if (
    typeof result.userAgent !== "string" ||
    typeof result.codexHome !== "string" ||
    !pathIsAbsoluteIntrinsic(result.codexHome) ||
    typeof result.platformFamily !== "string" ||
    typeof result.platformOs !== "string"
  ) {
    throw new Error();
  }
}

function validateThreadStartResponse(
  message: Record<string, JsonValue>,
  workspace: string,
  requestedEffort: string | null,
): ThreadState {
  const result = requiredObject(message.result);
  assertRequiredKeys(result, [
    "thread",
    "model",
    "modelProvider",
    "serviceTier",
    "cwd",
    "instructionSources",
    "approvalPolicy",
    "approvalsReviewer",
    "sandbox",
    "reasoningEffort",
  ]);
  const threadSnapshot = validateThreadSnapshot(result.thread, workspace);
  const thread = requiredObject(threadSnapshot);
  const sandbox = requiredObject(result.sandbox);
  const respondedModel = safeLabel(result.model);
  const modelProvider = safeLabel(result.modelProvider);
  const effectiveEffort = requiredNullableSafeLabel(result, "reasoningEffort");
  if (
    result.cwd !== workspace ||
    result.approvalPolicy !== "untrusted" ||
    result.approvalsReviewer !== "user" ||
    !arrayIsArrayIntrinsic(result.instructionSources) ||
    result.instructionSources.length !== 0 ||
    sandbox.type !== "readOnly" ||
    sandbox.networkAccess !== false ||
    thread.modelProvider !== modelProvider ||
    (requestedEffort !== null && effectiveEffort !== requestedEffort) ||
    (result.serviceTier !== null && !isSafeLabel(result.serviceTier))
  ) {
    throw new Error();
  }
  return {
    threadId: safeLabel(thread.id),
    respondedModel,
    effectiveEffort,
    snapshot: threadSnapshot,
  };
}

function validateTurnStartResponse(message: Record<string, JsonValue>): {
  turnId: string;
} {
  const turn = validateTurnSnapshot(
    requiredObject(message.result).turn,
    "inProgress",
    "notLoaded",
  );
  if (turn.items.length !== 0 || turn.startedAt !== null) throw new Error();
  return { turnId: turn.id };
}

function validateThreadStartedNotification(
  message: Record<string, JsonValue>,
  workspace: string,
  expected: ThreadState,
): void {
  const snapshot = validateThreadSnapshot(
    requiredObject(message.params).thread,
    workspace,
  );
  if (!jsonEqual(snapshot, expected.snapshot)) throw new Error();
}

async function collectTurnStart(
  connection: CodexAppServerProtocolConnection,
  threadId: string,
  onTurnId: (turnId: string) => void,
  thread: { respondedModel: string | null; effectiveEffort: string | null },
  expectedUserContent: JsonValue[],
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<{
  turnId: string;
  accumulator: TurnAccumulator;
  messageCount: number;
}> {
  let responseTurnId: string | undefined;
  let startedTurnId: string | undefined;
  let statusSeen = false;
  const accumulator = createTurnAccumulator();
  for (let count = 1; count <= MAX_PROTOCOL_EVENTS; count += 1) {
    const message = await nextMessage(connection, receiveBudget, signal);
    if (objectHasOwnIntrinsic(message, "id")) {
      if (responseTurnId !== undefined) throw new Error();
      responseTurnId = validateTurnStartResponseMessage(message);
      onTurnId(responseTurnId);
    } else {
      const params = requiredObject(message.params);
      if (message.method === "thread/status/changed" && !statusSeen) {
        if (startedTurnId !== undefined || params.threadId !== threadId) {
          throw new Error();
        }
        validateThreadStatus(params.status, "active");
        statusSeen = true;
      } else if (message.method === "turn/started" && startedTurnId === undefined) {
        if (!statusSeen || params.threadId !== threadId) throw new Error();
        const turn = validateTurnSnapshot(params.turn, "inProgress", "notLoaded");
        if (turn.items.length !== 0 || turn.startedAt === null) throw new Error();
        startedTurnId = turn.id;
        onTurnId(startedTurnId);
      } else {
        if (startedTurnId === undefined) throw new Error();
        applyTurnNotification(
          accumulator,
          message,
          threadId,
          startedTurnId,
          thread,
          expectedUserContent,
        );
      }
    }
    if (
      responseTurnId !== undefined &&
      startedTurnId !== undefined &&
      responseTurnId === startedTurnId
    ) {
      return {
        turnId: responseTurnId,
        accumulator,
        messageCount: count,
      };
    }
    if (
      responseTurnId !== undefined &&
      startedTurnId !== undefined &&
      responseTurnId !== startedTurnId
    ) {
      throw new Error();
    }
  }
  throw new Error();
}

function validateTurnStartResponseMessage(
  message: Record<string, JsonValue>,
): string {
  if (
    message.id !== 3 ||
    objectHasOwnIntrinsic(message, "error") ||
    !objectHasOwnIntrinsic(message, "result")
  ) {
    throw new Error();
  }
  return validateTurnStartResponse(message).turnId;
}

function validateThreadSnapshot(value: unknown, workspace: string): JsonValue {
  const thread = requiredObject(value);
  assertRequiredKeys(thread, [
    "id",
    "sessionId",
    "forkedFromId",
    "parentThreadId",
    "preview",
    "ephemeral",
    "section",
    "sectionEnteredAt",
    "projectId",
    "modelProvider",
    "createdAt",
    "updatedAt",
    "recencyAt",
    "status",
    "path",
    "cwd",
    "cliVersion",
    "source",
    "threadSource",
    "agentNickname",
    "agentRole",
    "gitInfo",
    "name",
    "turns",
  ]);
  safeLabel(thread.id);
  safeLabel(thread.sessionId);
  safeLabel(thread.modelProvider);
  nonnegativeInteger(thread.createdAt);
  nonnegativeInteger(thread.updatedAt);
  validateThreadStatus(thread.status, "idle");
  if (
    thread.cwd !== workspace ||
    thread.ephemeral !== true ||
    thread.cliVersion !== CODEX_APP_SERVER_CLI_VERSION ||
    (thread.source !== "appServer" && thread.source !== "vscode") ||
    thread.threadSource !== CLIENT_NAME ||
    typeof thread.preview !== "string" ||
    bufferByteLengthIntrinsic(thread.preview, "utf8") > MAX_PROVIDER_INPUT_BYTES ||
    !arrayIsArrayIntrinsic(thread.turns) ||
    thread.turns.length !== 0 ||
    thread.projectId !== null ||
    thread.forkedFromId !== null ||
    thread.parentThreadId !== null ||
    thread.path !== null ||
    !nullableString(thread.name) ||
    !nullableString(thread.agentNickname) ||
    !nullableString(thread.agentRole) ||
    !nullableInteger(thread.recencyAt) ||
    !nullableInteger(thread.sectionEnteredAt) ||
    thread.section !== null ||
    thread.gitInfo !== null
  ) {
    throw new Error();
  }
  return normalizeJsonValue(
    thread,
    "codex app-server thread",
    MAX_PROVIDER_INPUT_BYTES,
  );
}

function validateThreadStatus(
  value: unknown,
  expected?: "idle" | "active",
): void {
  const status = requiredObject(value);
  if (status.type === "idle") {
    if (expected === "active") throw new Error();
    return;
  }
  if (status.type !== "active" || !arrayIsArrayIntrinsic(status.activeFlags)) {
    throw new Error();
  }
  if (expected === "idle") throw new Error();
  for (let index = 0; index < status.activeFlags.length; index += 1) {
    const flag = status.activeFlags[index];
    if (flag !== "waitingOnApproval" && flag !== "waitingOnUserInput") {
      throw new Error();
    }
  }
}

function validateTurnSnapshot(
  value: unknown,
  expectedStatus: "inProgress" | "completed",
  expectedItemsView: "notLoaded" | "summary",
): { id: string; items: JsonValue[]; startedAt: number | null } {
  const turn = requiredObject(value);
  assertRequiredKeys(turn, [
    "id",
    "items",
    "itemsView",
    "status",
    "error",
    "startedAt",
    "completedAt",
    "durationMs",
  ]);
  const id = safeLabel(turn.id);
  if (
    turn.status !== expectedStatus ||
    !arrayIsArrayIntrinsic(turn.items) ||
    turn.itemsView !== expectedItemsView ||
    turn.error !== null ||
    !nullableInteger(turn.startedAt) ||
    !nullableInteger(turn.completedAt) ||
    !nullableInteger(turn.durationMs)
  ) {
    throw new Error();
  }
  if (
    expectedStatus === "inProgress" &&
    (turn.completedAt !== null || turn.durationMs !== null)
  ) {
    throw new Error();
  }
  const items: JsonValue[] = [];
  for (let index = 0; index < turn.items.length; index += 1) {
    items[index] = validateSafeItem(turn.items[index]);
  }
  return {
    id,
    items,
    startedAt: turn.startedAt as number | null,
  };
}

function validateSafeItem(
  value: unknown,
  expectedUserContent?: JsonValue[],
): JsonValue {
  const item = requiredObject(value);
  safeLabel(item.id);
  const type = safeItemType(item.type);
  if (type === "userMessage") {
    assertRequiredKeys(item, ["type", "id", "clientId", "content"]);
    if (
      !arrayIsArrayIntrinsic(item.content) ||
      expectedUserContent === undefined ||
      !jsonEqual(item.content, expectedUserContent) ||
      !nullableString(item.clientId)
    ) {
      throw new Error();
    }
  } else if (type === "reasoning") {
    assertRequiredKeys(item, ["type", "id", "summary", "content"]);
    validateStringArray(item.summary);
    validateStringArray(item.content);
  } else {
    assertRequiredKeys(item, [
      "type",
      "id",
      "text",
      "phase",
      "memoryCitation",
      "delivery",
    ]);
    if (
      typeof item.text !== "string" ||
      (item.phase !== null &&
        item.phase !== "commentary" &&
        item.phase !== "final_answer") ||
      item.memoryCitation !== null ||
      item.delivery !== null
    ) {
      throw new Error();
    }
  }
  return normalizeJsonValue(
    item,
    "codex app-server item",
    CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
  );
}

function validateStringArray(value: unknown): void {
  if (!arrayIsArrayIntrinsic(value)) throw new Error();
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== "string") throw new Error();
  }
}

function jsonEqual(left: JsonValue, right: JsonValue): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function canonicalJson(value: JsonValue): string {
  if (arrayIsArrayIntrinsic(value)) {
    let source = "[";
    for (let index = 0; index < value.length; index += 1) {
      if (index !== 0) source += ",";
      source += canonicalJson(value[index]!);
    }
    return `${source}]`;
  }
  if (isJsonObject(value)) {
    const keys = objectKeysIntrinsic(value);
    applyIntrinsic(arraySortIntrinsic, keys, []);
    let source = "{";
    for (let index = 0; index < keys.length; index += 1) {
      if (index !== 0) source += ",";
      const key = keys[index]!;
      source += `${stringifyJsonValue(key)}:${canonicalJson(value[key] as JsonValue)}`;
    }
    return `${source}}`;
  }
  return stringifyJsonValue(value);
}

async function nextResponse(
  connection: CodexAppServerProtocolConnection,
  id: number,
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<Record<string, JsonValue>> {
  const message = await nextMessage(connection, receiveBudget, signal);
  if (
    message.id !== id ||
    objectHasOwnIntrinsic(message, "error") ||
    !objectHasOwnIntrinsic(message, "result")
  ) {
    throw new Error();
  }
  return message;
}

async function nextNotification(
  connection: CodexAppServerProtocolConnection,
  method: string,
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<Record<string, JsonValue>> {
  const message = await nextMessage(connection, receiveBudget, signal);
  if (objectHasOwnIntrinsic(message, "id") || message.method !== method) throw new Error();
  return message;
}

async function nextMessage(
  connection: CodexAppServerProtocolConnection,
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<Record<string, JsonValue>> {
  const value = await receive(connection, receiveBudget, signal);
  if (!isJsonObject(value)) throw new Error();
  return value;
}

async function send(
  connection: CodexAppServerProtocolConnection,
  message: JsonValue,
  signal: AbortSignal | undefined,
): Promise<void> {
  assertActive(signal);
  const snapshot = normalizeJsonValue(message, "codex app-server request");
  await raceAbort(connection.send(snapshot), signal);
  assertActive(signal);
}

async function receive(
  connection: CodexAppServerProtocolConnection,
  receiveBudget: ProtocolReceiveBudget,
  signal: AbortSignal | undefined,
): Promise<JsonValue | undefined> {
  assertActive(signal);
  const received = await raceAbort(connection.receive(), signal);
  assertActive(signal);
  if (received === undefined) return undefined;
  if (receiveBudget.remainingBytes < 1) throw new Error();
  if (
    received === null ||
    typeof received !== "object" ||
    arrayIsArrayIntrinsic(received)
  ) {
    throw new Error();
  }
  const byteLengthProperty = objectGetOwnPropertyDescriptorIntrinsic(
    received,
    "byteLength",
  );
  const messageProperty = objectGetOwnPropertyDescriptorIntrinsic(received, "message");
  if (
    byteLengthProperty === undefined ||
    !("value" in byteLengthProperty) ||
    messageProperty === undefined ||
    !("value" in messageProperty)
  ) {
    throw new Error();
  }
  const reportedByteLength = byteLengthProperty.value as unknown;
  if (
    !numberIsSafeIntegerIntrinsic(reportedByteLength) ||
    typeof reportedByteLength !== "number" ||
    reportedByteLength < 1 ||
    reportedByteLength > receiveBudget.remainingBytes
  ) {
    throw new Error();
  }
  const snapshot = normalizeJsonValue(
    messageProperty.value,
    "codex app-server message",
    mathMinIntrinsic(
      CODEX_APP_SERVER_PROTOCOL_VALUE_LIMIT_BYTES,
      receiveBudget.remainingBytes,
    ),
  );
  const chargedBytes = mathMaxIntrinsic(
    reportedByteLength,
    bufferByteLengthIntrinsic(stringifyJsonValue(snapshot), "utf8"),
  );
  if (chargedBytes > receiveBudget.remainingBytes) throw new Error();
  receiveBudget.remainingBytes -= chargedBytes;
  return snapshot;
}

function snapshotRequested(value: unknown): RequestedExecutionSettings {
  const requested = requiredObject(value);
  const model = requiredNullableSafeLabel(requested, "model");
  const effort = requiredNullableSafeLabel(requested, "effort");
  if (!objectHasOwnIntrinsic(requested, "maxTokens")) throw new Error();
  const maxTokens = requested.maxTokens;
  if (
    maxTokens !== null &&
    (!numberIsSafeIntegerIntrinsic(maxTokens) || typeof maxTokens !== "number" || maxTokens < 1)
  ) {
    throw new Error();
  }
  return freezeIntrinsic({ model, effort, maxTokens });
}

function snapshotProtocolUsage(value: unknown): ProtocolUsage {
  const usage = requiredObject(value);
  assertRequiredKeys(usage, [
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
    "reasoningOutputTokens",
    "totalTokens",
  ]);
  const inputTokens = usage.inputTokens;
  const cachedInputTokens = usage.cachedInputTokens;
  const cacheWriteInputTokens = usage.cacheWriteInputTokens;
  const outputTokens = usage.outputTokens;
  const reasoningOutputTokens = usage.reasoningOutputTokens;
  const totalTokens = usage.totalTokens;
  if (
    !isTokenCount(inputTokens) ||
    !isTokenCount(cachedInputTokens) ||
    !isTokenCount(cacheWriteInputTokens) ||
    !isTokenCount(outputTokens) ||
    !isTokenCount(reasoningOutputTokens) ||
    !isTokenCount(totalTokens) ||
    totalTokens < inputTokens + outputTokens
  ) {
    throw new Error();
  }
  return { inputTokens, outputTokens, totalTokens };
}

function assertTurnIdentity(
  params: Record<string, JsonValue>,
  threadId: string,
  turnId: string,
): void {
  if (params.threadId !== threadId || params.turnId !== turnId) throw new Error();
}

function safeItemType(value: unknown): "userMessage" | "reasoning" | "agentMessage" {
  if (value === "userMessage" || value === "reasoning" || value === "agentMessage") {
    return value;
  }
  throw new Error();
}

function safeLabel(value: unknown): string {
  if (!isSafeLabel(value)) throw new Error();
  return value;
}

function requiredObject(value: unknown): Record<string, JsonValue> {
  if (!isJsonObject(value)) throw new Error();
  return value;
}

function assertRequiredKeys(
  object: Record<string, JsonValue>,
  keys: readonly string[],
): void {
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    if (!objectHasOwnIntrinsic(object, key)) throw new Error();
  }
}

function boundedMediaType(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 127 ||
    !applyIntrinsic(regExpTestIntrinsic, SAFE_MEDIA_TYPE_PATTERN, [value])
  ) {
    throw new Error();
  }
  return value;
}

function nullableSafeLabel(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return safeLabel(value);
}

function requiredNullableSafeLabel(
  object: Record<string, JsonValue>,
  key: string,
): string | null {
  if (!objectHasOwnIntrinsic(object, key)) throw new Error();
  return nullableSafeLabel(object[key]);
}

function nonnegativeInteger(value: unknown): number {
  if (!isTokenCount(value)) throw new Error();
  return value;
}

function nullableInteger(value: unknown): boolean {
  return value === null || isTokenCount(value);
}

function nullableString(value: unknown): boolean {
  return value === null || typeof value === "string";
}

function isSafeLabel(value: unknown): value is string {
  return (
    typeof value === "string" &&
    applyIntrinsic(regExpTestIntrinsic, SAFE_LABEL_PATTERN, [value])
  );
}

function isTokenCount(value: unknown): value is number {
  return typeof value === "number" && numberIsSafeIntegerIntrinsic(value) && value >= 0;
}

function assertActive(signal: AbortSignal | undefined): void {
  if (isAbortSignalAborted(signal)) throw new Error();
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  assertActive(signal);
  let rejectAbort!: (error: Error) => void;
  const aborted = createIntrinsicPromise<never>((_resolve, reject) => {
    rejectAbort = reject;
  });
  const abort = (): void => rejectAbort(new Error());
  addAbortSignalListener(signal, abort);
  try {
    return await raceIntrinsicPromises(promise, aborted);
  } finally {
    removeAbortSignalListener(signal, abort);
  }
}
