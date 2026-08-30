import { spawn } from "node:child_process";
import path from "node:path";
import {
  appendFile,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { createInterface } from "node:readline";

type JsonObject = Record<string, unknown>;

const [mode = "success", capturePath = "", canaryPath = "", ...command] =
  process.argv.slice(2);

if (command[0] === "app-server") {
  if (mode === "ancestor-config") {
    const root = path.dirname(await realpath(process.cwd()));
    await mkdir(path.join(root, ".git"));
    await writeFile(path.join(root, "AGENTS.md"), "synthetic ancestor instruction\n");
  }
  const overrides = await captureProcessBoundary(command);
  if (mode === "crash-descendant") {
    const descendant = spawnDescendant();
    await appendCapture({ descendantPid: descendant.pid });
    process.exit(7);
  }
  if (mode === "success-descendant") {
    const descendant = spawnDescendant();
    await appendCapture({ descendantPid: descendant.pid });
  }
  if (mode === "crash") process.exit(7);
  if (mode === "stderr-overflow") {
    process.stderr.write("x".repeat(2 * 1024 * 1024));
    await hangForever();
  }
  if (mode === "stdout-overflow") {
    process.stdout.write("x".repeat(2048));
    await hangForever();
  }
  if (mode === "malformed") {
    process.stdout.write("{synthetic malformed}\n");
    await hangForever();
  }
  if (mode === "unterminated") {
    process.stdout.write('{"synthetic":true}');
    process.exit(0);
  }
  if (mode === "hang" || mode === "cancel") {
    const descendant = spawnDescendant();
    await appendCapture({ descendantPid: descendant.pid });
    await hangForever();
  }
  await runProtocol(overrides);
} else {
  process.exit(9);
}

async function hangForever(): Promise<never> {
  setInterval(() => undefined, 1000);
  return await new Promise<never>(() => undefined);
}

async function captureProcessBoundary(arguments_: string[]): Promise<Map<string, string>> {
  const overrides = new Map<string, string>();
  for (let index = 0; index < arguments_.length; index += 1) {
    if (arguments_[index] === "-c") {
      const override = arguments_[index + 1];
      if (override === undefined) process.exit(8);
      const equals = override.indexOf("=");
      overrides.set(override.slice(0, equals), override.slice(equals + 1));
      index += 1;
    }
  }
  const catalogSetting = overrides.get("model_catalog_json");
  if (catalogSetting === undefined) process.exit(8);
  const catalogPath = JSON.parse(catalogSetting) as string;
  const catalog = JSON.parse(await readFile(catalogPath, "utf8")) as JsonObject;
  const model = object(array(catalog.models)[0]);
  const canonicalCwd = await realpath(process.cwd());
  const root = canonicalCwd.replace(/[\\/]workspace$/u, "");
  const workspaceStat = await stat(canonicalCwd);
  const rootStat = await stat(root);
  await appendCapture({
    phase: "app-server",
    root,
    cwd: canonicalCwd,
    rootMode: rootStat.mode & 0o777,
    workspaceMode: workspaceStat.mode & 0o777,
    workspaceEntries: await readdir(canonicalCwd),
    environmentKeys: Object.keys(process.env).sort(),
    parentCanary: process.env.SVBENCH_PARENT_CANARY ?? null,
    allowedCanary: process.env.SVBENCH_ALLOWED_CANARY ?? null,
    ancestorCanary:
      await readFile(path.join(root, "AGENTS.md"), "utf8").catch(() => null),
    isolation: {
      home: await isWithinRoot(process.env.HOME, root),
      codexHome: await isWithinRoot(process.env.CODEX_HOME, root),
      config: await isWithinRoot(process.env.XDG_CONFIG_HOME, root),
      cache: await isWithinRoot(process.env.XDG_CACHE_HOME, root),
      path: await isWithinRoot(process.env.PATH, root),
    },
    disabledFeatures: arguments_
      .flatMap((entry, index) => (entry === "--disable" ? [arguments_[index + 1]] : []))
      .filter((entry): entry is string => entry !== undefined),
    overrides: Object.fromEntries(overrides),
    catalogModel: {
      slug: model.slug,
      shellType: model.shell_type,
      applyPatch: model.apply_patch_tool_type,
      toolMode: model.tool_mode,
      multiAgent: model.multi_agent_version,
      experimentalTools: model.experimental_supported_tools,
      skills: model.include_skills_usage_instructions,
      plugins: model.include_plugin_usage_instructions,
      apps: model.include_apps_usage_instructions,
      search: model.supports_search_tool,
      nodeReplDisabled: model.node_repl_disabled,
    },
  });
  return overrides;
}

async function isWithinRoot(value: string | undefined, root: string): Promise<boolean> {
  if (value === undefined) return false;
  const relative = path.relative(root, await realpath(value));
  return (
    relative.length > 0 &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

async function runProtocol(overrides: ReadonlyMap<string, string>): Promise<void> {
  const lines = createInterface({ input: process.stdin });
  for await (const line of lines) {
    const message = JSON.parse(line) as JsonObject;
    if (message.method === "initialize") {
      const response = {
        id: message.id,
        result: {
          userAgent: "synthetic-codex-app-server/0.149.1",
          codexHome: process.env.CODEX_HOME,
          platformFamily: "synthetic",
          platformOs: "synthetic",
        },
      };
      if (mode === "fragmented-initialize") {
        for (const byte of Buffer.from(`${JSON.stringify(response)}\n`)) {
          process.stdout.write(Buffer.of(byte));
        }
      } else {
        send(response);
      }
    } else if (message.method === "thread/start") {
      const params = object(message.params);
      await appendCapture({ threadStart: params });
      const thread = syntheticThread(String(params.cwd));
      send({
        id: message.id,
        result: {
          thread,
          model: params.model,
          modelProvider: "synthetic-provider",
          serviceTier: null,
          cwd: params.cwd,
          instructionSources:
            mode === "ancestor-config" &&
            (overrides.get("project_root_markers") !== "[]" ||
              overrides.get("project_doc_max_bytes") !== "0")
              ? ["synthetic-ancestor-instruction"]
              : [],
          approvalPolicy: "untrusted",
          approvalsReviewer: "user",
          sandbox: { type: "readOnly", networkAccess: false },
          reasoningEffort: object(params.config).model_reasoning_effort ?? null,
        },
      });
      send({ method: "thread/started", params: { thread } });
    } else if (message.method === "turn/start") {
      const params = object(message.params);
      await appendCapture({ turnStart: params });
      send({
        id: message.id,
        result: { turn: syntheticTurn("inProgress", [], "notLoaded", null) },
      });
      send({
        method: "thread/status/changed",
        params: {
          threadId: "synthetic-thread",
          status: { type: "active", activeFlags: [] },
        },
      });
      if (mode === "cancel-turn") {
        const descendant = spawnDescendant();
        await appendCapture({ ready: true, descendantPid: descendant.pid });
        continue;
      }
      send({
        method: "turn/started",
        params: {
          threadId: "synthetic-thread",
          turn: syntheticTurn("inProgress", [], "notLoaded", 1),
        },
      });
      if (mode.startsWith("tool-")) {
        send({
          method:
            mode === "tool-approval"
              ? "item/commandExecution/requestApproval"
              : "item/started",
          id: mode === "tool-approval" ? "synthetic-request" : undefined,
          params: {
            threadId: "synthetic-thread",
            turnId: "synthetic-turn",
            startedAtMs: 1,
            item: {
              id: "synthetic-tool",
              type: toolItemType(mode),
              path: canaryPath,
              command: canaryPath,
            },
          },
        });
        await new Promise(() => undefined);
      }
      const userItem = {
        id: "synthetic-user",
        type: "userMessage",
        content: params.input,
        clientId: null,
      };
      send(itemEvent("started", userItem));
      send(itemEvent("completed", userItem));
      const finalItem = {
        id: "synthetic-final",
        type: "agentMessage",
        text: JSON.stringify(
          mode === "provider-success" ||
            mode === "provider-success-no-usage" ||
            mode === "provider-sanitizer-raw"
            ? {
                documentKind: "synthetic_invoice",
                invoiceNumber:
                  mode === "provider-sanitizer-raw"
                    ? "SYNTHETIC-RAW-PROVIDER-ONLY"
                    : "INV-SYNTH-PROVIDER",
                issuedAt: "2031-02-03",
                currency: "JPY",
                lines: [
                  {
                    lineNo: 1,
                    description: "Synthetic service",
                    quantity: 1,
                    unitPrice: 0,
                    amount: 0,
                  },
                ],
                totalAmount: 0,
              }
            : { documentKind: "synthetic_invoice", totalAmount: 0 },
        ),
        phase: "final_answer",
        memoryCitation: null,
        delivery: null,
      };
      send(itemEvent("started", { ...finalItem, text: "" }));
      send(itemEvent("completed", finalItem));
      if (mode !== "provider-success-no-usage") {
        send({
          method: "thread/tokenUsage/updated",
          params: {
            threadId: "synthetic-thread",
            turnId: "synthetic-turn",
            tokenUsage: {
              total: usage(),
              last: usage(),
              modelContextWindow: 1024,
            },
          },
        });
      }
      send({
        method: "turn/completed",
        params: {
          threadId: "synthetic-thread",
          turn: syntheticTurn("completed", [finalItem], "summary", 1),
        },
      });
    } else if (message.method === "turn/interrupt") {
      await appendCapture({ interrupt: message.params });
      send({ id: message.id, result: {} });
    }
  }
}

function spawnDescendant(): ReturnType<typeof spawn> {
  const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  descendant.unref();
  return descendant;
}

function syntheticThread(cwd: string): JsonObject {
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
    cwd,
    cliVersion: mode === "version-mismatch" ? "0.149.0" : "0.149.1",
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
  status: string,
  items: unknown[],
  itemsView: string,
  startedAt: number | null,
): JsonObject {
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

function itemEvent(state: "started" | "completed", item: JsonObject): JsonObject {
  return {
    method: `item/${state}`,
    params: {
      threadId: "synthetic-thread",
      turnId: "synthetic-turn",
      [state === "started" ? "startedAtMs" : "completedAtMs"]: 1,
      item,
    },
  };
}

function usage(): JsonObject {
  return {
    inputTokens: 11,
    cachedInputTokens: 0,
    cacheWriteInputTokens: 0,
    outputTokens: 7,
    reasoningOutputTokens: 0,
    totalTokens: 18,
  };
}

function toolItemType(value: string): string {
  return (
    {
      "tool-shell": "commandExecution",
      "tool-apply-patch": "fileChange",
      "tool-view-image": "mcpToolCall",
      "tool-code-mode": "dynamicToolCall",
      "tool-child-turn": "collabAgentToolCall",
    }[value] ?? "commandExecution"
  );
}

function send(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function appendCapture(value: unknown): Promise<void> {
  if (capturePath.length > 0) await appendFile(capturePath, `${JSON.stringify(value)}\n`);
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) process.exit(8);
  return value as JsonObject;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) process.exit(8);
  return value;
}

if (capturePath.length > 0 && command[0] !== "app-server") {
  await writeFile(capturePath, "", { flag: "a" });
}
