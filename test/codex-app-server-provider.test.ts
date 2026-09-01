import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CODEX_APP_SERVER_PROVIDER_ID,
  CODEX_APP_SERVER_PROVIDER_IMPLEMENTATION_VERSION,
  CODEX_APP_SERVER_PROVIDER_ROUTE,
  createCodexAppServerProvider,
  type CodexAppServerTransportRevalidator,
} from "../src/provider/codex-app-server-provider.js";
import { CODEX_APP_SERVER_PROTOCOL_VERSION } from "../src/provider/codex-app-server.js";
import { readAttempt } from "../src/runner/attempt.js";
import { RunnerError } from "../src/runner/errors.js";
import {
  computeCaseInputIdentity,
  createSanitizerRequirementDecision,
  type SanitizerRequirementSettings,
} from "../src/runner/identity.js";
import { runBundle } from "../src/runner/run.js";
import type {
  ApprovalGate,
  ApprovalRequest,
  ApprovalResponse,
  ApprovalSettings,
  ProviderAdapterContext,
  ProviderModelRequest,
} from "../src/runner/types.js";

const FIXTURE = path.join(
  process.cwd(),
  ".tmp",
  "build",
  "test",
  "support",
  "fake-codex-app-server.js",
);
const BUNDLE = path.join(process.cwd(), "fixtures", "synthetic", "invoice-basic");
const PHASE = "development";

test("runs one approved app-server transport and preserves upstream metadata", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    let revalidations = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        revalidations += 1;
        return approval;
      },
    });
    assert.equal(provider.id, CODEX_APP_SERVER_PROVIDER_ID);
    assert.equal(provider.route, CODEX_APP_SERVER_PROVIDER_ROUTE);
    assert.equal(
      provider.implementationVersion,
      CODEX_APP_SERVER_PROVIDER_IMPLEMENTATION_VERSION,
    );
    assert.equal(provider.protocolVersion, CODEX_APP_SERVER_PROTOCOL_VERSION);

    const prepared = await provider.prepareTransport!(direct.approval);
    const response = await provider.invoke(direct.request, direct.context);
    assert.deepEqual(prepared, direct.approval);
    assert.deepEqual(response.approval, direct.approval);
    assert.equal(response.respondedModel, "synthetic-model");
    assert.equal(response.effectiveEffort, "medium");
    assert.deepEqual(response.usage, {
      available: true,
      inputTokens: 11,
      cachedInputTokens: 5,
      cacheWriteInputTokens: 3,
      outputTokens: 7,
      totalTokens: 18,
    });
    assert.equal(response.stopReason, null);
    assert.deepEqual(direct.reads, { image: 1, schema: 1, system: 1, instruction: 1 });
    assert.equal(revalidations, 2);
    assert.equal(await appServerStarts(capture), 1);
    const hostedMessages = (await readCapture(capture)).filter(
      (record) => record.threadStart !== undefined || record.turnStart !== undefined,
    );
    const hostedWire = JSON.stringify(hostedMessages);
    for (const prohibited of [
      direct.context.caseId,
      direct.context.provenance.promptVersion,
      direct.approval.gateId,
      direct.approval.runtimeBindingIdentity,
      direct.approval.approvedScopeIdentity,
      direct.approval.requirementDecisionDigest,
    ]) {
      assert.equal(hostedWire.includes(prohibited), false, prohibited);
    }

    await assert.rejects(
      provider.invoke(direct.request, direct.context),
      stableProviderFailure,
    );
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("validates and snapshots the public factory configuration", async () => {
  const invalid = [
    null,
    {},
    { process: { executable: "relative" }, revalidateTransport: async () => syntheticApproval() },
    {
      process: { executable: process.execPath, codexHome: "relative" },
      revalidateTransport: async () => syntheticApproval(),
    },
    { process: { executable: process.execPath }, revalidateTransport: null },
    {
      process: { executable: process.execPath, envAllowlist: ["HOME"] },
      revalidateTransport: async () => syntheticApproval(),
    },
  ];
  for (const value of invalid) {
    assert.throws(
      () =>
        createCodexAppServerProvider(
          value as Parameters<typeof createCodexAppServerProvider>[0],
        ),
      (error: unknown) =>
        error instanceof Error &&
        error.message === "codex app-server provider configuration is invalid",
    );
  }

  await withFixture("provider-success", async ({ capture, options }) => {
    const arguments_ = [...options.executableArguments];
    const provider = createCodexAppServerProvider({
      process: { ...options, executableArguments: arguments_ },
      revalidateTransport: async (approval) => approval,
    });
    arguments_[0] = path.join(tmpdir(), "synthetic-mutated-entry.mjs");
    const direct = directInvocation();
    await provider.prepareTransport!(direct.approval);
    await provider.invoke(direct.request, direct.context);
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("rejects a counterfeit AbortSignal without calling its methods or retaining lifecycle state", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => approval,
    });
    await provider.prepareTransport!(direct.approval);
    let listenerCalls = 0;
    const signal = {
      aborted: false,
      addEventListener(): void {
        listenerCalls += 1;
      },
      removeEventListener(): void {
        listenerCalls += 1;
      },
    } as unknown as AbortSignal;
    await assert.rejects(
      provider.invoke(direct.request, direct.context, signal),
      stableProviderFailure,
    );
    await provider.prepareTransport!(direct.approval);
    assert.equal(listenerCalls, 0);
    assert.equal(await appServerStarts(capture), 0);
  });
});

test("rejects a transparent wrapper that loses the fixed cleanup capability", async () => {
  await withFixture("provider-success", async ({ capture, options, root }) => {
    const requirement = syntheticRequirement();
    let revalidations = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        revalidations += 1;
        return approval;
      },
    });
    const wrapped = new Proxy(provider, {});
    await assert.rejects(
      runBundle({
        bundleDirectory: BUNDLE,
        attemptRoot: path.join(root, "attempts"),
        provider: wrapped,
        phase: PHASE,
        requestedModel: "synthetic-model",
        requestedEffort: "medium",
        maxTokens: null,
        sanitizerRequirement: requirement,
        approval: approvalSettings(requirement),
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_invalid",
    );
    assert.equal(revalidations, 0);
    assert.equal(await appServerStarts(capture), 0);
  });
});

test("fails closed before process and input access without one exact active approval", async (t) => {
  for (const mode of [
    "missing",
    "denied",
    "expired",
    "prepare-mismatch",
    "context-mismatch",
    "requirement-mismatch",
  ]) {
    await t.test(mode, async () => {
      await withFixture("provider-success", async ({ capture, options }) => {
        const direct = directInvocation();
        const revalidateTransport: CodexAppServerTransportRevalidator = async (approval) =>
          mode === "prepare-mismatch"
            ? { ...approval, runtimeBindingIdentity: "synthetic-changed-runtime" }
            : approval;
        const provider = createCodexAppServerProvider({
          process: options,
          revalidateTransport,
        });
        if (mode !== "missing") {
          const preparedApproval =
            mode === "denied"
              ? { ...direct.approval, approved: false }
              : mode === "expired"
                ? { ...direct.approval, expiresAt: "2020-01-01T00:00:00Z" }
                : direct.approval;
          if (mode === "denied" || mode === "expired" || mode === "prepare-mismatch") {
            await assert.rejects(
              provider.prepareTransport!(preparedApproval),
              stablePreparationFailure,
            );
          } else {
            await provider.prepareTransport!(preparedApproval);
          }
        }
        if (mode === "missing" || mode === "context-mismatch" || mode === "requirement-mismatch") {
          const context = structuredClone(direct.context);
          if (mode === "context-mismatch") {
            context.approval = {
              ...direct.approval,
              approvedScopeIdentity: "synthetic-other-scope",
            };
          }
          if (mode === "requirement-mismatch") {
            context.sanitizerRequirement = {
              ...context.sanitizerRequirement,
              sanitizerRequirementReason: "synthetic_changed",
            };
          }
          await assert.rejects(provider.invoke(direct.request, context), stableProviderFailure);
        }
        assert.deepEqual(direct.reads, {
          image: 0,
          schema: 0,
          system: 0,
          instruction: 0,
        });
        assert.equal(await appServerStarts(capture), 0);
      });
    });
  }
});

test("a later prepare invalidates the prior one-shot authorization", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const later = {
      ...direct.approval,
      runtimeBindingDigest: "e".repeat(64),
      runtimeBindingIdentity: "synthetic-runtime-later",
    };
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => approval,
    });
    await provider.prepareTransport!(direct.approval);
    await provider.prepareTransport!(later);
    await assert.rejects(provider.invoke(direct.request, direct.context), stableProviderFailure);
    assert.deepEqual(direct.reads, { image: 0, schema: 0, system: 0, instruction: 0 });
    assert.equal(await appServerStarts(capture), 0);

    const laterDirect = directInvocation(later);
    await provider.prepareTransport!(later);
    await provider.invoke(laterDirect.request, laterDirect.context);
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("revalidates runtime after private setup and immediately before app-server start", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const guardedModel = "synthetic-spawn-guard-model";
    direct.request.requested = {
      ...direct.request.requested,
      model: guardedModel,
    };
    direct.context.requested = direct.request.requested;
    const existingRoots = await codexTemporaryRoots();
    let calls = 0;
    let preparedCatalogObserved = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        calls += 1;
        if (calls === 1) return approval;
        preparedCatalogObserved = await hasNewPreparedCatalog(
          existingRoots,
          guardedModel,
        );
        return { ...approval, runtimeBindingDigest: "f".repeat(64) };
      },
    });
    await provider.prepareTransport!(direct.approval);
    await assert.rejects(provider.invoke(direct.request, direct.context), stableProviderFailure);
    assert.equal(calls, 2);
    assert.equal(preparedCatalogObserved, true);
    assert.deepEqual(direct.reads, { image: 0, schema: 0, system: 0, instruction: 0 });
    assert.equal(await appServerStarts(capture), 0);
  });
});

test("snapshots allowlisted runtime environment after the spawn guard", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const environmentName = "SVBENCH_ALLOWED_CANARY";
    const previous = process.env[environmentName];
    process.env[environmentName] = "synthetic-runtime-a";
    try {
      const direct = directInvocation();
      let calls = 0;
      const provider = createCodexAppServerProvider({
        process: { ...options, envAllowlist: [environmentName] },
        revalidateTransport: async (approval) => {
          calls += 1;
          if (calls === 2) process.env[environmentName] = "synthetic-runtime-b";
          return approval;
        },
      });
      await provider.prepareTransport!(direct.approval);
      await provider.invoke(direct.request, direct.context);
      const boundary = (await readCapture(capture)).find(
        (record) => record.phase === "app-server",
      );
      assert.ok(boundary);
      assert.equal(boundary.allowedCanary, "synthetic-runtime-b");
      assert.equal(calls, 2);
    } finally {
      restoreEnvironment(environmentName, previous);
    }
  });
});

test("shared Array iterator mutation cannot replace the environment allowlist", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const environmentName = "SVBENCH_ALLOWED_CANARY";
    const replacementName = "SVBENCH_PARENT_CANARY";
    const previousAllowed = process.env[environmentName];
    const previousParent = process.env[replacementName];
    process.env[environmentName] = "synthetic-runtime-a";
    process.env[replacementName] = "synthetic-parent-canary";
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      Symbol.iterator,
    );
    assert.ok(iteratorDescriptor?.value);
    let calls = 0;
    try {
      const direct = directInvocation();
      const provider = createCodexAppServerProvider({
        process: { ...options, envAllowlist: [environmentName] },
        revalidateTransport: async (approval) => {
          calls += 1;
          if (calls === 1) {
            Object.defineProperty(Array.prototype, Symbol.iterator, {
              configurable: true,
              writable: true,
              value: function* (this: unknown[]): Generator<unknown> {
                if (this.length === 1 && this[0] === environmentName) {
                  yield replacementName;
                  return;
                }
                for (let index = 0; index < this.length; index += 1) {
                  yield this[index];
                }
              },
            });
          }
          return approval;
        },
      });

      try {
        await provider.prepareTransport!(direct.approval);
        await provider.invoke(direct.request, direct.context);
      } finally {
        Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
      }

      const boundary = (await readCapture(capture)).find(
        (record) => record.phase === "app-server",
      );
      assert.ok(boundary);
      assert.equal(boundary.allowedCanary, "synthetic-runtime-a");
      assert.equal(boundary.parentCanary, null);
      assert.equal(calls, 2);
    } finally {
      Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
      restoreEnvironment(environmentName, previousAllowed);
      restoreEnvironment(replacementName, previousParent);
    }
  });
});

test("invocation settlement uses the module-load Promise constructor", async () => {
  await withFixture("provider-success", async ({ options }) => {
    const promiseDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Promise");
    assert.ok(promiseDescriptor);
    const OriginalPromise = Promise;
    let revalidations = 0;
    const direct = directInvocation();
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        revalidations += 1;
        if (revalidations === 1) {
          const ReplacementPromise = function (
            executor: (
              resolve: (value?: unknown) => void,
              reject: (reason?: unknown) => void,
            ) => void,
          ): Promise<unknown> {
            executor(undefined as unknown as (value?: unknown) => void, () => undefined);
            return OriginalPromise.resolve();
          } as unknown as PromiseConstructor;
          Object.defineProperty(globalThis, "Promise", {
            configurable: true,
            value: ReplacementPromise,
            writable: true,
          });
        }
        return approval;
      },
    });

    try {
      await provider.prepareTransport!(direct.approval);
      const running = provider.invoke(direct.request, direct.context);
      Object.defineProperty(globalThis, "Promise", promiseDescriptor);
      await running;
    } finally {
      Object.defineProperty(globalThis, "Promise", promiseDescriptor);
    }

    assert.equal(revalidations, 2);
  });
});

test("revalidation settlement restores captured Promise metadata", async (context) => {
  await context.test("species mutation", async () => {
    await withFixture("provider-success", async ({ options }) => {
      const speciesDescriptor = Object.getOwnPropertyDescriptor(Promise, Symbol.species);
      const thenDescriptor = Object.getOwnPropertyDescriptor(Promise.prototype, "then");
      assert.ok(speciesDescriptor);
      assert.ok(thenDescriptor?.value);
      let speciesCalls = 0;
      let thenReads = 0;
      const direct = directInvocation();
      const provider = createCodexAppServerProvider({
        process: options,
        revalidateTransport: (approval) => {
          Object.defineProperty(Promise, Symbol.species, {
            configurable: true,
            value: function SyntheticSpecies(
              executor: ConstructorParameters<PromiseConstructor>[0],
            ): Promise<unknown> {
              speciesCalls += 1;
              return new Promise(executor);
            },
          });
          Object.defineProperty(Promise.prototype, "then", {
            configurable: true,
            get() {
              thenReads += 1;
              throw new Error("synthetic then access");
            },
          });
          return Promise.resolve(approval);
        },
      });

      try {
        await provider.prepareTransport!(direct.approval);
        await provider.invoke(direct.request, direct.context);
      } finally {
        Object.defineProperty(Promise, Symbol.species, speciesDescriptor);
        Object.defineProperty(Promise.prototype, "then", thenDescriptor);
      }

      assert.equal(speciesCalls, 0);
      assert.equal(thenReads, 0);
    });
  });

  await context.test("rejected Promise with hostile constructor getter", async () => {
    await withFixture("provider-success", async ({ options }) => {
      const unhandledRejections: unknown[] = [];
      const recordUnhandledRejection = (reason: unknown): void => {
        unhandledRejections[unhandledRejections.length] = reason;
      };
      process.on("unhandledRejection", recordUnhandledRejection);
      const direct = directInvocation();
      const provider = createCodexAppServerProvider({
        process: options,
        revalidateTransport: () => {
          const rejected = Promise.reject(new Error("synthetic rejected revalidation"));
          Object.defineProperty(rejected, "constructor", {
            configurable: false,
            get() {
              throw new Error("synthetic constructor access");
            },
          });
          return rejected;
        },
      });

      try {
        await assert.rejects(
          provider.prepareTransport!(direct.approval),
          /codex app-server transport preparation failed/u,
        );
        await new Promise<void>((resolve) => setImmediate(resolve));
      } finally {
        process.off("unhandledRejection", recordUnhandledRejection);
      }

      assert.deepEqual(unhandledRejections, []);
    });
  });
});

test("private workspace paths use module-load path functions", async () => {
  await withFixture("provider-success", async ({ options, capture, root }) => {
    const joinDescriptor = Object.getOwnPropertyDescriptor(path, "join");
    const dirnameDescriptor = Object.getOwnPropertyDescriptor(path, "dirname");
    assert.ok(joinDescriptor?.value);
    assert.ok(dirnameDescriptor?.value);
    let joinCalls = 0;
    let dirnameCalls = 0;
    const canonicalTemporaryParent = await realpath("/tmp");
    const direct = directInvocation();
    let revalidations = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        revalidations += 1;
        if (revalidations === 1) {
          Object.defineProperty(path, "join", {
            configurable: true,
            value: (..._parts: string[]) => {
              joinCalls += 1;
              return `${root}/synthetic-outside-workspace`;
            },
            writable: true,
          });
          Object.defineProperty(path, "dirname", {
            configurable: true,
            value: (_value: string) => {
              dirnameCalls += 1;
              return "/tmp";
            },
            writable: true,
          });
        }
        return approval;
      },
    });

    try {
      await provider.prepareTransport!(direct.approval);
      await provider.invoke(direct.request, direct.context);
    } finally {
      Object.defineProperty(path, "join", joinDescriptor);
      Object.defineProperty(path, "dirname", dirnameDescriptor);
    }

    assert.equal(joinCalls, 0);
    assert.equal(dirnameCalls, 0);
    const boundary = (await readCapture(capture)).find(
      (record) => record.phase === "app-server",
    );
    assert.ok(boundary);
    assert.equal(path.dirname(String(boundary.root)), canonicalTemporaryParent);
    assert.match(path.basename(String(boundary.root)), /^svbench-codex-/u);
  });
});

test("reads allowlisted runtime only after final approval succeeds", async (context) => {
  for (const mode of ["prepare-only", "rejected-invoke"] as const) {
    await context.test(mode, async () => {
      await withFixture("provider-success", async ({ capture, options }) => {
        const environmentName = "SVBENCH_ALLOWED_CANARY";
        const originalEnvironment = process.env;
        const previous = originalEnvironment[environmentName];
        originalEnvironment[environmentName] = "synthetic-runtime-a";
        let environmentReads = 0;
        process.env = new Proxy(originalEnvironment, {
          get(target, property, receiver) {
            if (property === environmentName) environmentReads += 1;
            return Reflect.get(target, property, receiver) as unknown;
          },
        });
        try {
          const direct = directInvocation();
          let calls = 0;
          const provider = createCodexAppServerProvider({
            process: { ...options, envAllowlist: [environmentName] },
            revalidateTransport: async (approval) => {
              calls += 1;
              if (mode === "rejected-invoke" && calls === 2) {
                return { ...approval, runtimeBindingDigest: "f".repeat(64) };
              }
              return approval;
            },
          });

          await provider.prepareTransport!(direct.approval);
          if (mode === "rejected-invoke") {
            await assert.rejects(
              provider.invoke(direct.request, direct.context),
              stableProviderFailure,
            );
            assert.deepEqual(direct.reads, {
              image: 0,
              schema: 0,
              system: 0,
              instruction: 0,
            });
          }

          assert.equal(environmentReads, 0);
          assert.equal(await appServerStarts(capture), 0);
        } finally {
          process.env = originalEnvironment;
          restoreEnvironment(environmentName, previous);
        }
      });
    });
  }
});

test("rechecks approval expiry after the final runtime read", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const environmentName = "SVBENCH_ALLOWED_CANARY";
    const originalEnvironment = process.env;
    const previous = originalEnvironment[environmentName];
    originalEnvironment[environmentName] = "synthetic-runtime-a";
    const expiresAt = Date.now() + 500;
    let environmentReads = 0;
    process.env = new Proxy(originalEnvironment, {
      get(target, property, receiver) {
        if (property === environmentName) {
          environmentReads += 1;
          if (environmentReads === 2) {
            Atomics.wait(
              new Int32Array(new SharedArrayBuffer(4)),
              0,
              0,
              Math.max(1, expiresAt - Date.now() + 1),
            );
          }
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    try {
      const approval = {
        ...syntheticApproval(),
        expiresAt: new Date(expiresAt).toISOString(),
      };
      const direct = directInvocation(approval);
      const provider = createCodexAppServerProvider({
        process: { ...options, envAllowlist: [environmentName] },
        revalidateTransport: async (actual) => actual,
      });

      await provider.prepareTransport!(direct.approval);
      await assert.rejects(
        provider.invoke(direct.request, direct.context),
        stableProviderFailure,
      );

      assert.equal(environmentReads, 2);
      assert.deepEqual(direct.reads, {
        image: 0,
        schema: 0,
        system: 0,
        instruction: 0,
      });
      assert.equal(await appServerStarts(capture), 0);
    } finally {
      process.env = originalEnvironment;
      restoreEnvironment(environmentName, previous);
    }
  });
});

test("shared clock mutation cannot revive an expired approval", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const nowDescriptor = Object.getOwnPropertyDescriptor(Date, "now");
    const parseDescriptor = Object.getOwnPropertyDescriptor(Date, "parse");
    assert.ok(nowDescriptor?.value);
    assert.ok(parseDescriptor?.value);
    const originalNow = nowDescriptor.value as typeof Date.now;
    const expiresAt = originalNow() + 250;
    const approval = {
      ...syntheticApproval(),
      expiresAt: new Date(expiresAt).toISOString(),
    };
    const direct = directInvocation(approval);
    let calls = 0;
    let clockReplaced = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual) => {
        calls += 1;
        if (calls === 2) {
          Atomics.wait(
            new Int32Array(new SharedArrayBuffer(4)),
            0,
            0,
            Math.max(1, expiresAt - originalNow() + 1),
          );
          Object.defineProperties(Date, {
            now: {
              configurable: true,
              writable: true,
              value: () => 0,
            },
            parse: {
              configurable: true,
              writable: true,
              value: () => 1,
            },
          });
          clockReplaced = true;
        }
        return actual;
      },
    });

    try {
      await provider.prepareTransport!(direct.approval);
      await assert.rejects(
        provider.invoke(direct.request, direct.context),
        stableProviderFailure,
      );
    } finally {
      Object.defineProperty(Date, "now", nowDescriptor);
      Object.defineProperty(Date, "parse", parseDescriptor);
    }

    assert.equal(clockReplaced, true);
    assert.ok(originalNow() >= expiresAt);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.equal(await appServerStarts(capture), 0);
  });
});

test("does not read a consumer-owned signal getter after final approval", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const expiresAt = Date.now() + 500;
    const approval = {
      ...syntheticApproval(),
      expiresAt: new Date(expiresAt).toISOString(),
    };
    const direct = directInvocation(approval);
    let calls = 0;
    let abortedReads = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual, signal) => {
        calls += 1;
        if (calls === 2) {
          assert.ok(signal);
          Object.defineProperty(signal, "aborted", {
            configurable: true,
            get() {
              abortedReads += 1;
              if (abortedReads === 4) {
                Atomics.wait(
                  new Int32Array(new SharedArrayBuffer(4)),
                  0,
                  0,
                  Math.max(1, expiresAt - Date.now() + 1),
                );
              }
              return false;
            },
          });
        }
        return actual;
      },
    });

    await provider.prepareTransport!(direct.approval);
    await provider.invoke(direct.request, direct.context);

    assert.equal(abortedReads, 0);
    assert.ok(Date.now() < expiresAt);
    assert.deepEqual(direct.reads, {
      image: 1,
      schema: 1,
      system: 1,
      instruction: 1,
    });
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("consumer guard signal mutation cannot disable process cancellation", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const parent = new AbortController();
    let calls = 0;
    let abortedReads = 0;
    let abortQueued = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual, signal) => {
        calls += 1;
        if (calls === 2) {
          assert.ok(signal);
          Object.defineProperties(signal, {
            aborted: {
              configurable: true,
              get() {
                abortedReads += 1;
                return false;
              },
            },
            addEventListener: {
              configurable: true,
              value() {},
            },
          });
          abortQueued = true;
          queueMicrotask(() => parent.abort());
        }
        return actual;
      },
    });

    await provider.prepareTransport!(direct.approval);
    await assert.rejects(
      provider.invoke(direct.request, direct.context, parent.signal),
      stableProviderFailure,
    );

    assert.equal(abortQueued, true);
    assert.equal(abortedReads, 0);
    assert.equal(parent.signal.aborted, true);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.ok((await appServerStarts(capture)) <= 1);
  });
});

test("shared AbortSignal prototype mutation cannot disable internal cancellation", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const model = "synthetic-prototype-cancel-model";
    const request = {
      ...direct.request,
      requested: { ...direct.request.requested, model },
    };
    const context = {
      ...direct.context,
      requested: request.requested,
    };
    const parent = new AbortController();
    const prototype = AbortSignal.prototype;
    const abortedDescriptor = Object.getOwnPropertyDescriptor(prototype, "aborted");
    const addEventListenerDescriptor = Object.getOwnPropertyDescriptor(
      prototype,
      "addEventListener",
    );
    const existingRoots = await codexTemporaryRoots();
    let calls = 0;
    let abortQueued = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual, signal) => {
        calls += 1;
        if (calls === 2) {
          assert.ok(signal);
          assert.equal(Object.getPrototypeOf(signal), prototype);
          Object.defineProperties(prototype, {
            aborted: {
              configurable: true,
              get() {
                return false;
              },
            },
            addEventListener: {
              configurable: true,
              value() {},
            },
          });
          abortQueued = true;
          queueMicrotask(() => parent.abort());
        }
        return actual;
      },
    });

    await provider.prepareTransport!(direct.approval);
    try {
      await assert.rejects(
        provider.invoke(request, context, parent.signal),
        stableProviderFailure,
      );
    } finally {
      if (abortedDescriptor === undefined) {
        Reflect.deleteProperty(prototype, "aborted");
      } else {
        Object.defineProperty(prototype, "aborted", abortedDescriptor);
      }
      if (addEventListenerDescriptor === undefined) {
        Reflect.deleteProperty(prototype, "addEventListener");
      } else {
        Object.defineProperty(
          prototype,
          "addEventListener",
          addEventListenerDescriptor,
        );
      }
    }

    assert.equal(abortQueued, true);
    assert.equal(parent.signal.aborted, true);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.ok((await appServerStarts(capture)) <= 1);
    assert.equal(await hasNewPreparedCatalog(existingRoots, model), false);
  });
});

test("prepare-time AbortSignal prototype mutation cannot hide an aborted invoke", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const model = "synthetic-provider-prototype-cancel-model";
    const request = {
      ...direct.request,
      requested: { ...direct.request.requested, model },
    };
    const context = {
      ...direct.context,
      requested: request.requested,
    };
    const parent = new AbortController();
    parent.abort();
    const prototype = AbortSignal.prototype;
    const abortedDescriptor = Object.getOwnPropertyDescriptor(prototype, "aborted");
    const addEventListenerDescriptor = Object.getOwnPropertyDescriptor(
      prototype,
      "addEventListener",
    );
    const existingRoots = await codexTemporaryRoots();
    let calls = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual) => {
        calls += 1;
        if (calls === 1) {
          Object.defineProperties(prototype, {
            aborted: {
              configurable: true,
              get() {
                return false;
              },
            },
            addEventListener: {
              configurable: true,
              value() {},
            },
          });
        }
        return actual;
      },
    });

    try {
      await provider.prepareTransport!(direct.approval);
      await assert.rejects(
        provider.invoke(request, context, parent.signal),
        stableProviderFailure,
      );
    } finally {
      if (abortedDescriptor === undefined) {
        Reflect.deleteProperty(prototype, "aborted");
      } else {
        Object.defineProperty(prototype, "aborted", abortedDescriptor);
      }
      if (addEventListenerDescriptor === undefined) {
        Reflect.deleteProperty(prototype, "addEventListener");
      } else {
        Object.defineProperty(
          prototype,
          "addEventListener",
          addEventListenerDescriptor,
        );
      }
    }

    assert.equal(parent.signal.aborted, true);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.equal(await appServerStarts(capture), 0);
    assert.equal(await hasNewPreparedCatalog(existingRoots, model), false);
  });
});

test("prepare-time AbortController signal mutation cannot hide internal cancellation", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const model = "synthetic-controller-signal-cancel-model";
    const request = {
      ...direct.request,
      requested: { ...direct.request.requested, model },
    };
    const context = {
      ...direct.context,
      requested: request.requested,
    };
    const parent = new AbortController();
    const parentSignal = parent.signal;
    const decoy = new AbortController();
    const decoySignal = decoy.signal;
    const prototype = AbortController.prototype;
    const signalDescriptor = Object.getOwnPropertyDescriptor(prototype, "signal");
    assert.ok(signalDescriptor?.get);
    const existingRoots = await codexTemporaryRoots();
    let calls = 0;
    let abortQueued = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual) => {
        calls += 1;
        if (calls === 1) {
          Object.defineProperty(prototype, "signal", {
            configurable: true,
            get() {
              return decoySignal;
            },
          });
        } else if (calls === 2) {
          abortQueued = true;
          queueMicrotask(() => parent.abort());
        }
        return actual;
      },
    });

    try {
      await provider.prepareTransport!(direct.approval);
      await assert.rejects(
        provider.invoke(request, context, parentSignal),
        stableProviderFailure,
      );
    } finally {
      Object.defineProperty(prototype, "signal", signalDescriptor);
    }

    assert.equal(abortQueued, true);
    assert.equal(parentSignal.aborted, true);
    assert.equal(decoySignal.aborted, false);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.ok((await appServerStarts(capture)) <= 1);
    assert.equal(await hasNewPreparedCatalog(existingRoots, model), false);
  });
});

test("shared AbortController prototype mutation cannot disable guard cancellation", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    const model = "synthetic-controller-prototype-cancel-model";
    const request = {
      ...direct.request,
      requested: { ...direct.request.requested, model },
    };
    const context = {
      ...direct.context,
      requested: request.requested,
    };
    const parent = new AbortController();
    const prototype = AbortController.prototype;
    const abortDescriptor = Object.getOwnPropertyDescriptor(prototype, "abort");
    assert.ok(abortDescriptor?.value);
    const abortIntrinsic = abortDescriptor.value as (reason?: unknown) => void;
    const existingRoots = await codexTemporaryRoots();
    let calls = 0;
    let abortQueued = false;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (actual) => {
        calls += 1;
        if (calls === 2) {
          Object.defineProperty(prototype, "abort", {
            configurable: true,
            value() {},
          });
          abortQueued = true;
          queueMicrotask(() => Reflect.apply(abortIntrinsic, parent, []));
        }
        return actual;
      },
    });

    await provider.prepareTransport!(direct.approval);
    try {
      await assert.rejects(
        provider.invoke(request, context, parent.signal),
        stableProviderFailure,
      );
    } finally {
      Object.defineProperty(prototype, "abort", abortDescriptor);
    }

    assert.equal(abortQueued, true);
    assert.equal(parent.signal.aborted, true);
    assert.deepEqual(direct.reads, {
      image: 0,
      schema: 0,
      system: 0,
      instruction: 0,
    });
    assert.ok((await appServerStarts(capture)) <= 1);
    assert.equal(await hasNewPreparedCatalog(existingRoots, model), false);
  });
});

test("does not execute inherited optional approval getters", async () => {
  await withFixture("provider-success", async ({ capture, options }) => {
    const direct = directInvocation();
    let inheritedReads = 0;
    const inherited = Object.create(Object.prototype, {
      reasonCode: {
        configurable: true,
        get() {
          inheritedReads += 1;
          throw new Error("synthetic inherited approval getter");
        },
      },
    }) as object;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        const response = { ...approval };
        Object.setPrototypeOf(response, inherited);
        return response;
      },
    });

    await provider.prepareTransport!(direct.approval);
    await provider.invoke(direct.request, direct.context);

    assert.equal(inheritedReads, 0);
    assert.deepEqual(direct.reads, {
      image: 1,
      schema: 1,
      system: 1,
      instruction: 1,
    });
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("rejects nested-microtask expiry and runtime drift before spawn", async (t) => {
  for (const mode of ["expiry", "runtime"] as const) {
    await t.test(mode, async () => {
      await withFixture("provider-success", async ({ capture, options }) => {
        const environmentName = "SVBENCH_ALLOWED_CANARY";
        const previous = process.env[environmentName];
        process.env[environmentName] = "synthetic-runtime-a";
        try {
          const expiry = Date.now() + 500;
          const approval = {
            ...syntheticApproval(),
            ...(mode === "expiry"
              ? { expiresAt: new Date(expiry).toISOString() }
              : {}),
          };
          const direct = directInvocation(approval);
          let calls = 0;
          const provider = createCodexAppServerProvider({
            process: { ...options, envAllowlist: [environmentName] },
            revalidateTransport: async (actual) => {
              calls += 1;
              if (calls === 2) {
                queueMicrotask(() => {
                  queueMicrotask(() => {
                    if (mode === "expiry") {
                      Atomics.wait(
                        new Int32Array(new SharedArrayBuffer(4)),
                        0,
                        0,
                        Math.max(1, expiry - Date.now() + 1),
                      );
                    } else {
                      process.env[environmentName] = "synthetic-runtime-b";
                    }
                  });
                });
              }
              return actual;
            },
          });
          await provider.prepareTransport!(direct.approval);
          await assert.rejects(
            provider.invoke(direct.request, direct.context),
            stableProviderFailure,
          );
          assert.equal(calls, 2);
          assert.deepEqual(direct.reads, {
            image: 0,
            schema: 0,
            system: 0,
            instruction: 0,
          });
          assert.equal(await appServerStarts(capture), 0);
        } finally {
          restoreEnvironment(environmentName, previous);
        }
      });
    });
  }
});

test("publishes one schema-valid policy-free runner attempt", async () => {
  await withFixture("provider-success", async ({ capture, options, root }) => {
    const requirement = syntheticRequirement();
    let revalidations = 0;
    const provider = createCodexAppServerProvider({
      process: options,
      revalidateTransport: async (approval) => {
        revalidations += 1;
        return approval;
      },
    });
    const result = await runBundle({
      bundleDirectory: BUNDLE,
      attemptRoot: path.join(root, "attempts"),
      provider,
      phase: PHASE,
      requestedModel: "synthetic-model",
      requestedEffort: "medium",
      maxTokens: null,
      sanitizerRequirement: requirement,
      approval: approvalSettings(requirement),
    });
    const attempt = await readAttempt(result.attemptDirectory);
    assert.equal(attempt.manifest.run.providerId, CODEX_APP_SERVER_PROVIDER_ID);
    assert.equal(attempt.manifest.run.route, CODEX_APP_SERVER_PROVIDER_ROUTE);
    assert.equal(
      attempt.manifest.run.implementationVersion,
      CODEX_APP_SERVER_PROVIDER_IMPLEMENTATION_VERSION,
    );
    assert.equal(
      attempt.manifest.run.protocolVersion,
      CODEX_APP_SERVER_PROTOCOL_VERSION,
    );
    assert.equal(attempt.manifest.run.responded.model, "synthetic-model");
    assert.equal(attempt.manifest.run.responded.effort, "medium");
    assert.equal(attempt.manifest.run.responded.usage.available, true);
    assert.equal(attempt.manifest.approval.applied, true);
    assert.equal(attempt.manifest.sanitizer, undefined);
    assert.equal(revalidations, 2);
    assert.equal(await appServerStarts(capture), 1);
  });
});

test("runner timeout waits for process-tree and private-workspace cleanup", async () => {
  await withFixture("hang", async ({ capture, options, root }) => {
    const requirement = syntheticRequirement();
    const provider = createCodexAppServerProvider({
      process: { ...options, timeoutMs: 10_000 },
      revalidateTransport: async (approval) => approval,
    });
    await assert.rejects(
      runBundle({
        bundleDirectory: BUNDLE,
        attemptRoot: path.join(root, "attempts"),
        provider,
        phase: PHASE,
        requestedModel: "synthetic-model",
        requestedEffort: "medium",
        maxTokens: null,
        sanitizerRequirement: requirement,
        approval: approvalSettings(requirement),
        providerTimeoutMs: 750,
      }),
      (error: unknown) => error instanceof RunnerError && error.code === "provider_timeout",
    );
    const records = await readCapture(capture);
    const boundary = records.find((record) => record.phase === "app-server");
    const descendant = records.find((record) => record.descendantPid !== undefined);
    assert.ok(boundary);
    assert.ok(descendant);
    await assert.rejects(stat(String(boundary.root)), hasCode("ENOENT"));
    await assertProcessStopped(Number(descendant.descendantPid));
  });
});

function createProviderRequest(
  reads: Record<string, number>,
): { request: ProviderModelRequest; digests: ProviderAdapterContext["inputDigests"] } {
  const image = Buffer.from("synthetic provider image");
  const schema = Buffer.from(`${JSON.stringify(outputSchema())}\n`);
  const system = Buffer.from("synthetic provider system");
  const instruction = Buffer.from("synthetic provider instruction");
  const digests = {
    image: digest(image),
    schema: digest(schema),
    system: digest(system),
    instruction: digest(instruction),
  };
  return {
    request: {
      image: {
        mediaType: "image/png",
        readBytes: async () => read("image", image, reads),
      },
      schema: outputSchema(),
      schemaInput: {
        mediaType: "application/schema+json",
        readBytes: async () => read("schema", schema, reads),
      },
      system: {
        mediaType: "text/plain",
        readText: async () => (await read("system", system, reads)).toString("utf8"),
      },
      instruction: {
        mediaType: "text/plain",
        readText: async () =>
          (await read("instruction", instruction, reads)).toString("utf8"),
      },
      requested: { model: "synthetic-model", effort: "medium", maxTokens: null },
    },
    digests,
  };
}

function directInvocation(approval = syntheticApproval()): {
  request: ProviderModelRequest;
  context: ProviderAdapterContext;
  approval: ApprovalResponse;
  reads: Record<string, number>;
} {
  const reads = { image: 0, schema: 0, system: 0, instruction: 0 };
  const { request, digests } = createProviderRequest(reads);
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-provider-case",
    documentKind: "synthetic_invoice",
    preparedImage: { mediaType: request.image.mediaType, sha256: digests.image },
  });
  const requirement = syntheticRequirement().decision;
  return {
    request,
    approval,
    reads,
    context: {
      phase: approval.phase,
      bundle: { version: 1, manifestDigest: "9".repeat(64) },
      caseId: identity.caseId,
      documentKind: identity.documentKind,
      caseInputIdentity: identity,
      inputDigests: digests,
      requested: request.requested,
      provenance: {
        harnessVersion: "synthetic-harness-v1",
        harnessCommit: null,
        promptVersion: "synthetic-prompt-v1",
        preprocessVersion: "synthetic-preprocess-v1",
        sourceCommit: null,
      },
      sanitizerRequirement: requirement,
      approval,
    },
  };
}

function syntheticRequirement(): SanitizerRequirementSettings {
  const verifier = {
    id: "synthetic-requirement-verifier",
    version: "synthetic-v1",
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "synthetic_not_required",
      consumerSourceCommit: "synthetic-source-v1",
    }),
  };
  return {
    verifier,
    decision: createSanitizerRequirementDecision(verifier.derive(), verifier),
  };
}

function syntheticApproval(): ApprovalResponse {
  const requirement = syntheticRequirement().decision;
  return {
    responseVersion: 1,
    approved: true,
    gateId: "synthetic-app-server-gate",
    protocolVersion: 1,
    snapshotDigest: "a".repeat(64),
    runtimeBindingDigest: "b".repeat(64),
    runtimeBindingIdentity: "synthetic-runtime",
    approvedScopeDigest: "c".repeat(64),
    approvedScopeIdentity: "synthetic-scope",
    phase: PHASE,
    requirementVerifierId: requirement.requirementVerifierId,
    requirementVerifierVersion: requirement.requirementVerifierVersion,
    consumerSourceCommit: requirement.consumerSourceCommit,
    requirementDecisionDigest: requirement.requirementDecisionDigest,
    sanitizerRequirementVersion: requirement.sanitizerRequirementVersion,
    sanitizerRequired: requirement.sanitizerRequired,
    policyRequired: requirement.policyRequired,
    sanitizerRequirementReason: requirement.sanitizerRequirementReason,
    checkedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
  };
}

function approvalSettings(requirement: SanitizerRequirementSettings): ApprovalSettings {
  const gate: ApprovalGate = {
    id: "synthetic-app-server-gate",
    protocolVersion: 1,
    approve: async (request) => approvalResponse(request),
  };
  return {
    required: true,
    gate,
    expectedGateId: gate.id,
    expectedProtocolVersion: 1,
    snapshotDigest: "a".repeat(64),
    runtimeBindingDigest: "b".repeat(64),
    runtimeBindingIdentity: "synthetic-runtime",
    approvedScopeDigest: "c".repeat(64),
    approvedScopeIdentity: "synthetic-scope",
    phase: PHASE,
    expectedRequirementVerifierId: requirement.decision.requirementVerifierId,
    expectedRequirementVerifierVersion: requirement.decision.requirementVerifierVersion,
    expectedConsumerSourceCommit: requirement.decision.consumerSourceCommit,
    expectedRequirementDecisionDigest: requirement.decision.requirementDecisionDigest,
    expectedSanitizerRequirementVersion: 1,
    expectedSanitizerRequired: false,
    expectedPolicyRequired: false,
    expectedSanitizerRequirementReason:
      requirement.decision.sanitizerRequirementReason,
  };
}

function approvalResponse(request: ApprovalRequest): ApprovalResponse {
  return {
    responseVersion: 1,
    approved: true,
    gateId: request.expected.gateId,
    protocolVersion: 1,
    snapshotDigest: request.expected.snapshotDigest,
    runtimeBindingDigest: request.expected.runtimeBindingDigest,
    runtimeBindingIdentity: request.expected.runtimeBindingIdentity,
    approvedScopeDigest: request.expected.approvedScopeDigest,
    approvedScopeIdentity: request.expected.approvedScopeIdentity,
    phase: request.phase,
    requirementVerifierId: request.expected.requirementVerifierId,
    requirementVerifierVersion: request.expected.requirementVerifierVersion,
    consumerSourceCommit: request.expected.consumerSourceCommit,
    requirementDecisionDigest: request.expected.requirementDecisionDigest,
    sanitizerRequirementVersion: request.sanitizerRequirement.sanitizerRequirementVersion,
    sanitizerRequired: request.sanitizerRequirement.sanitizerRequired,
    policyRequired: request.sanitizerRequirement.policyRequired,
    sanitizerRequirementReason: request.sanitizerRequirement.sanitizerRequirementReason,
    checkedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
  };
}

function outputSchema(): ProviderModelRequest["schema"] {
  return {
    type: "object",
    additionalProperties: true,
    required: ["documentKind", "totalAmount"],
    properties: {
      documentKind: { const: "synthetic_invoice" },
      totalAmount: { type: "integer" },
    },
  };
}

async function withFixture(
  mode: string,
  run: (fixture: {
    root: string;
    capture: string;
    options: {
      executable: string;
      executableArguments: string[];
      timeoutMs: number;
    };
  }) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), "svbench-provider-test-"));
  const capture = path.join(root, "capture.jsonl");
  try {
    await run({
      root,
      capture,
      options: {
        executable: process.execPath,
        executableArguments: [FIXTURE, mode, capture, path.join(root, "canary")],
        timeoutMs: 3_000,
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function appServerStarts(capture: string): Promise<number> {
  return (await readCapture(capture)).filter((record) => record.phase === "app-server").length;
}

async function codexTemporaryRoots(): Promise<Set<string>> {
  return new Set(
    (await readdir("/tmp")).filter((name) => name.startsWith("svbench-codex-")),
  );
}

async function hasNewPreparedCatalog(
  existingRoots: ReadonlySet<string>,
  model: string,
): Promise<boolean> {
  for (const root of await codexTemporaryRoots()) {
    if (existingRoots.has(root)) continue;
    try {
      const catalog = await readFile(path.join("/tmp", root, "model-catalog.json"), "utf8");
      if (catalog.includes(model)) return true;
    } catch {
      // A concurrent cleanup is equivalent to not observing this candidate.
    }
  }
  return false;
}

async function readCapture(capture: string): Promise<Array<Record<string, unknown>>> {
  let source: string;
  try {
    source = await readFile(capture, "utf8");
  } catch (error: unknown) {
    if (objectWithCode(error).code === "ENOENT") return [];
    throw error;
  }
  return source
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function read(
  name: string,
  source: Buffer,
  reads: Record<string, number>,
): Promise<Buffer> {
  reads[name] = (reads[name] ?? 0) + 1;
  return Buffer.from(source);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableProviderFailure(error: unknown): boolean {
  return error instanceof Error && error.message === "codex app-server provider failed";
}

function stablePreparationFailure(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.message === "codex app-server transport preparation failed"
  );
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error) => objectWithCode(error).code === code;
}

function objectWithCode(value: unknown): { code?: string } {
  return value !== null && typeof value === "object" ? (value as { code?: string }) : {};
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
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
    assert.ok(stateOffset >= 2);
    assert.ok(processStat[stateOffset] === "Z" || processStat[stateOffset] === "X");
    return;
  }
  assert.fail("descendant process is still running");
}
