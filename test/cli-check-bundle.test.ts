import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const CLI = path.join(".tmp", "build", "src", "cli", "check-bundle.js");
const FIXTURE = path.resolve("fixtures/synthetic/invoice-basic");

test("prints a JSON failure summary with stable code for unknown options", async () => {
  await runCli(async (cli) => {
    const result = spawnSync(process.execPath, [cli, FIXTURE, "--json", "--synthetic-unknown"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 2);
    const summary = JSON.parse(result.stdout) as {
      ok: boolean;
      error: { code: string; details: string[] };
    };
    assert.equal(summary.ok, false);
    assert.equal(summary.error.code, "invalid_arguments");
    assert.ok(!result.stderr.includes("at "), "no stack trace on stderr");
    assert.ok(!result.stderr.includes(process.cwd()), "no internal paths on stderr");
  });
});

test("reports invalid arguments without --json on stderr and exits 2", async () => {
  await runCli(async (cli) => {
    const result = spawnSync(process.execPath, [cli, "--synthetic-unknown"], {
      encoding: "utf8",
    });
    assert.equal(result.status, 2);
    assert.ok(result.stderr.includes("invalid_arguments"));
    assert.equal(result.stdout, "");
  });
});

test("keeps the machine-readable success summary", async () => {
  await runCli(async (cli) => {
    const result = spawnSync(process.execPath, [cli, FIXTURE, "--json"], { encoding: "utf8" });
    assert.equal(result.status, 0);
    const summary = JSON.parse(result.stdout) as { ok: boolean; caseId: string };
    assert.equal(summary.ok, true);
    assert.equal(summary.caseId, "synthetic-invoice-basic");
  });
});

test("never leaks the working directory in CLI diagnostics", async () => {
  await runCli(async (cli) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      await writeFile(
        path.join(temporary, "bundle.json"),
        '{"bundleVersion":1,"syntheticUnknownKey":true}\n',
        "utf8",
      );
      const result = spawnSync(process.execPath, [cli, temporary, "--json"], {
        encoding: "utf8",
      });
      assert.equal(result.status, 1);
      assert.ok(result.stdout.length > 0, "expected a JSON failure summary");
      assert.ok(!result.stdout.includes(temporary), "bundle directory must not be echoed");
      const summary = JSON.parse(result.stdout) as {
        error: { code: string; message: string; details: string[] };
      };
      assert.ok(!JSON.stringify(summary).includes(temporary));
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});

let compiled = false;

async function ensureCompiled(): Promise<void> {
  if (compiled) return;
  try {
    await access(CLI);
    compiled = true;
    return;
  } catch {
    // The test runner compiles before collecting tests; build once as a
    // fallback when this file is executed directly.
    const executable = path.join("node_modules", ".bin", process.platform === "win32" ? "tsc.cmd" : "tsc");
    const result = spawnSync(executable, ["-p", "tsconfig.build.json"], { stdio: "inherit" });
    if (result.status !== 0) assert.fail("failed to compile the CLI for testing");
    compiled = true;
  }
}

async function runCli(run: (cli: string) => Promise<void>): Promise<void> {
  await ensureCompiled();
  await run(CLI);
}
