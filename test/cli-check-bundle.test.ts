import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

test("comparison contract failures keep pointer values out of the whole summary", async () => {
  await runCli(async (cli) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      // Copy the synthetic fixture and inject a duplicated confidential-shaped
      // array path so the cross-field check fires.
      await cp(FIXTURE, temporary, { recursive: true });
      const manifestPath = path.join(temporary, "bundle.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
        comparison: { arrays: unknown[] };
      };
      const marker = "/tmp/synthetic-local/PRIVATE_CORPUS";
      manifest.comparison.arrays = [
        ...manifest.comparison.arrays,
        { path: marker, key: "/lineNo", fields: ["/amount"] },
        { path: marker, key: "/lineNo", fields: ["/amount"] },
      ];
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

      for (const flags of [["--json"], []]) {
        const result = spawnSync(process.execPath, [cli, temporary, ...flags], {
          encoding: "utf8",
        });
        assert.equal(result.status, 1);
        const rendered = `${result.stdout}${result.stderr}`;
        assert.ok(
          !rendered.includes(marker),
          `pointer value must not reach ${flags.length > 0 ? "JSON summary" : "stderr"}`,
        );
        assert.ok(rendered.includes("comparison.arrays["), "position must be reported instead");
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});

test("keeps duplicate-member diagnostics fixed and bounded", async () => {
  await runCli(async (cli) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      const marker = "/tmp/SYNTHETIC_PRIVATE_PATH";
      const source = `{"bundleVersion":1,"${marker}":1,"${marker}":2}`;
      await writeFile(path.join(temporary, "bundle.json"), source, "utf8");

      for (const flags of [["--json"], []]) {
        const result = spawnSync(process.execPath, [cli, temporary, ...flags], {
          encoding: "utf8",
        });
        assert.equal(result.status, 1);
        const rendered = `${result.stdout}${result.stderr}`;
        assert.ok(rendered.length < 2_000, "JSON diagnostics must stay bounded");
        assert.ok(!rendered.includes(marker), "duplicate member names must not be echoed");
        if (flags.length > 0) {
          const summary = JSON.parse(result.stdout) as {
            error: { code: string; message: string; details: string[] };
          };
          assert.equal(summary.error.code, "json_file_invalid");
          assert.ok(summary.error.message.includes("invalid"));
        }
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});

test("keeps a maximum-size overflow number out of CLI diagnostics", async () => {
  await runCli(async (cli) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      const prefix = '{"bundleVersion":1,"overflow":';
      const suffix = "}";
      const literal = `1${"0".repeat(4 * 1024 * 1024 - Buffer.byteLength(prefix) - suffix.length - 1)}`;
      await writeFile(path.join(temporary, "bundle.json"), `${prefix}${literal}${suffix}`, "utf8");

      for (const flags of [["--json"], []]) {
        const result = spawnSync(process.execPath, [cli, temporary, ...flags], {
          encoding: "utf8",
          maxBuffer: 10_000,
        });
        assert.equal(result.status, 1);
        const rendered = `${result.stdout}${result.stderr}`;
        assert.ok(rendered.length < 2_000, "overflow diagnostics must stay bounded");
        if (flags.length > 0) {
          const summary = JSON.parse(result.stdout) as {
            error: { code: string; message: string; details: string[] };
          };
          assert.equal(summary.error.code, "json_file_invalid");
        }
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});

test("classifies invalid UTF-8 as input errors at the CLI boundary", async () => {
  await runCli(async (cli) => {
    const invalidManifestDirectory = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      await writeFile(
        path.join(invalidManifestDirectory, "bundle.json"),
        Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]),
      );
      assert.equal(
        runJsonCli(cli, invalidManifestDirectory).error.code,
        "json_file_invalid",
      );
    } finally {
      await rm(invalidManifestDirectory, { recursive: true, force: true });
    }

    for (const key of ["schema", "truth", "system", "instruction"] as const) {
      const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
      try {
        await cp(FIXTURE, temporary, { recursive: true });
        const fileName = key === "schema" || key === "truth" ? `${key}.json` : `${key}.txt`;
        const bytes = Buffer.from([0x73, 0x79, 0x6e, 0xff, 0x74, 0x68]);
        await writeFile(path.join(temporary, fileName), bytes);
        const manifestPath = path.join(temporary, "bundle.json");
        const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
          inputs: Record<string, { sha256: string }>;
        };
        manifest.inputs[key]!.sha256 = createHash("sha256").update(bytes).digest("hex");
        await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

        const summary = runJsonCli(cli, temporary);
        assert.equal(
          summary.error.code,
          key === "system" || key === "instruction" ? "text_file_invalid" : "json_file_invalid",
        );
      } finally {
        await rm(temporary, { recursive: true, force: true });
      }
    }
  });
});

test("unexpected runtime errors become internal_error with exit code 2", async () => {
  await runCli(async (cli) => {
    // A valid argument that triggers an unexpected failure inside the
    // validator: a referenced file deleted between preflight checks and digest
    // reading. We simulate the class of failure by pointing at a bundle whose
    // truth file becomes unreadable after validation started — approximated
    // here with a directory in place of a JSON input, which passes lstat checks
    // as neither regular nor symlink only if races occur; the deterministic
    // trigger is a permission-denied read on the schema file.
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svbench-cli-"));
    try {
      await cp(FIXTURE, temporary, { recursive: true });
      if (process.platform !== "win32") {
        const schemaPath = path.join(temporary, "schema.json");
        await writeFile(schemaPath, await readFile(schemaPath));
        await chmod(schemaPath, 0o000);
        const result = spawnSync(process.execPath, [cli, temporary], { encoding: "utf8" });
        assert.equal(result.status, 2);
        assert.ok(!result.stderr.includes("at "), "no stack trace on stderr");
        assert.ok(!result.stderr.includes(temporary), "no internal paths on stderr");
        if (process.getuid && process.getuid() === 0) return; // root ignores chmod
        assert.ok(
          !result.stderr.includes("invalid_arguments"),
          "argument errors and runtime errors must not be conflated",
        );
      }
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

function runJsonCli(
  cli: string,
  bundle: string,
): { error: { code: string; message: string; details: string[] } } {
  const result = spawnSync(process.execPath, [cli, bundle, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.ok(result.stdout.length < 2_000, "CLI diagnostics must stay bounded");
  return JSON.parse(result.stdout) as { error: { code: string; message: string; details: string[] } };
}
