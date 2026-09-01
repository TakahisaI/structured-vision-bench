import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { writeSync } from "node:fs";
import { appendFile, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const mode = process.argv[2] ?? "success";
const operation = process.env.SVBENCH_COMMAND_OPERATION;
if (operation !== "prepare-transport" && operation !== "invoke") fail();
let requestDirectory = process.env.SVBENCH_COMMAND_REQUEST_DIRECTORY;
const stdinLines = readLines(process.stdin)[Symbol.asyncIterator]();
if (process.env.SYNTHETIC_COMMAND_MARKER !== undefined) {
  await appendFile(process.env.SYNTHETIC_COMMAND_MARKER, `${operation}\n`, "utf8");
}

if (operation === "prepare-transport") {
  if (requestDirectory !== undefined || (await readdir(".")).length !== 0) fail();
  const transportRequest = JSON.parse(await readStdinLine());
  if (
    transportRequest.requestVersion !== 1 ||
    transportRequest.operation !== "prepareTransport"
  ) {
    fail();
  }
  const transportResponse = transportRequest.approval;
  await probeTransportIsolation();
  if (mode === "transport-mismatch") {
    transportResponse.runtimeBindingDigest = "0".repeat(64);
  }
  process.stdout.write(`${JSON.stringify(transportResponse)}\n`);
  process.exit(0);
}
if (requestDirectory === undefined) {
  if ((await readdir(".")).length !== 0) fail();
  const transportRequest = JSON.parse(await readStdinLine());
  if (
    transportRequest.requestVersion !== 1 ||
    transportRequest.operation !== "prepareTransport"
  ) {
    fail();
  }
  const transportResponse = transportRequest.approval;
  await probeTransportIsolation();
  if (mode === "inline-transport-mismatch") {
    transportResponse.runtimeBindingDigest = "0".repeat(64);
  }
  if (mode === "inline-working-file") {
    await writeFile("synthetic-unexpected", "synthetic working data\n", "utf8");
  }
  if (process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER !== undefined) {
    await appendFile(
      process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER,
      `reattest:${process.pid}\n`,
      "utf8",
    );
  }
  if (mode === "inline-exit-with-inherited-descendant") {
    const observedMarker = process.env.SYNTHETIC_COMMAND_REQUEST_OBSERVED_MARKER;
    if (observedMarker === undefined) fail();
    spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { appendFile } from "node:fs/promises";
const marker = process.argv[1];
await appendFile(marker, "synthetic helper ready\\n", "utf8");
setInterval(() => undefined, 1000);`,
        observedMarker,
      ],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    let helperReady = false;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      try {
        await stat(observedMarker);
        helperReady = true;
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
    }
    if (!helperReady) fail();
    writeSync(process.stdout.fd, `${JSON.stringify(transportResponse)}\n`);
    process.exit(0);
  }
  await writeStdoutLine(transportResponse);
  if (mode === "inline-exit-after-attestation") process.exit(0);
  const invokeRequest = JSON.parse(await readStdinLine());
  if (
    invokeRequest.requestVersion !== 1 ||
    invokeRequest.operation !== "invoke" ||
    typeof invokeRequest.requestDirectory !== "string" ||
    !path.isAbsolute(invokeRequest.requestDirectory)
  ) {
    fail();
  }
  requestDirectory = invokeRequest.requestDirectory;
  if (process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER !== undefined) {
    await appendFile(
      process.env.SYNTHETIC_COMMAND_HANDSHAKE_MARKER,
      `invoke:${process.pid}\n`,
      "utf8",
    );
  }
}
if (requestDirectory === undefined || !path.isAbsolute(requestDirectory)) fail();
const expectedFiles = [
  "image.input",
  "instruction.txt",
  "request.json",
  "schema.json",
  "system.txt",
];

if (mode === "hang") {
  await new Promise(() => undefined);
}
if (mode === "descendant-hang") {
  const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER !== undefined) {
    await writeFile(
      process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER,
      `${descendant.pid}\n`,
      "utf8",
    );
  }
  setInterval(() => undefined, 1000);
  await new Promise(() => undefined);
}
if (mode === "detached-descendant-hang") {
  const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    detached: process.platform !== "win32",
    stdio: "ignore",
  });
  descendant.unref();
  if (process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER !== undefined) {
    await writeFile(
      process.env.SYNTHETIC_COMMAND_DESCENDANT_MARKER,
      `${descendant.pid}\n`,
      "utf8",
    );
  }
  setInterval(() => undefined, 1000);
  await new Promise(() => undefined);
}

if ((await readdir(".")).length !== 0) fail();
const names = (await readdir(requestDirectory)).sort();
if (JSON.stringify(names) !== JSON.stringify(expectedFiles)) fail();
const directoryInfo = await stat(requestDirectory);
if (process.platform !== "win32" && (directoryInfo.mode & 0o077) !== 0) fail();
for (const name of expectedFiles) {
  const info = await stat(path.join(requestDirectory, name));
  if (!info.isFile() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) fail();
}

const request = JSON.parse(
  await readFile(path.join(requestDirectory, "request.json"), "utf8"),
);
for (const forbidden of [
  "truth",
  "comparison",
  "attemptKey",
  "attemptId",
  "runId",
  "policy",
  "sanitizer",
]) {
  if (Object.hasOwn(request, forbidden)) fail();
}
if (request.requestVersion !== 1) fail();
if (request.provider.protocolVersion !== "command-provider-v1") fail();
if (request.sanitizerRequirement.sanitizerRequired) fail();
if (request.sanitizerRequirement.policyRequired) fail();

const inputNames = ["image", "schema", "system", "instruction"];
for (const inputName of inputNames) {
  const input = request.inputs[inputName];
  const bytes = await readFile(path.join(requestDirectory, input.path));
  if (createHash("sha256").update(bytes).digest("hex") !== input.sha256) fail();
}

const hostedPayload = {
  image: await readFile(path.join(requestDirectory, request.inputs.image.path)),
  schema: JSON.parse(
    await readFile(path.join(requestDirectory, request.inputs.schema.path), "utf8"),
  ),
  system: await readFile(
    path.join(requestDirectory, request.inputs.system.path),
    "utf8",
  ),
  instruction: await readFile(
    path.join(requestDirectory, request.inputs.instruction.path),
    "utf8",
  ),
  requested: request.requested,
};
if (
  JSON.stringify(Object.keys(hostedPayload).sort()) !==
  JSON.stringify(["image", "instruction", "requested", "schema", "system"])
) {
  fail();
}

if (mode === "env") {
  if (
    process.env.SYNTHETIC_COMMAND_ALLOWED !== "synthetic-allowed" ||
    process.env.SYNTHETIC_COMMAND_BLOCKED !== undefined
  ) {
    fail();
  }
}
if (mode === "nonzero") {
  process.stderr.write("synthetic private adapter failure\n");
  process.exit(7);
}
if (mode === "stderr-overflow") {
  process.stderr.write("x".repeat(4096));
  await new Promise(() => undefined);
}
if (mode === "invalid-json") {
  process.stdout.write("{synthetic invalid json\n");
  process.exit(0);
}
if (mode === "duplicate-json") {
  process.stdout.write('{"responseVersion":1,"responseVersion":1}\n');
  process.exit(0);
}
if (mode === "huge-output") {
  process.stdout.write("x".repeat(4096));
  await new Promise(() => undefined);
}

const response = {
  responseVersion: 1,
  phase: request.phase,
  provider: request.provider,
  requested: request.requested,
  caseInputIdentity: {
    identityVersion: request.caseInputIdentity.identityVersion,
    digest: request.caseInputIdentity.digest,
  },
  sanitizerRequirement: request.sanitizerRequirement,
  approval: request.approval,
  document: {
    documentKind: "synthetic_invoice",
    invoiceNumber: "SYNTHETIC-COMMAND-001",
    issuedAt: "2026-01-01",
    currency: "JPY",
    lines: [],
    totalAmount: 0,
  },
  responded: {
    model: request.requested.model,
    effort: request.requested.effort,
    usage: { available: false },
    stopReason: "stop",
  },
};

if (mode === "phase-mismatch") response.phase = "synthetic-other-phase";
if (mode === "requested-mismatch") response.requested.model = "synthetic-other-model";
if (mode === "identity-mismatch") response.caseInputIdentity.digest = "0".repeat(64);
if (mode === "requirement-mismatch") {
  response.sanitizerRequirement.sanitizerRequirementReason = "synthetic_changed";
}
if (mode === "approval-missing") response.approval = null;
if (mode === "approval-mismatch" && response.approval !== null) {
  response.approval.runtimeBindingDigest = "0".repeat(64);
}
if (mode === "unknown-field") response.syntheticUnknown = true;
if (mode === "echo-phase") response.document.syntheticPhase = request.phase;
if (mode === "cache-usage") {
  response.responded.usage = {
    available: true,
    inputTokens: 23,
    cachedInputTokens: 13,
    cacheWriteInputTokens: 4,
    outputTokens: 8,
    totalTokens: 31,
  };
}
if (mode === "usage-without-cache") {
  response.responded.usage = {
    available: true,
    inputTokens: 23,
    outputTokens: 8,
    totalTokens: 31,
  };
}
if (mode === "echo-contract") {
  response.document.syntheticRequestedModel = request.requested.model;
  response.document.syntheticCaseId = request.case.id;
  response.document.syntheticHarnessVersion = request.provenance.harnessVersion;
}

process.stdout.write(`${JSON.stringify(response)}\n`);

function fail() {
  process.exit(9);
}

async function readStdinLine() {
  const next = await stdinLines.next();
  if (next.done) fail();
  return next.value;
}

async function* readLines(stream) {
  let pending = "";
  for await (const chunk of stream) {
    pending += Buffer.from(chunk).toString("utf8");
    for (;;) {
      const newline = pending.indexOf("\n");
      if (newline === -1) break;
      yield pending.slice(0, newline);
      pending = pending.slice(newline + 1);
    }
  }
  if (pending.length !== 0) fail();
}

async function probeTransportIsolation() {
  if (mode === "transport-sibling-read") {
    try {
      await readFile(path.join("..", "request", "system.txt"));
      fail();
    } catch (error) {
      if (error?.code !== "ENOENT") fail();
    }
  }
  if (mode === "transport-sibling-write") {
    try {
      await writeFile(
        path.join("..", "request", "instruction.txt"),
        "synthetic transport tamper\n",
        "utf8",
      );
    } catch (error) {
      if (error?.code !== "ENOENT") fail();
    }
  }
}

async function writeStdoutLine(value) {
  await new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(value)}\n`, (error) => {
      if (error === undefined || error === null) resolve();
      else reject(error);
    });
  });
}
