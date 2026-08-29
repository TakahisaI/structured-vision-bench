#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_PROVIDER_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_ISSUES = 50;
const DEFAULT_TIMEOUT_MS = 120_000;
const ALLOWED_CASE_KEYS = new Set([
  "image",
  "schema",
  "system",
  "instruction",
  "truth",
  "mockOutput",
]);
const ALLOWED_SCHEMA_KEYS = new Set([
  "$schema",
  "title",
  "description",
  "type",
  "required",
  "properties",
  "additionalProperties",
  "items",
  "enum",
  "const",
]);

export class BenchError extends Error {
  constructor(code) {
    super(code);
    this.name = "BenchError";
    this.code = code;
  }
}

export async function runCase(options) {
  const started = performance.now();
  const loaded = await loadCase(options.caseDirectory);
  assertSupportedSchema(loaded.schema);

  const document = options.mock
    ? requireMockOutput(loaded.mockOutput)
    : await runProviderCommand({
        command: options.provider,
        args: options.providerArgs ?? [],
        timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        cwd: process.cwd(),
        request: {
          version: 1,
          imagePath: loaded.imagePath,
          schema: loaded.schema,
          system: loaded.system,
          instruction: loaded.instruction,
        },
      });

  const schemaIssues = validateDocument(loaded.schema, document);
  const comparisonIssues = loaded.truth === undefined ? [] : compareDocuments(loaded.truth, document);
  const passed = schemaIssues.length === 0 && comparisonIssues.length === 0;
  const result = {
    version: 1,
    status: passed ? "pass" : "fail",
    provider: options.mock ? "mock" : path.basename(options.provider),
    schemaValid: schemaIssues.length === 0,
    truthCompared: loaded.truth !== undefined,
    exactMatch: loaded.truth === undefined ? null : comparisonIssues.length === 0,
    schemaIssues,
    comparisonIssues,
    durationMs: Math.round(performance.now() - started),
  };

  if (options.output) {
    await writeFile(options.output, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  return result;
}

export async function loadCase(caseDirectory) {
  if (typeof caseDirectory !== "string" || caseDirectory.length === 0) {
    throw new BenchError("invalid_arguments");
  }

  let root;
  try {
    root = await realpath(caseDirectory);
    if (!(await stat(root)).isDirectory()) throw new Error();
  } catch {
    throw new BenchError("invalid_case");
  }

  const manifestPath = await resolveCaseFile(root, "case.json");
  const manifest = await readJson(manifestPath);
  if (!isObject(manifest)) throw new BenchError("invalid_case");
  for (const key of Object.keys(manifest)) {
    if (!ALLOWED_CASE_KEYS.has(key)) throw new BenchError("invalid_case");
  }
  for (const key of ["image", "schema", "instruction"]) {
    if (typeof manifest[key] !== "string" || manifest[key].length === 0) {
      throw new BenchError("invalid_case");
    }
  }

  const imagePath = await resolveCaseFile(root, manifest.image);
  const schemaPath = await resolveCaseFile(root, manifest.schema);
  const instructionPath = await resolveCaseFile(root, manifest.instruction);
  const systemPath = await resolveOptionalCaseFile(root, manifest.system);
  const truthPath = await resolveOptionalCaseFile(root, manifest.truth);
  const mockOutputPath = await resolveOptionalCaseFile(root, manifest.mockOutput);

  return {
    root,
    imagePath,
    schema: await readJson(schemaPath),
    instruction: await readText(instructionPath),
    system: systemPath === undefined ? "" : await readText(systemPath),
    truth: truthPath === undefined ? undefined : await readJson(truthPath),
    mockOutput: mockOutputPath === undefined ? undefined : await readJson(mockOutputPath),
  };
}

export function validateDocument(schema, value) {
  const issues = [];
  validateAt(schema, value, "", issues);
  return issues;
}

export function compareDocuments(expected, actual) {
  const issues = [];
  compareAt(expected, actual, "", issues);
  return issues;
}

function validateAt(schema, value, pointer, issues) {
  if (issues.length >= MAX_ISSUES) return;
  if (Object.hasOwn(schema, "const") && !isDeepStrictEqual(value, schema.const)) {
    addIssue(issues, pointer, "const");
    return;
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((item) => isDeepStrictEqual(item, value))) {
    addIssue(issues, pointer, "enum");
    return;
  }
  if (schema.type !== undefined && !matchesType(schema.type, value)) {
    addIssue(issues, pointer, "type");
    return;
  }
  if (schema.type === "object") {
    const properties = schema.properties ?? {};
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) addIssue(issues, childPointer(pointer, key), "required");
    }
    for (const [key, item] of Object.entries(value)) {
      if (Object.hasOwn(properties, key)) {
        validateAt(properties[key], item, childPointer(pointer, key), issues);
      } else if (schema.additionalProperties === false) {
        addIssue(issues, childPointer(pointer, key), "additional_property");
      }
    }
  }
  if (schema.type === "array" && schema.items !== undefined) {
    for (let index = 0; index < value.length && issues.length < MAX_ISSUES; index += 1) {
      validateAt(schema.items, value[index], childPointer(pointer, String(index)), issues);
    }
  }
}

function compareAt(expected, actual, pointer, issues) {
  if (issues.length >= MAX_ISSUES || isDeepStrictEqual(expected, actual)) return;
  if (Array.isArray(expected) && Array.isArray(actual)) {
    const common = Math.min(expected.length, actual.length);
    for (let index = 0; index < common; index += 1) {
      compareAt(expected[index], actual[index], childPointer(pointer, String(index)), issues);
    }
    for (let index = common; index < expected.length; index += 1) {
      addIssue(issues, childPointer(pointer, String(index)), "missing");
    }
    for (let index = common; index < actual.length; index += 1) {
      addIssue(issues, childPointer(pointer, String(index)), "extra");
    }
    return;
  }
  if (isObject(expected) && isObject(actual)) {
    const expectedKeys = Object.keys(expected).sort();
    const actualKeys = Object.keys(actual).sort();
    for (const key of expectedKeys) {
      if (!Object.hasOwn(actual, key)) addIssue(issues, childPointer(pointer, key), "missing");
      else compareAt(expected[key], actual[key], childPointer(pointer, key), issues);
    }
    for (const key of actualKeys) {
      if (!Object.hasOwn(expected, key)) addIssue(issues, childPointer(pointer, key), "extra");
    }
    return;
  }
  addIssue(issues, pointer, typeof expected === typeof actual ? "different" : "different_type");
}

function assertSupportedSchema(schema) {
  if (!isObject(schema)) throw new BenchError("unsupported_schema");
  for (const key of Object.keys(schema)) {
    if (!ALLOWED_SCHEMA_KEYS.has(key)) throw new BenchError("unsupported_schema");
  }
  if (schema.type !== undefined && !["object", "array", "string", "number", "integer", "boolean", "null"].includes(schema.type)) {
    throw new BenchError("unsupported_schema");
  }
  if (schema.required !== undefined && (!Array.isArray(schema.required) || !schema.required.every((item) => typeof item === "string"))) {
    throw new BenchError("unsupported_schema");
  }
  if (schema.properties !== undefined) {
    if (!isObject(schema.properties)) throw new BenchError("unsupported_schema");
    for (const child of Object.values(schema.properties)) assertSupportedSchema(child);
  }
  if (schema.items !== undefined) assertSupportedSchema(schema.items);
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== "boolean") {
    throw new BenchError("unsupported_schema");
  }
  if (schema.enum !== undefined && !Array.isArray(schema.enum)) throw new BenchError("unsupported_schema");
}

async function runProviderCommand({ command, args, timeoutMs, cwd, request }) {
  if (
    typeof command !== "string" ||
    command.length === 0 ||
    !Array.isArray(args) ||
    !args.every((item) => typeof item === "string")
  ) {
    throw new BenchError("invalid_arguments");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30 * 60_000) {
    throw new BenchError("invalid_arguments");
  }

  return await new Promise((resolve, reject) => {
    let settled = false;
    let outputBytes = 0;
    const output = [];
    const child = spawn(command, args, { cwd, shell: false, stdio: ["pipe", "pipe", "ignore"] });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new BenchError("provider_timeout"));
    }, timeoutMs);

    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    }

    child.on("error", () => finish(new BenchError("provider_failed")));
    child.stdin.on("error", () => finish(new BenchError("provider_failed")));
    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_PROVIDER_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish(new BenchError("provider_output_invalid"));
      } else {
        output.push(chunk);
      }
    });
    child.on("close", (code) => {
      if (settled) return;
      if (code !== 0) return finish(new BenchError("provider_failed"));
      try {
        finish(undefined, JSON.parse(Buffer.concat(output).toString("utf8")));
      } catch {
        finish(new BenchError("provider_output_invalid"));
      }
    });
    child.stdin.end(`${JSON.stringify(request)}\n`);
  });
}

async function resolveOptionalCaseFile(root, value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) throw new BenchError("invalid_case");
  return await resolveCaseFile(root, value);
}

async function resolveCaseFile(root, relativePath) {
  if (path.isAbsolute(relativePath)) throw new BenchError("invalid_case");
  const candidate = path.resolve(root, relativePath);
  if (!isInside(root, candidate)) throw new BenchError("invalid_case");
  try {
    const resolved = await realpath(candidate);
    if (!isInside(root, resolved) || !(await stat(resolved)).isFile()) throw new Error();
    return resolved;
  } catch {
    throw new BenchError("invalid_case");
  }
}

async function readJson(filePath) {
  const text = await readText(filePath);
  try {
    return JSON.parse(text);
  } catch {
    throw new BenchError("invalid_case");
  }
}

async function readText(filePath) {
  let bytes;
  try {
    bytes = await readFile(filePath);
  } catch {
    throw new BenchError("invalid_case");
  }
  if (bytes.length > MAX_JSON_BYTES) throw new BenchError("invalid_case");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BenchError("invalid_case");
  }
}

function requireMockOutput(value) {
  if (value === undefined) throw new BenchError("mock_output_missing");
  return value;
}

function matchesType(type, value) {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return isObject(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return typeof value === type;
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function childPointer(parent, segment) {
  const escaped = segment.replaceAll("~", "~0").replaceAll("/", "~1");
  return `${parent}/${escaped}`;
}

function addIssue(issues, pointer, kind) {
  if (issues.length < MAX_ISSUES) issues.push({ path: pointer, kind });
}

function parseArguments(argv) {
  if (argv[0] !== "run") throw new BenchError("invalid_arguments");
  const options = { providerArgs: [] };
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--mock") options.mock = true;
    else if (["--case", "--provider", "--provider-arg", "--output", "--timeout-ms"].includes(arg)) {
      const value = argv[index + 1];
      if (value === undefined) throw new BenchError("invalid_arguments");
      index += 1;
      if (arg === "--case") options.caseDirectory = value;
      else if (arg === "--provider") options.provider = value;
      else if (arg === "--provider-arg") options.providerArgs.push(value);
      else if (arg === "--output") options.output = value;
      else options.timeoutMs = Number(value);
    } else {
      throw new BenchError("invalid_arguments");
    }
  }
  if (!options.caseDirectory || Boolean(options.mock) === Boolean(options.provider)) {
    throw new BenchError("invalid_arguments");
  }
  return options;
}

async function main() {
  try {
    const result = await runCase(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.status === "pass" ? 0 : 1;
  } catch (error) {
    const code = error instanceof BenchError ? error.code : "internal_error";
    process.stdout.write(`${JSON.stringify({ version: 1, status: "error", error: { code } })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
