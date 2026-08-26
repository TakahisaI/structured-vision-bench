import { readdir } from "node:fs/promises";
import path from "node:path";

const IGNORED_DIRECTORIES = new Set([".git", ".tmp", "node_modules", "coverage", "dist"]);
const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".mts",
  ".ts",
  ".txt",
  ".yaml",
  ".yml",
]);
const TEXT_BASENAMES = new Set([".gitignore", ".node-version", ".npmrc", "LICENSE"]);

export async function listTextFiles(root = process.cwd()) {
  const output = [];
  await walk(root, output);
  return output.sort();
}

async function walk(directory, output) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) continue;

    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(absolute, output);
      continue;
    }
    if (!entry.isFile()) continue;

    if (TEXT_BASENAMES.has(entry.name) || TEXT_EXTENSIONS.has(path.extname(entry.name))) {
      output.push(absolute);
    }
  }
}
