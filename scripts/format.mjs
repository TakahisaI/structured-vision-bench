import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { listTextFiles } from "./files.mjs";

const mode = process.argv[2];
if (mode !== "--check" && mode !== "--write") {
  console.error("usage: node scripts/format.mjs --check|--write");
  process.exitCode = 2;
} else {
  const changed = [];
  for (const file of await listTextFiles()) {
    const before = await readFile(file, "utf8");
    const after = format(file, before);
    if (before === after) continue;

    changed.push(path.relative(process.cwd(), file));
    if (mode === "--write") await writeFile(file, after, "utf8");
  }

  if (changed.length > 0) {
    const action = mode === "--write" ? "formatted" : "needs formatting";
    for (const file of changed) console.error(`${action}: ${file}`);
    if (mode === "--check") process.exitCode = 1;
  }
}

function format(file, source) {
  let output = source.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  output = output
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/u, ""))
    .join("\n")
    .replace(/\n*$/u, "\n");

  if (path.extname(file) === ".json") {
    const parsed = JSON.parse(output);
    output = `${JSON.stringify(parsed, null, 2)}\n`;
  }
  return output;
}
