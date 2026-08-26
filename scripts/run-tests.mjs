import { readdir } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { compile } from "./compile.mjs";

await compile();
const tests = await collectTests(path.join(".tmp", "build", "test"));
if (tests.length === 0) {
  console.error("no compiled tests found");
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...tests], {
  cwd: process.cwd(),
  encoding: "utf8",
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);

async function collectTests(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...(await collectTests(candidate)));
    else if (entry.isFile() && entry.name.endsWith(".test.js")) output.push(candidate);
  }
  return output.sort();
}
