#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";

import { compile } from "./compile.mjs";

await compile();
const cli = path.resolve(".tmp", "build", "src", "cli", "svbench.js");
const result = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 2);
