import path from "node:path";
import { spawnSync } from "node:child_process";

import { compile } from "./compile.mjs";

await compile();
const cli = path.join(".tmp", "build", "src", "cli", "check-bundle.js");
const result = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
  cwd: process.cwd(),
  encoding: "utf8",
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
