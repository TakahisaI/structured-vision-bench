import { rm } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

export async function compile() {
  await rm(".tmp/build", { recursive: true, force: true });
  const executable = path.join(
    "node_modules",
    ".bin",
    process.platform === "win32" ? "tsc.cmd" : "tsc",
  );
  const result = spawnSync(executable, ["-p", "tsconfig.build.json"], {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
