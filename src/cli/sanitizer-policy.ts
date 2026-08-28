import { constants } from "node:fs";
import fsPromises from "node:fs/promises";

import { RunnerError } from "../runner/errors.js";
import { MAX_SANITIZER_POLICY_BYTES } from "../runner/sanitizer.js";

/** @internal Reads a private policy only where portable secure-open flags are enforceable. */
export async function readPrivateSanitizerPolicy(
  file: string,
): Promise<Buffer> {
  assertSanitizerPolicyPlatformSupported(process.platform);
  const flags =
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let handle: Awaited<ReturnType<typeof fsPromises.open>> | undefined;
  try {
    handle = await fsPromises.open(file, flags);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.size > MAX_SANITIZER_POLICY_BYTES ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new Error();
    }
    const bounded = Buffer.allocUnsafe(MAX_SANITIZER_POLICY_BYTES + 1);
    let total = 0;
    try {
      while (total < bounded.byteLength) {
        const { bytesRead } = await handle.read(
          bounded,
          total,
          bounded.byteLength - total,
          null,
        );
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      if (total > MAX_SANITIZER_POLICY_BYTES) throw new Error();
      return Buffer.from(bounded.subarray(0, total));
    } finally {
      bounded.fill(0);
    }
  } catch {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy is unreadable");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** @internal Pure platform guard used by cross-platform contract tests. */
export function assertSanitizerPolicyPlatformSupported(
  platform: NodeJS.Platform,
): void {
  if (platform === "win32") {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy is unreadable");
  }
}
