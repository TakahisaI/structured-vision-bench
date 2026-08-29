import { createHash } from "node:crypto";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;

export type SuiteAttemptContext = Readonly<{
  suiteVersion: 1;
  suiteId: string;
  suiteDigest: string;
  suitePlanDigest: string;
  casePolicyMapDigest: string;
  caseIndex: number;
  repeatIndex: number;
}>;

/** Derives the v1 caller key for one immutable suite slot. */
export function deriveSuiteAttemptKey(caseIndex: number, repeatIndex: number): string {
  if (
    !Number.isSafeInteger(caseIndex) ||
    caseIndex < 0 ||
    caseIndex > 999 ||
    !Number.isSafeInteger(repeatIndex) ||
    repeatIndex < 0 ||
    repeatIndex > 999
  ) {
    throw new Error("suite slot is invalid");
  }
  const attemptKey = `c${caseIndex.toString(36)}-r${repeatIndex.toString(36)}`;
  if (!SAFE_LABEL_PATTERN.test(attemptKey)) throw new Error("suite slot is invalid");
  return attemptKey;
}

/** Commits the exact suite bytes and its ordered case-policy mapping. */
export function computeSuitePlanDigest(
  suiteDigest: string,
  casePolicyMapDigest: string,
): string {
  if (
    typeof suiteDigest !== "string" ||
    typeof casePolicyMapDigest !== "string" ||
    !DIGEST_PATTERN.test(suiteDigest) ||
    !DIGEST_PATTERN.test(casePolicyMapDigest)
  ) {
    throw new Error("suite plan identity is invalid");
  }
  return createHash("sha256")
    .update(Buffer.from("svbench-suite-plan-v1", "ascii"))
    .update(lengthPrefixedAscii(suiteDigest))
    .update(lengthPrefixedAscii(casePolicyMapDigest))
    .digest("hex");
}

/** Copies and validates the bounded suite context accepted by the runner and reader. */
export function snapshotSuiteAttemptContext(value: unknown): SuiteAttemptContext {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    const expectedKeys = [
      "suiteVersion",
      "suiteId",
      "suiteDigest",
      "suitePlanDigest",
      "casePolicyMapDigest",
      "caseIndex",
      "repeatIndex",
    ] as const;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== expectedKeys.length ||
      expectedKeys.some((key) => !keys.includes(key))
    ) {
      throw new Error();
    }
    const suiteVersion = ownDataValue(value, "suiteVersion");
    const suiteId = ownDataValue(value, "suiteId");
    const suiteDigest = ownDataValue(value, "suiteDigest");
    const suitePlanDigest = ownDataValue(value, "suitePlanDigest");
    const casePolicyMapDigest = ownDataValue(value, "casePolicyMapDigest");
    const caseIndex = ownDataValue(value, "caseIndex");
    const repeatIndex = ownDataValue(value, "repeatIndex");
    if (
      suiteVersion !== 1 ||
      typeof suiteId !== "string" ||
      !SAFE_LABEL_PATTERN.test(suiteId) ||
      typeof suiteDigest !== "string" ||
      !DIGEST_PATTERN.test(suiteDigest) ||
      typeof suitePlanDigest !== "string" ||
      !DIGEST_PATTERN.test(suitePlanDigest) ||
      typeof casePolicyMapDigest !== "string" ||
      !DIGEST_PATTERN.test(casePolicyMapDigest) ||
      computeSuitePlanDigest(suiteDigest, casePolicyMapDigest) !== suitePlanDigest ||
      !Number.isSafeInteger(caseIndex) ||
      (caseIndex as number) < 0 ||
      (caseIndex as number) > 999 ||
      !Number.isSafeInteger(repeatIndex) ||
      (repeatIndex as number) < 0 ||
      (repeatIndex as number) > 999
    ) {
      throw new Error();
    }
    deriveSuiteAttemptKey(caseIndex as number, repeatIndex as number);
    return Object.freeze({
      suiteVersion,
      suiteId,
      suiteDigest,
      suitePlanDigest,
      casePolicyMapDigest,
      caseIndex: caseIndex as number,
      repeatIndex: repeatIndex as number,
    });
  } catch {
    throw new Error("suite attempt context is invalid");
  }
}

function ownDataValue(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    throw new Error();
  }
  return descriptor.value;
}

function lengthPrefixedAscii(value: string): Buffer {
  const bytes = Buffer.from(value, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}
