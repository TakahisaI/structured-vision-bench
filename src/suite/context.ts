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
    !Number.isSafeInteger(repeatIndex) ||
    repeatIndex < 0
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
  if (!DIGEST_PATTERN.test(suiteDigest) || !DIGEST_PATTERN.test(casePolicyMapDigest)) {
    throw new Error("suite plan identity is invalid");
  }
  return createHash("sha256")
    .update(Buffer.from("svbench-suite-plan-v1", "ascii"))
    .update(lengthPrefixedAscii(suiteDigest))
    .update(lengthPrefixedAscii(casePolicyMapDigest))
    .digest("hex");
}

/** Copies and validates the bounded suite context accepted by the runner and reader. */
export function snapshotSuiteAttemptContext(value: SuiteAttemptContext): SuiteAttemptContext {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 7 ||
    !Object.hasOwn(value, "suiteVersion") ||
    !Object.hasOwn(value, "suiteId") ||
    !Object.hasOwn(value, "suiteDigest") ||
    !Object.hasOwn(value, "suitePlanDigest") ||
    !Object.hasOwn(value, "casePolicyMapDigest") ||
    !Object.hasOwn(value, "caseIndex") ||
    !Object.hasOwn(value, "repeatIndex") ||
    value.suiteVersion !== 1 ||
    !SAFE_LABEL_PATTERN.test(value.suiteId) ||
    !DIGEST_PATTERN.test(value.suiteDigest) ||
    !DIGEST_PATTERN.test(value.suitePlanDigest) ||
    !DIGEST_PATTERN.test(value.casePolicyMapDigest) ||
    computeSuitePlanDigest(value.suiteDigest, value.casePolicyMapDigest) !==
      value.suitePlanDigest ||
    !Number.isSafeInteger(value.caseIndex) ||
    value.caseIndex < 0 ||
    value.caseIndex > 999 ||
    !Number.isSafeInteger(value.repeatIndex) ||
    value.repeatIndex < 0 ||
    value.repeatIndex > 999
  ) {
    throw new Error("suite attempt context is invalid");
  }
  deriveSuiteAttemptKey(value.caseIndex, value.repeatIndex);
  return Object.freeze({ ...value });
}

function lengthPrefixedAscii(value: string): Buffer {
  const bytes = Buffer.from(value, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}
