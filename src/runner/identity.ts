import { createHash } from "node:crypto";

import { snapshotSanitizerFindingPathPatterns } from "./sanitizer-finding-path.js";

export const CASE_INPUT_IDENTITY_VERSION = 1 as const;
export const ATTEMPT_IDENTITY_VERSION = 1 as const;
export const POLICY_BINDING_VERSION = 1 as const;
export const RUN_IDENTITY_VERSION = 1 as const;
export const SANITIZER_REQUIREMENT_VERSION = 1 as const;
export const SANITIZER_FINDING_PATH_ALLOWLIST_VERSION = 1 as const;

export type SanitizerRequirementCoreV1 = {
  sanitizerRequired: boolean;
  policyRequired: boolean;
  sanitizerRequirementReason: string;
  consumerSourceCommit: string | null;
};

export type SanitizerRequirementDecisionV1 = SanitizerRequirementCoreV1 & {
  sanitizerRequirementVersion: typeof SANITIZER_REQUIREMENT_VERSION;
  requirementVerifierId: string;
  requirementVerifierVersion: string;
  requirementDecisionDigest: string;
};

export type SanitizerRequirementVerifier = {
  readonly id: string;
  readonly version: string;
  derive: (documentKind: string) => SanitizerRequirementCoreV1;
};

export type SanitizerRequirementSettings = {
  decision: SanitizerRequirementDecisionV1;
  verifier: SanitizerRequirementVerifier;
};

export type SanitizerRequirementDigestInput = SanitizerRequirementCoreV1 & {
  sanitizerRequirementVersion: typeof SANITIZER_REQUIREMENT_VERSION;
  requirementVerifierId: string;
  requirementVerifierVersion: string;
};

export type CaseInputIdentityInput = {
  caseId: string;
  documentKind: string;
  preparedImage: {
    mediaType: string;
    sha256: string;
  };
};

export type CaseInputIdentity = {
  identityVersion: typeof CASE_INPUT_IDENTITY_VERSION;
  caseId: string;
  documentKind: string;
  preparedImage: {
    mediaType: string;
    sha256: string;
  };
  digest: string;
};

export type PolicyBindingInput = {
  caseInputIdentityDigest: string;
  policyVersion: number;
  policyDigest: string;
};

export type AttemptIdentityInput = {
  runId: string;
  attemptKey: string;
};

export type AttemptIdentity = AttemptIdentityInput & {
  attemptIdentityVersion: typeof ATTEMPT_IDENTITY_VERSION;
  attemptId: string;
};

export type RunIdentityInput = {
  caseInputIdentityDigest: string;
  bundleManifestDigest?: string | null;
  phase: string;
  providerId: string;
  providerRoute: string;
  providerImplementationVersion?: string | null;
  providerProtocolVersion?: string | null;
  requestedModel?: string | null;
  requestedEffort?: string | null;
  maxTokens?: number | null;
  approvalBindingDigest?: string | null;
  approvalBindingIdentity?: string | null;
  approvalGateId?: string | null;
  approvalProtocolVersion?: number | null;
  approvalSnapshotDigest?: string | null;
  approvalPhase?: string | null;
  approvalScopeDigest?: string | null;
  approvalScopeIdentity?: string | null;
  approvalRequired?: boolean;
  sanitizerBindingDigest?: string | null;
  sanitizerId?: string | null;
  sanitizerProtocolVersion?: number | null;
  sanitizerRequired?: boolean;
  policyRequired?: boolean;
  sanitizerRequirementVersion?: number | null;
  sanitizerRequirementReason?: string | null;
  requirementVerifierId?: string | null;
  requirementVerifierVersion?: string | null;
  consumerSourceCommit?: string | null;
  requirementDecisionDigest?: string | null;
};

/**
 * Computes the exact bundle-to-policy target identity from Issue #2/#8.
 * The identity intentionally excludes truth, comparison, schema, prompts,
 * provider settings, and any output so policy targeting follows the input case.
 */
export function computeCaseInputIdentity(input: CaseInputIdentityInput): CaseInputIdentity {
  const digest = sha256([
    Buffer.from("svbench-case-input-v1", "ascii"),
    lengthPrefixedUtf8(input.caseId),
    lengthPrefixedUtf8(input.documentKind),
    lengthPrefixedUtf8(input.preparedImage.mediaType),
    lengthPrefixedAscii(input.preparedImage.sha256),
  ]);
  return {
    identityVersion: CASE_INPUT_IDENTITY_VERSION,
    caseId: input.caseId,
    documentKind: input.documentKind,
    preparedImage: { ...input.preparedImage },
    digest,
  };
}

/** Computes the exact sanitizer policy binding digest from Issue #8. */
export function computePolicyBindingDigest(input: PolicyBindingInput): string {
  return sha256([
    Buffer.from("svbench-sanitizer-policy-binding-v1", "ascii"),
    lengthPrefixedAscii(input.caseInputIdentityDigest),
    lengthPrefixedUtf8(String(input.policyVersion)),
    lengthPrefixedAscii(input.policyDigest),
  ]);
}

/** Commits the canonical consumer-owned finding-path allowlist without document values. */
export function computeSanitizerFindingPathAllowlistDigest(
  sourcePatterns: readonly string[],
): string {
  const patterns = snapshotSanitizerFindingPathPatterns(sourcePatterns);
  return sha256([
    Buffer.from("svbench-sanitizer-finding-path-allowlist-v1", "ascii"),
    lengthPrefixedUtf8(String(patterns.length)),
    ...patterns.map(lengthPrefixedUtf8),
  ]);
}

/** Binds the policy and path allowlist into the existing run sanitizer binding slot. */
export function computeSanitizerExecutionBindingDigest(input: {
  policyBindingDigest: string;
  findingPathAllowlistDigest: string;
}): string {
  return sha256([
    Buffer.from("svbench-sanitizer-execution-binding-v1", "ascii"),
    lengthPrefixedAscii(input.policyBindingDigest),
    lengthPrefixedAscii(input.findingPathAllowlistDigest),
  ]);
}

/** Computes one caller-named execution instance identity within a stable run. */
export function computeAttemptIdentity(input: AttemptIdentityInput): AttemptIdentity {
  if (typeof input.runId !== "string" || !/^[a-f0-9]{64}$/u.test(input.runId)) {
    throw new Error("attempt run identity is invalid");
  }
  if (
    typeof input.attemptKey !== "string" ||
    !/^[A-Za-z0-9._-]{1,64}$/u.test(input.attemptKey)
  ) {
    throw new Error("attempt key is invalid");
  }
  return {
    attemptIdentityVersion: ATTEMPT_IDENTITY_VERSION,
    runId: input.runId,
    attemptKey: input.attemptKey,
    attemptId: sha256([
      Buffer.from("svbench-attempt-v1", "ascii"),
      lengthPrefixedAscii(input.runId),
      lengthPrefixedUtf8(input.attemptKey),
    ]),
  };
}

/** Computes the digest committed by a consumer-owned sanitizer decision. */
export function computeSanitizerRequirementDigest(input: SanitizerRequirementDigestInput): string {
  return sha256([
    Buffer.from("svbench-sanitizer-requirement-v1", "ascii"),
    lengthPrefixedUtf8(input.requirementVerifierId),
    lengthPrefixedUtf8(input.requirementVerifierVersion),
    optionalUtf8(input.consumerSourceCommit),
    lengthPrefixedUtf8(String(input.sanitizerRequirementVersion)),
    lengthPrefixedUtf8(input.sanitizerRequired ? "true" : "false"),
    lengthPrefixedUtf8(input.policyRequired ? "true" : "false"),
    lengthPrefixedUtf8(input.sanitizerRequirementReason),
  ]);
}

export function createSanitizerRequirementDecision(
  core: SanitizerRequirementCoreV1,
  verifier: SanitizerRequirementVerifier,
): SanitizerRequirementDecisionV1 {
  const digestInput: SanitizerRequirementDigestInput = {
    ...core,
    sanitizerRequirementVersion: SANITIZER_REQUIREMENT_VERSION,
    requirementVerifierId: verifier.id,
    requirementVerifierVersion: verifier.version,
  };
  return {
    ...digestInput,
    requirementDecisionDigest: computeSanitizerRequirementDigest(digestInput),
  };
}

/**
 * Computes a stable identity for one requested execution. It includes the
 * bundle manifest digest, run settings, and binding identities, never input
 * contents or provider output.
 */
export function computeRunIdentity(input: RunIdentityInput): string {
  return sha256([
    Buffer.from("svbench-run-v1", "ascii"),
    lengthPrefixedAscii(input.caseInputIdentityDigest),
    optionalAscii(input.bundleManifestDigest),
    optionalUtf8(input.phase),
    lengthPrefixedUtf8(input.providerId),
    lengthPrefixedUtf8(input.providerRoute),
    optionalUtf8(input.providerImplementationVersion),
    optionalUtf8(input.providerProtocolVersion),
    optionalUtf8(input.requestedModel),
    optionalUtf8(input.requestedEffort),
    optionalNumber(input.maxTokens),
    optionalAscii(input.approvalBindingDigest),
    optionalUtf8(input.approvalBindingIdentity),
    optionalUtf8(input.approvalGateId),
    optionalNumber(input.approvalProtocolVersion),
    optionalAscii(input.approvalSnapshotDigest),
    optionalUtf8(input.approvalPhase),
    optionalAscii(input.approvalScopeDigest),
    optionalUtf8(input.approvalScopeIdentity),
    optionalAscii(input.sanitizerBindingDigest),
    optionalBoolean(input.approvalRequired),
    optionalUtf8(input.sanitizerId),
    optionalNumber(input.sanitizerProtocolVersion),
    optionalBoolean(input.sanitizerRequired),
    optionalBoolean(input.policyRequired),
    optionalNumber(input.sanitizerRequirementVersion),
    optionalUtf8(input.sanitizerRequirementReason),
    optionalUtf8(input.requirementVerifierId),
    optionalUtf8(input.requirementVerifierVersion),
    optionalUtf8(input.consumerSourceCommit),
    optionalAscii(input.requirementDecisionDigest),
  ]);
}

function sha256(parts: Buffer[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function lengthPrefixedUtf8(value: string): Buffer {
  return lengthPrefix(Buffer.from(value, "utf8"));
}

function lengthPrefixedAscii(value: string): Buffer {
  if (!/^[\x00-\x7f]*$/u.test(value)) throw new Error("identity input must be ASCII");
  return lengthPrefix(Buffer.from(value, "ascii"));
}

function optionalUtf8(value: string | null | undefined): Buffer {
  if (value === undefined) return Buffer.from([0]);
  if (value === null) return Buffer.from([1, 0]);
  return Buffer.concat([Buffer.from([1, 1]), lengthPrefixedUtf8(value)]);
}

function optionalAscii(value: string | null | undefined): Buffer {
  if (value === undefined) return Buffer.from([0]);
  if (value === null) return Buffer.from([1, 0]);
  return Buffer.concat([Buffer.from([1, 1]), lengthPrefixedAscii(value)]);
}

function optionalBoolean(value: boolean | undefined): Buffer {
  return value === undefined ? Buffer.from([0]) : Buffer.from([1, value ? 1 : 0]);
}

function optionalNumber(value: number | null | undefined): Buffer {
  if (value === undefined) return Buffer.from([0]);
  if (value === null) return Buffer.from([1, 0]);
  return Buffer.concat([Buffer.from([1, 1]), lengthPrefixedUtf8(String(value))]);
}

function lengthPrefix(value: Buffer): Buffer {
  if (value.length > 0xffff_ffff) throw new Error("identity input is too large");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(value.length, 0);
  return Buffer.concat([prefix, value]);
}
