import { createHash } from "node:crypto";

import {
  isSanitizerFindingPath,
  snapshotSanitizerFindingPathPatterns,
} from "./sanitizer-finding-path.js";

export const CASE_INPUT_IDENTITY_VERSION = 1 as const;
export const ATTEMPT_IDENTITY_VERSION = 1 as const;
export const POLICY_BINDING_VERSION = 1 as const;
export const RUN_IDENTITY_VERSION = 1 as const;
export const SANITIZER_REQUIREMENT_VERSION = 1 as const;
export const SANITIZER_FINDING_PATH_ALLOWLIST_VERSION = 1 as const;
export const ARTIFACT_IDENTITY_VERSION = 1 as const;

export type ArtifactIdentityFindingInput = {
  code: string;
  severity: "info" | "warning" | "error";
  classification: string;
  hardGate: boolean;
  path: string | null;
};

export type ArtifactIdentityInput = {
  attemptId: string;
  documentSha256: string;
  sanitizer: {
    id: string;
    protocolVersion: 1;
    bindingDigest: string;
    findings: readonly ArtifactIdentityFindingInput[];
  } | null;
};

export type ArtifactIdentity = {
  artifactIdentityVersion: typeof ARTIFACT_IDENTITY_VERSION;
  artifactId: string;
};

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
 * Commits the identity of the formal post-sanitization artifact without
 * including document or finding values. Finding tuples retain their reported
 * order, and an absent sanitizer is distinct from every sanitizer identity.
 */
export function computeArtifactIdentity(input: ArtifactIdentityInput): ArtifactIdentity {
  const snapshot = snapshotArtifactIdentityInput(input);
  const sanitizerParts: Buffer[] = [];
  if (snapshot.sanitizer === null) {
    sanitizerParts.push(lengthPrefixedUtf8("null"), lengthPrefixedUtf8("0"));
  } else {
    sanitizerParts.push(
      lengthPrefixedUtf8("present"),
      lengthPrefixedUtf8(snapshot.sanitizer.id),
      lengthPrefixedUtf8(String(snapshot.sanitizer.protocolVersion)),
      lengthPrefixedAscii(snapshot.sanitizer.bindingDigest),
      lengthPrefixedUtf8(String(snapshot.sanitizer.findings.length)),
    );
    for (const finding of snapshot.sanitizer.findings) {
      sanitizerParts.push(
        lengthPrefixedUtf8(finding.code),
        lengthPrefixedUtf8(finding.severity),
        lengthPrefixedUtf8(finding.classification),
        lengthPrefixedUtf8(finding.hardGate ? "true" : "false"),
        lengthPrefixedUtf8(finding.path === null ? "null" : "value"),
      );
      if (finding.path !== null) sanitizerParts.push(lengthPrefixedUtf8(finding.path));
    }
  }
  return {
    artifactIdentityVersion: ARTIFACT_IDENTITY_VERSION,
    artifactId: sha256([
      Buffer.from("svbench-artifact-v1", "ascii"),
      lengthPrefixedUtf8(String(ARTIFACT_IDENTITY_VERSION)),
      lengthPrefixedAscii(snapshot.attemptId),
      lengthPrefixedAscii(snapshot.documentSha256),
      ...sanitizerParts,
    ]),
  };
}

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

function snapshotArtifactIdentityInput(input: ArtifactIdentityInput): ArtifactIdentityInput {
  try {
    if (!isPlainRecord(input) || !hasExactKeys(input, ["attemptId", "documentSha256", "sanitizer"])) {
      throw new Error();
    }
    const attemptId = requiredDigest(input.attemptId);
    const documentSha256 = requiredDigest(input.documentSha256);
    if (input.sanitizer === null) return { attemptId, documentSha256, sanitizer: null };

    const sanitizer = input.sanitizer;
    if (
      !isPlainRecord(sanitizer) ||
      !hasExactKeys(sanitizer, ["id", "protocolVersion", "bindingDigest", "findings"]) ||
      !isSafeLabel(sanitizer.id) ||
      sanitizer.protocolVersion !== 1 ||
      !isDenseArray(sanitizer.findings) ||
      sanitizer.findings.length > 100
    ) {
      throw new Error();
    }
    const bindingDigest = requiredDigest(sanitizer.bindingDigest);
    const findings = Array.from(sanitizer.findings, (finding) =>
      snapshotArtifactFinding(finding),
    );
    return {
      attemptId,
      documentSha256,
      sanitizer: {
        id: sanitizer.id,
        protocolVersion: sanitizer.protocolVersion,
        bindingDigest,
        findings,
      },
    };
  } catch {
    throw new Error("artifact identity input is invalid");
  }
}

function snapshotArtifactFinding(finding: unknown): ArtifactIdentityFindingInput {
  if (
    !isPlainRecord(finding) ||
    !hasExactKeys(finding, ["code", "severity", "classification", "hardGate", "path"]) ||
    !isSafeLabel(finding.code) ||
    (finding.severity !== "info" &&
      finding.severity !== "warning" &&
      finding.severity !== "error") ||
    !isSafeLabel(finding.classification) ||
    typeof finding.hardGate !== "boolean" ||
    (finding.path !== null && !isSanitizerFindingPath(finding.path))
  ) {
    throw new Error();
  }
  return {
    code: finding.code,
    severity: finding.severity,
    classification: finding.classification,
    hardGate: finding.hardGate,
    path: finding.path,
  };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => typeof key === "string" && expected.includes(key))
  );
}

function isDenseArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes("length")) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, String(index))) return false;
  }
  return keys.every(
    (key) =>
      key === "length" ||
      (typeof key === "string" && /^(?:0|[1-9][0-9]*)$/u.test(key) && Number(key) < value.length),
  );
}

function requiredDigest(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) throw new Error();
  return value;
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,64}$/u.test(value);
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
