import { createHash } from "node:crypto";

export const CASE_INPUT_IDENTITY_VERSION = 1 as const;
export const POLICY_BINDING_VERSION = 1 as const;
export const RUN_IDENTITY_VERSION = 1 as const;

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

export type RunIdentityInput = {
  caseInputIdentityDigest: string;
  bundleManifestDigest?: string | null;
  providerId: string;
  providerRoute: string;
  requestedModel?: string | null;
  requestedEffort?: string | null;
  maxTokens?: number | null;
  approvalBindingDigest?: string | null;
  approvalBindingIdentity?: string | null;
  sanitizerBindingDigest?: string | null;
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

/**
 * Computes a stable identity for one requested execution. It includes the
 * bundle manifest digest, run settings, and binding identities, never input
 * contents or provider output.
 */
export function computeRunIdentity(input: RunIdentityInput): string {
  return sha256([
    Buffer.from("svbench-run-v1", "ascii"),
    lengthPrefixedAscii(input.caseInputIdentityDigest),
    lengthPrefixedAscii(input.bundleManifestDigest ?? ""),
    lengthPrefixedUtf8(input.providerId),
    lengthPrefixedUtf8(input.providerRoute),
    lengthPrefixedUtf8(input.requestedModel ?? ""),
    lengthPrefixedUtf8(input.requestedEffort ?? ""),
    lengthPrefixedUtf8(input.maxTokens === undefined || input.maxTokens === null ? "" : String(input.maxTokens)),
    lengthPrefixedAscii(input.approvalBindingDigest ?? ""),
    lengthPrefixedUtf8(input.approvalBindingIdentity ?? ""),
    lengthPrefixedAscii(input.sanitizerBindingDigest ?? ""),
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

function lengthPrefix(value: Buffer): Buffer {
  if (value.length > 0xffff_ffff) throw new Error("identity input is too large");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(value.length, 0);
  return Buffer.concat([prefix, value]);
}
