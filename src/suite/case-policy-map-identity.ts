import { createHash } from "node:crypto";

export type CasePolicyMapIdentityEntry = Readonly<{
  caseIndex: number;
  caseInputIdentityDigest: string;
  sanitizerRequirement: Readonly<{
    sanitizerRequirementVersion: 1;
    sanitizerRequired: boolean;
    policyRequired: boolean;
    sanitizerRequirementReason: string;
    requirementVerifierId: string;
    requirementVerifierVersion: string;
    consumerSourceCommit: string | null;
    requirementDecisionDigest: string;
  }>;
  policy: Readonly<{
    policyVersion: number;
    policyDigest: string;
    policyTargetIdentityDigest: string;
    policyBindingDigest: string;
  }> | null;
}>;

/** Hashes a previously validated, value-free case-policy identity projection. */
export function computeCasePolicyMapIdentityDigest(
  entries: readonly CasePolicyMapIdentityEntry[],
): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from("svbench-case-policy-map-v1", "ascii"));
  hash.update(lengthPrefixedUtf8(String(entries.length)));
  for (const entry of entries) {
    const requirement = entry.sanitizerRequirement;
    hash.update(lengthPrefixedUtf8(String(entry.caseIndex)));
    hash.update(lengthPrefixedAscii(entry.caseInputIdentityDigest));
    hash.update(lengthPrefixedUtf8(String(requirement.sanitizerRequirementVersion)));
    hash.update(lengthPrefixedUtf8(requirement.sanitizerRequired ? "true" : "false"));
    hash.update(lengthPrefixedUtf8(requirement.policyRequired ? "true" : "false"));
    hash.update(lengthPrefixedUtf8(requirement.sanitizerRequirementReason));
    hash.update(lengthPrefixedUtf8(requirement.requirementVerifierId));
    hash.update(lengthPrefixedUtf8(requirement.requirementVerifierVersion));
    hash.update(optionalUtf8(requirement.consumerSourceCommit));
    hash.update(lengthPrefixedAscii(requirement.requirementDecisionDigest));
    if (entry.policy === null) {
      hash.update(lengthPrefixedUtf8("not-required"));
    } else {
      hash.update(lengthPrefixedUtf8("required"));
      hash.update(lengthPrefixedUtf8(String(entry.policy.policyVersion)));
      hash.update(lengthPrefixedAscii(entry.policy.policyDigest));
      hash.update(lengthPrefixedAscii(entry.policy.policyTargetIdentityDigest));
      hash.update(lengthPrefixedAscii(entry.policy.policyBindingDigest));
    }
  }
  return hash.digest("hex");
}

function lengthPrefixedUtf8(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function lengthPrefixedAscii(value: string): Buffer {
  const bytes = Buffer.from(value, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function optionalUtf8(value: string | null): Buffer {
  if (value === null) return Buffer.from([0]);
  return Buffer.concat([Buffer.from([1]), lengthPrefixedUtf8(value)]);
}
