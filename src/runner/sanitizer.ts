import { createHash } from "node:crypto";

import { decodeUtf8Strict, isJsonObject, parseJson, type JsonValue } from "../bundle/json.js";
import {
  computeCaseInputIdentity,
  computePolicyBindingDigest,
  type CaseInputIdentity,
} from "./identity.js";
import { RunnerError } from "./errors.js";
import type {
  JsonRecord,
  Sanitizer,
  SanitizerPolicyBindingIdentity,
  SanitizerSettings,
} from "./types.js";

export type { Sanitizer } from "./types.js";

export type SanitizerPolicyEnvelopeInput = {
  target: CaseInputIdentity;
  policyVersion: number;
  policy: JsonRecord;
};

export type PreparedSanitizerPolicy = {
  envelope: JsonRecord;
  policy: JsonRecord;
  policyVersion: number;
  policyDigest: string;
  policyTargetIdentityDigest: string;
  policyBindingIdentity: SanitizerPolicyBindingIdentity;
  policyBindingDigest: string;
};

const MAX_SANITIZER_POLICY_BYTES = 4 * 1024 * 1024;

export function createSanitizerPolicyEnvelope(input: SanitizerPolicyEnvelopeInput): Buffer {
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy version is invalid");
  }
  const envelope = {
    envelopeVersion: 1,
    target: {
      identityVersion: input.target.identityVersion,
      caseId: input.target.caseId,
      documentKind: input.target.documentKind,
      preparedImage: input.target.preparedImage,
      caseInputIdentityDigest: input.target.digest,
    },
    policyVersion: input.policyVersion,
    policy: input.policy,
  } satisfies Record<string, JsonValue>;
  return Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8");
}

export function prepareSanitizerPolicy(
  settings: SanitizerSettings | undefined,
  currentIdentity: CaseInputIdentity,
): PreparedSanitizerPolicy | undefined {
  if (settings === undefined) return undefined;
  if (!settings.required && settings.sanitizer === undefined && settings.policyEnvelopeBytes === undefined) {
    return undefined;
  }
  if (settings.policyEnvelopeBytes === undefined) {
    throw new RunnerError("sanitizer_policy_missing", "required sanitizer policy is missing");
  }
  if (settings.sanitizer === undefined) {
    throw new RunnerError("sanitizer_required", "sanitizer implementation is missing");
  }

  let envelope: JsonValue;
  let policyDigest: string;
  let policyBytes: Buffer | undefined;
  try {
    policyBytes = Buffer.from(settings.policyEnvelopeBytes);
    if (policyBytes.length > MAX_SANITIZER_POLICY_BYTES) throw new Error();
    policyDigest = createHash("sha256").update(policyBytes).digest("hex");
    envelope = parseJson(
      decodeUtf8Strict(policyBytes, "sanitizer policy"),
      "sanitizer policy",
    );
  } catch {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy is invalid");
  } finally {
    policyBytes?.fill(0);
  }
  if (!isJsonObject(envelope)) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy is invalid");
  }
  if (envelope.envelopeVersion !== 1) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy version is invalid");
  }
  if (!hasOnlyKeys(envelope, ["envelopeVersion", "target", "policyVersion", "policy"])) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy shape is invalid");
  }

  const target = envelope.target;
  const targetImage = isJsonObject(target) ? target.preparedImage : undefined;
  if (
    !isJsonObject(target) ||
    target.identityVersion !== currentIdentity.identityVersion ||
    typeof target.caseId !== "string" ||
    typeof target.documentKind !== "string" ||
    !isJsonObject(targetImage) ||
    typeof targetImage.mediaType !== "string" ||
    typeof targetImage.sha256 !== "string" ||
    typeof target.caseInputIdentityDigest !== "string"
  ) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy target is invalid");
  }
  if (
    !hasOnlyKeys(target, [
      "identityVersion",
      "caseId",
      "documentKind",
      "preparedImage",
      "caseInputIdentityDigest",
    ]) ||
    !hasOnlyKeys(targetImage, ["mediaType", "sha256"])
  ) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy target shape is invalid");
  }

  let targetIdentity: CaseInputIdentity;
  try {
    targetIdentity = computeCaseInputIdentity({
      caseId: target.caseId,
      documentKind: target.documentKind,
      preparedImage: {
        mediaType: targetImage.mediaType,
        sha256: targetImage.sha256,
      },
    });
  } catch {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy target is invalid");
  }
  if (
    targetIdentity.digest !== target.caseInputIdentityDigest ||
    targetIdentity.digest !== currentIdentity.digest
  ) {
    throw new RunnerError(
      "sanitizer_policy_target_mismatch",
      "sanitizer policy target does not match the current case",
    );
  }

  const policyVersion = envelope.policyVersion;
  const policy = envelope.policy;
  if (
    typeof policyVersion !== "number" ||
    !Number.isSafeInteger(policyVersion) ||
    policyVersion < 1 ||
    !isJsonObject(policy)
  ) {
    throw new RunnerError("sanitizer_policy_invalid", "sanitizer policy body is invalid");
  }
  if (
    settings.expectedPolicyVersion !== undefined &&
    settings.expectedPolicyVersion !== policyVersion
  ) {
    throw new RunnerError("sanitizer_policy_identity_mismatch", "sanitizer policy version mismatch");
  }
  if (
    settings.expectedPolicyDigest !== undefined &&
    settings.expectedPolicyDigest !== policyDigest
  ) {
    throw new RunnerError("sanitizer_policy_identity_mismatch", "sanitizer policy digest mismatch");
  }
  if (
    settings.expectedCaseInputIdentityDigest !== undefined &&
    settings.expectedCaseInputIdentityDigest !== currentIdentity.digest
  ) {
    throw new RunnerError(
      "sanitizer_policy_identity_mismatch",
      "sanitizer policy identity mismatch",
    );
  }
  if (
    settings.expectedCaseInputIdentityVersion !== undefined &&
    settings.expectedCaseInputIdentityVersion !== currentIdentity.identityVersion
  ) {
    throw new RunnerError(
      "sanitizer_policy_identity_mismatch",
      "sanitizer policy identity version mismatch",
    );
  }

  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: currentIdentity.digest,
    policyVersion,
    policyDigest,
  });
  if (
    settings.expectedPolicyBindingDigest !== undefined &&
    settings.expectedPolicyBindingDigest !== policyBindingDigest
  ) {
    throw new RunnerError(
      "sanitizer_policy_binding_mismatch",
      "sanitizer policy binding mismatch",
    );
  }
  return {
    envelope,
    policy,
    policyVersion,
    policyDigest,
    policyTargetIdentityDigest: targetIdentity.digest,
    policyBindingIdentity: {
      caseInputIdentityDigest: currentIdentity.digest,
      policyVersion,
      policyDigest,
    },
    policyBindingDigest,
  };
}

function hasOnlyKeys(value: Record<string, JsonValue>, allowed: string[]): boolean {
  const allowedKeys = new Set(allowed);
  return Object.keys(value).every((key) => allowedKeys.has(key));
}
