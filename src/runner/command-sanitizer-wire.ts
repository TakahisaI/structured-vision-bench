import {
  decodeUtf8Strict,
  isJsonObject,
  normalizeJsonValue,
  parseJson,
  type JsonValue,
} from "../bundle/json.js";
import { computeCaseInputIdentity, computePolicyBindingDigest } from "./identity.js";
import type {
  JsonRecord,
  ProviderUsage,
  SanitizerFinding,
  SanitizerRequest,
  SanitizerResponse,
} from "./types.js";

export const MAX_COMMAND_SANITIZER_REQUEST_BYTES = 16 * 1024 * 1024;
const MAX_COMMAND_SANITIZER_SOURCE_BYTES =
  MAX_COMMAND_SANITIZER_REQUEST_BYTES * 2 + 4 * 1024;

const SAFE_LABEL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const CASE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u;
const JSON_POINTER_PATTERN = /^(?:\/(?:[^~/]|~[01])*)*$/u;

export type CommandSanitizerRequestV1 = {
  requestVersion: 1;
  caseInputIdentity: SanitizerRequest["caseInputIdentity"];
  documentKind: string;
  policyEnvelope: JsonRecord;
  policyVersion: number;
  policyDigest: string;
  policyBindingDigest: string;
  document: JsonValue;
  provider: SanitizerRequest["provider"];
  provenance: SanitizerRequest["provenance"];
};

export type CommandSanitizerResponseV1 = SanitizerResponse & {
  responseVersion: 1;
};

/** @internal Creates the immutable request used by the private command protocol. */
export function snapshotCommandSanitizerRequest(
  source: SanitizerRequest,
): CommandSanitizerRequestV1 {
  const normalized = normalizeJsonValue(
    source,
    "command sanitizer request",
    MAX_COMMAND_SANITIZER_SOURCE_BYTES,
  );
  if (!isJsonObject(normalized)) throw new Error();
  assertKeys(normalized, [
    "caseInputIdentity",
    "documentKind",
    "policyEnvelope",
    "policy",
    "policyVersion",
    "policyDigest",
    "policyBindingDigest",
    "document",
    "provider",
    "provenance",
  ]);

  const identity = requiredObject(normalized.caseInputIdentity);
  assertKeys(identity, ["identityVersion", "caseId", "documentKind", "preparedImage", "digest"]);
  const preparedImage = requiredObject(identity.preparedImage);
  assertKeys(preparedImage, ["mediaType", "sha256"]);
  if (
    identity.identityVersion !== 1 ||
    !isCaseId(identity.caseId) ||
    !isSafeLabel(identity.documentKind) ||
    !isMediaType(preparedImage.mediaType) ||
    !isDigest(preparedImage.sha256) ||
    !isDigest(identity.digest) ||
    normalized.documentKind !== identity.documentKind
  ) {
    throw new Error();
  }
  const computedIdentity = computeCaseInputIdentity({
    caseId: identity.caseId,
    documentKind: identity.documentKind,
    preparedImage: {
      mediaType: preparedImage.mediaType,
      sha256: preparedImage.sha256,
    },
  });
  if (computedIdentity.digest !== identity.digest) throw new Error();

  const policyEnvelope = requiredObject(normalized.policyEnvelope);
  assertKeys(policyEnvelope, ["envelopeVersion", "target", "policyVersion", "policy"]);
  const target = requiredObject(policyEnvelope.target);
  assertKeys(target, [
    "identityVersion",
    "caseId",
    "documentKind",
    "preparedImage",
    "caseInputIdentityDigest",
  ]);
  const targetImage = requiredObject(target.preparedImage);
  assertKeys(targetImage, ["mediaType", "sha256"]);
  const policy = requiredObject(normalized.policy);
  if (
    policyEnvelope.envelopeVersion !== 1 ||
    target.identityVersion !== 1 ||
    target.caseId !== identity.caseId ||
    target.documentKind !== identity.documentKind ||
    targetImage.mediaType !== preparedImage.mediaType ||
    targetImage.sha256 !== preparedImage.sha256 ||
    target.caseInputIdentityDigest !== identity.digest ||
    !Number.isSafeInteger(normalized.policyVersion) ||
    typeof normalized.policyVersion !== "number" ||
    normalized.policyVersion < 1 ||
    policyEnvelope.policyVersion !== normalized.policyVersion ||
    !jsonEqual(policyEnvelope.policy, policy) ||
    !isDigest(normalized.policyDigest) ||
    !isDigest(normalized.policyBindingDigest) ||
    computePolicyBindingDigest({
      caseInputIdentityDigest: identity.digest,
      policyVersion: normalized.policyVersion,
      policyDigest: normalized.policyDigest,
    }) !== normalized.policyBindingDigest
  ) {
    throw new Error();
  }

  return deepFreeze({
    requestVersion: 1,
    caseInputIdentity: {
      identityVersion: 1,
      caseId: identity.caseId,
      documentKind: identity.documentKind,
      preparedImage: {
        mediaType: preparedImage.mediaType,
        sha256: preparedImage.sha256,
      },
      digest: identity.digest,
    },
    documentKind: identity.documentKind,
    policyEnvelope,
    policyVersion: normalized.policyVersion,
    policyDigest: normalized.policyDigest,
    policyBindingDigest: normalized.policyBindingDigest,
    document: normalized.document!,
    provider: snapshotProvider(normalized.provider),
    provenance: snapshotProvenance(normalized.provenance),
  });
}

/** @internal Encodes one request object followed by LF for stdin framing. */
export function encodeCommandSanitizerRequest(request: CommandSanitizerRequestV1): Buffer {
  const bytes = Buffer.from(`${JSON.stringify(request)}\n`, "utf8");
  if (bytes.byteLength > MAX_COMMAND_SANITIZER_REQUEST_BYTES) {
    bytes.fill(0);
    throw new Error();
  }
  return bytes;
}

/** @internal Parses and binds one strict response to the validated request. */
export function parseCommandSanitizerResponse(
  bytes: Uint8Array,
  sanitizerId: string,
  request: CommandSanitizerRequestV1,
): SanitizerResponse {
  const text = decodeUtf8Strict(bytes, "command sanitizer response");
  if (text.trim() !== text) throw new Error();
  const parsed = parseJson(text, "command sanitizer response");
  const response = requiredObject(parsed);
  assertKeys(
    response,
    [
      "responseVersion",
      "sanitizedDocument",
      "sanitizerId",
      "protocolVersion",
      "policyVersion",
      "policyDigest",
      "caseInputIdentityVersion",
      "caseInputIdentityDigest",
      "policyTargetIdentityDigest",
      "policyBindingDigest",
    ],
    ["findings"],
  );
  if (
    response.responseVersion !== 1 ||
    response.sanitizerId !== sanitizerId ||
    response.protocolVersion !== 1 ||
    typeof response.policyVersion !== "number" ||
    !Number.isSafeInteger(response.policyVersion) ||
    response.policyVersion < 1 ||
    response.policyVersion !== request.policyVersion ||
    response.policyDigest !== request.policyDigest ||
    response.caseInputIdentityVersion !== 1 ||
    response.caseInputIdentityDigest !== request.caseInputIdentity.digest ||
    response.policyTargetIdentityDigest !== request.caseInputIdentity.digest ||
    response.policyBindingDigest !== request.policyBindingDigest
  ) {
    throw new Error();
  }
  const findings = snapshotFindings(response.findings);
  return deepFreeze({
    sanitizedDocument: response.sanitizedDocument!,
    sanitizerId: response.sanitizerId,
    protocolVersion: 1,
    policyVersion: response.policyVersion,
    policyDigest: response.policyDigest,
    caseInputIdentityVersion: 1,
    caseInputIdentityDigest: response.caseInputIdentityDigest,
    policyTargetIdentityDigest: response.policyTargetIdentityDigest,
    policyBindingDigest: response.policyBindingDigest,
    ...(findings === undefined ? {} : { findings }),
  });
}

function snapshotProvider(value: JsonValue | undefined): SanitizerRequest["provider"] {
  const provider = requiredObject(value);
  assertKeys(provider, [
    "id",
    "route",
    "requested",
    "respondedModel",
    "effectiveEffort",
    "usage",
    "stopReason",
  ]);
  const requested = requiredObject(provider.requested);
  assertKeys(requested, ["model", "effort", "maxTokens"]);
  const usage = snapshotUsage(provider.usage);
  if (
    !isSafeLabel(provider.id) ||
    !isSafeLabel(provider.route) ||
    !isNullableSafeLabel(requested.model) ||
    !isNullableSafeLabel(requested.effort) ||
    (requested.maxTokens !== null &&
      (typeof requested.maxTokens !== "number" ||
        !Number.isSafeInteger(requested.maxTokens) ||
        requested.maxTokens < 1)) ||
    !isNullableSafeLabel(provider.respondedModel) ||
    !isNullableSafeLabel(provider.effectiveEffort) ||
    !isNullableSafeLabel(provider.stopReason)
  ) {
    throw new Error();
  }
  return {
    id: provider.id,
    route: provider.route,
    requested: {
      model: requested.model,
      effort: requested.effort,
      maxTokens: requested.maxTokens,
    },
    respondedModel: provider.respondedModel,
    effectiveEffort: provider.effectiveEffort,
    usage,
    stopReason: provider.stopReason,
  };
}

function snapshotUsage(value: JsonValue | undefined): ProviderUsage {
  const usage = requiredObject(value);
  assertKeys(usage, ["available"], ["inputTokens", "outputTokens", "totalTokens"]);
  if (typeof usage.available !== "boolean") throw new Error();
  if (!usage.available) {
    if (Object.keys(usage).length !== 1) throw new Error();
    return { available: false };
  }
  const result: ProviderUsage = { available: true };
  for (const key of ["inputTokens", "outputTokens", "totalTokens"] as const) {
    const tokenCount = usage[key];
    if (tokenCount === undefined) continue;
    if (
      tokenCount !== null &&
      (typeof tokenCount !== "number" || !Number.isSafeInteger(tokenCount) || tokenCount < 0)
    ) {
      throw new Error();
    }
    result[key] = tokenCount;
  }
  return result;
}

function snapshotProvenance(value: JsonValue | undefined): SanitizerRequest["provenance"] {
  const provenance = requiredObject(value);
  assertKeys(provenance, [
    "harnessVersion",
    "harnessCommit",
    "promptVersion",
    "preprocessVersion",
    "sourceCommit",
  ]);
  if (
    !isSafeLabel(provenance.harnessVersion) ||
    !isNullableSafeLabel(provenance.harnessCommit) ||
    !isSafeLabel(provenance.promptVersion) ||
    !isSafeLabel(provenance.preprocessVersion) ||
    !isNullableSafeLabel(provenance.sourceCommit)
  ) {
    throw new Error();
  }
  return {
    harnessVersion: provenance.harnessVersion,
    harnessCommit: provenance.harnessCommit,
    promptVersion: provenance.promptVersion,
    preprocessVersion: provenance.preprocessVersion,
    sourceCommit: provenance.sourceCommit,
  };
}

function snapshotFindings(value: JsonValue | undefined): SanitizerFinding[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 100) throw new Error();
  return value.map((item) => {
    const finding = requiredObject(item);
    assertKeys(finding, ["code", "severity", "classification", "hardGate"], ["path"]);
    if (
      !isSafeLabel(finding.code) ||
      (finding.severity !== "info" &&
        finding.severity !== "warning" &&
        finding.severity !== "error") ||
      !isSafeLabel(finding.classification) ||
      typeof finding.hardGate !== "boolean" ||
      (finding.path !== undefined &&
        finding.path !== null &&
        (typeof finding.path !== "string" ||
          finding.path.length > 1024 ||
          !JSON_POINTER_PATTERN.test(finding.path)))
    ) {
      throw new Error();
    }
    return {
      code: finding.code,
      severity: finding.severity,
      classification: finding.classification,
      hardGate: finding.hardGate,
      ...(finding.path === undefined ? {} : { path: finding.path }),
    };
  });
}

function requiredObject(value: JsonValue | undefined): Record<string, JsonValue> {
  if (!isJsonObject(value)) throw new Error();
  return value;
}

function assertKeys(
  value: Record<string, JsonValue>,
  required: string[],
  optional: string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new Error();
  }
}

function isSafeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL_PATTERN.test(value);
}

function isNullableSafeLabel(value: unknown): value is string | null {
  return value === null || isSafeLabel(value);
}

function isCaseId(value: unknown): value is string {
  return typeof value === "string" && CASE_ID_PATTERN.test(value);
}

function isMediaType(value: unknown): value is string {
  return typeof value === "string" && MEDIA_TYPE_PATTERN.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function jsonEqual(left: JsonValue | undefined, right: JsonValue): boolean {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => jsonEqual(item, right[index]!))
    );
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && jsonEqual(left[key], right[key]!))
  );
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
