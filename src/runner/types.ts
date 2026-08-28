import type {
  CaseInputIdentity,
  SanitizerRequirementDecisionV1,
  SanitizerRequirementSettings,
} from "./identity.js";
import type { JsonValue } from "../bundle/json.js";

export type JsonRecord = { [key: string]: JsonValue };

export type RequestedExecutionSettings = {
  model: string | null;
  effort: string | null;
  maxTokens: number | null;
};

export type ProviderInputDigestSet = {
  image: string;
  schema: string;
  system: string;
  instruction: string;
};

export type ProviderModelRequest = {
  image: {
    mediaType: string;
    readBytes: () => Promise<Buffer>;
  };
  schema: JsonValue;
  schemaInput: {
    mediaType: string;
    readBytes: () => Promise<Buffer>;
  };
  system: {
    mediaType: string;
    readText: () => Promise<string>;
  };
  instruction: {
    mediaType: string;
    readText: () => Promise<string>;
  };
  requested: RequestedExecutionSettings;
};

export type ProviderAdapterContext = {
  phase: string;
  bundle: {
    version: 1;
    manifestDigest: string;
  };
  caseId: string;
  documentKind: string;
  caseInputIdentity: CaseInputIdentity;
  inputDigests: ProviderInputDigestSet;
  requested: RequestedExecutionSettings;
  provenance: {
    harnessVersion: string;
    harnessCommit: string | null;
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  sanitizerRequirement: SanitizerRequirementDecisionV1;
  approval: ApprovalResponse | null;
};

export type ProviderUsage = {
  available: boolean;
  inputTokens?: number | null;
  outputTokens?: number | null;
  totalTokens?: number | null;
};

export type ProviderOutput = JsonValue | string | Uint8Array;

export type ProviderResponse = {
  rawDocument: ProviderOutput;
  approval?: ApprovalResponse;
  respondedModel?: string | null;
  effectiveEffort?: string | null;
  usage?: ProviderUsage;
  stopReason?: string | null;
};

export interface Provider {
  readonly id: string;
  readonly route: string;
  readonly implementationVersion?: string | null;
  readonly protocolVersion?: string | null;
  prepareTransport?(
    approval: ApprovalResponse,
    signal?: AbortSignal,
  ): Promise<ApprovalResponse>;
  invoke(
    request: ProviderModelRequest,
    context: ProviderAdapterContext,
    signal?: AbortSignal,
  ): Promise<ProviderResponse>;
}

export type ApprovalRequest = {
  requestVersion: 1;
  provider: {
    id: string;
    route: string;
    implementationVersion: string | null;
    protocolVersion: string | null;
  };
  requested: RequestedExecutionSettings;
  harness: {
    version: string;
    commit: string | null;
  };
  documentKind: string;
  phase: string;
  provenance: {
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
  sanitizerRequirement: {
    sanitizerRequirementVersion: 1;
    sanitizerRequired: boolean;
    policyRequired: boolean;
    sanitizerRequirementReason: string;
  };
  expected: {
    gateId: string;
    protocolVersion: 1;
    snapshotDigest: string;
    runtimeBindingDigest: string;
    runtimeBindingIdentity: string;
    approvedScopeDigest: string;
    approvedScopeIdentity: string;
    requirementVerifierId: string;
    requirementVerifierVersion: string;
    consumerSourceCommit: string | null;
    requirementDecisionDigest: string;
  };
};

export type ApprovalResponse = {
  responseVersion: 1;
  approved: boolean;
  gateId: string;
  protocolVersion: 1;
  snapshotDigest: string;
  runtimeBindingDigest: string;
  runtimeBindingIdentity: string;
  approvedScopeDigest: string;
  approvedScopeIdentity: string;
  phase: string;
  requirementVerifierId: string;
  requirementVerifierVersion: string;
  consumerSourceCommit: string | null;
  requirementDecisionDigest: string;
  sanitizerRequirementVersion: 1;
  sanitizerRequired: boolean;
  policyRequired: boolean;
  sanitizerRequirementReason: string;
  checkedAt?: string | null;
  expiresAt?: string | null;
  reasonCode?: string;
};

export interface ApprovalGate {
  readonly id: string;
  readonly protocolVersion: 1;
  approve(request: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalResponse>;
}

export type ApprovalSettings = {
  required: boolean;
  gate?: ApprovalGate;
  executable?: string;
  argv?: string[];
  envAllowlist?: string[];
  outputLimitBytes?: number;
  expectedGateId?: string;
  expectedProtocolVersion?: 1;
  snapshotDigest?: string;
  runtimeBindingDigest?: string;
  runtimeBindingIdentity?: string;
  approvedScopeDigest?: string;
  approvedScopeIdentity?: string;
  phase?: string;
  expectedRequirementVerifierId?: string;
  expectedRequirementVerifierVersion?: string;
  expectedConsumerSourceCommit?: string | null;
  expectedRequirementDecisionDigest?: string;
  expectedSanitizerRequirementVersion?: 1;
  expectedSanitizerRequired?: boolean;
  expectedPolicyRequired?: boolean;
  expectedSanitizerRequirementReason?: string;
  timeoutMs?: number;
};

export type SanitizerProviderMetadata = {
  id: string;
  route: string;
  requested: RequestedExecutionSettings;
  respondedModel: string | null;
  effectiveEffort: string | null;
  usage: ProviderUsage;
  stopReason: string | null;
};

export type SanitizerFinding = {
  code: string;
  severity: "info" | "warning" | "error";
  classification: string;
  hardGate: boolean;
  path?: string | null;
};

export type SanitizerPolicyBindingIdentity = {
  caseInputIdentityDigest: string;
  policyVersion: number;
  policyDigest: string;
};

export type SanitizerRequest = {
  caseInputIdentity: CaseInputIdentity;
  documentKind: string;
  policyEnvelope: JsonRecord;
  policy: JsonRecord;
  policyVersion: number;
  policyDigest: string;
  policyBindingDigest: string;
  document: JsonValue;
  provider: SanitizerProviderMetadata;
  provenance: {
    harnessVersion: string;
    harnessCommit: string | null;
    promptVersion: string;
    preprocessVersion: string;
    sourceCommit: string | null;
  };
};

export type SanitizerResponse = {
  sanitizedDocument: JsonValue;
  sanitizerId: string;
  protocolVersion: 1;
  policyVersion: number;
  policyDigest: string;
  caseInputIdentityVersion: 1;
  caseInputIdentityDigest: string;
  policyTargetIdentityDigest: string;
  policyBindingDigest: string;
  findings?: SanitizerFinding[];
};

export interface Sanitizer {
  readonly id: string;
  readonly protocolVersion: 1;
  sanitize(request: SanitizerRequest, signal?: AbortSignal): Promise<SanitizerResponse>;
}

export type SanitizerSettings = {
  required: boolean;
  sanitizer?: Sanitizer;
  allowedFindingPathPatterns?: readonly string[];
  expectedSanitizerId?: string;
  expectedProtocolVersion?: 1;
  policyEnvelopeBytes?: Uint8Array;
  expectedPolicyVersion?: number;
  expectedPolicyDigest?: string;
  expectedCaseInputIdentityVersion?: 1;
  expectedCaseInputIdentityDigest?: string;
  expectedPolicyBindingDigest?: string;
  timeoutMs?: number;
};

export type RunBundleOptions = {
  bundleDirectory: string;
  attemptRoot: string;
  provider: Provider;
  requestedModel?: string | null;
  requestedEffort?: string | null;
  maxTokens?: number | null;
  attemptKey?: string;
  phase?: string;
  harnessVersion?: string;
  harnessCommit?: string | null;
  sanitizerRequirement: SanitizerRequirementSettings;
  approval?: ApprovalSettings;
  sanitizer?: SanitizerSettings;
  contractSchemaPath?: string;
  providerTimeoutMs?: number;
};

export type RunResult = {
  phase: string;
  attemptDirectory: string;
  attemptId: string;
  runId: string;
  attemptKey: string;
  caseId: string;
  documentSha256: string;
};
