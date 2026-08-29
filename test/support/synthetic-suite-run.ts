import {
  computeCaseInputIdentity,
  createSanitizerRequirementDecision,
  type SanitizerRequirementVerifier,
} from "../../src/runner/identity.js";
import {
  computeCasePolicyMapDigest,
  computeSuitePlanDigest,
  deriveSuiteAttemptKey,
  type SuiteCasePlan,
  type SuitePreflightPlan,
} from "../../src/suite/preflight.js";
import {
  createSuiteRunManifest,
  type SuiteRunManifest,
} from "../../src/suite/run-manifest.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

export function syntheticSuiteRunManifest(): SuiteRunManifest {
  const verifier: SanitizerRequirementVerifier = {
    id: "synthetic-verifier",
    version: "v1",
    derive: () => ({
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: "synthetic-commit",
    }),
  };
  const caseInputIdentity = computeCaseInputIdentity({
    caseId: "synthetic-private-case",
    documentKind: "synthetic-private-kind",
    preparedImage: { mediaType: "image/png", sha256: DIGEST_A },
  });
  const sanitizerRequirement = createSanitizerRequirementDecision(
    {
      sanitizerRequired: false,
      policyRequired: false,
      sanitizerRequirementReason: "not-required",
      consumerSourceCommit: "synthetic-commit",
    },
    verifier,
  );
  const cases: SuiteCasePlan[] = [
    {
      caseIndex: 0,
      bundlePath: "SYNTHETIC_PRIVATE_BUNDLE",
      bundleManifestDigest: DIGEST_B,
      caseInputIdentity,
      sanitizerRequirement,
    },
  ];
  const casePolicyMapDigest = computeCasePolicyMapDigest(cases);
  const suiteDigest = "c".repeat(64);
  const plan: SuitePreflightPlan = {
    suiteVersion: 1,
    suiteId: "synthetic-suite",
    suiteDigest,
    suitePlanDigest: computeSuitePlanDigest(suiteDigest, casePolicyMapDigest),
    casePolicyMapDigest,
    provider: {
      id: "synthetic-provider",
      route: "synthetic-route",
      implementationVersion: "v1",
      protocolVersion: "v1",
      requested: { model: "synthetic-model", effort: null, maxTokens: 256 },
    },
    phase: "synthetic-phase",
    repeat: 1,
    requirementVerifier: {
      id: verifier.id,
      version: verifier.version,
      consumerSourceCommit: "synthetic-commit",
    },
    cases,
    slots: [{ caseIndex: 0, repeatIndex: 0, attemptKey: deriveSuiteAttemptKey(0, 0) }],
  };
  return createSuiteRunManifest(plan);
}
