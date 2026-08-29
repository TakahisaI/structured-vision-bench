import assert from "node:assert/strict";
import test from "node:test";

import {
  ARTIFACT_IDENTITY_VERSION,
  computeArtifactIdentity,
  type ArtifactIdentityInput,
} from "../src/runner/identity.js";

const ARTIFACT_INPUT = {
  attemptId: "a".repeat(64),
  documentSha256: "b".repeat(64),
  sanitizer: {
    id: "synthetic-sanitizer",
    protocolVersion: 1,
    bindingDigest: "c".repeat(64),
    findings: [
      {
        code: "synthetic_name_missing",
        severity: "warning",
        classification: "synthetic_pii",
        hardGate: false,
        path: "/synthetic/name",
      },
      {
        code: "synthetic_total_blocked",
        severity: "error",
        classification: "synthetic_policy",
        hardGate: true,
        path: null,
      },
    ],
  },
} as const satisfies ArtifactIdentityInput;

test("computes the artifact identity v1 fixed vector", () => {
  assert.equal(ARTIFACT_IDENTITY_VERSION, 1);
  assert.deepEqual(computeArtifactIdentity(ARTIFACT_INPUT), {
    artifactIdentityVersion: 1,
    artifactId: "e507f227ac07016996a5185b4051762dce536a2c3cadf4e41100ee673d8265ed",
  });
  assert.deepEqual(
    computeArtifactIdentity({
      attemptId: ARTIFACT_INPUT.attemptId,
      documentSha256: ARTIFACT_INPUT.documentSha256,
      sanitizer: null,
    }),
    {
      artifactIdentityVersion: 1,
      artifactId: "e88df24d0b6e0c4274d4b96a8db79c42bb4e253b51491f92f927374ee36f72e3",
    },
  );
});

test("commits ordered finding tuples, attributes, paths, and sanitizer binding", () => {
  const base = computeArtifactIdentity(ARTIFACT_INPUT).artifactId;
  const [first, second] = ARTIFACT_INPUT.sanitizer.findings;
  assert.notEqual(
    computeArtifactIdentity({
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, findings: [second, first] },
    }).artifactId,
    base,
  );
  const attributeAndPathSwaps: ArtifactIdentityInput["sanitizer"][] = [
    {
      ...ARTIFACT_INPUT.sanitizer,
      findings: [
        { ...first, code: second.code },
        { ...second, code: first.code },
      ],
    },
    {
      ...ARTIFACT_INPUT.sanitizer,
      findings: [
        { ...first, severity: second.severity },
        { ...second, severity: first.severity },
      ],
    },
    {
      ...ARTIFACT_INPUT.sanitizer,
      findings: [
        { ...first, classification: second.classification },
        { ...second, classification: first.classification },
      ],
    },
    {
      ...ARTIFACT_INPUT.sanitizer,
      findings: [
        { ...first, hardGate: second.hardGate },
        { ...second, hardGate: first.hardGate },
      ],
    },
    {
      ...ARTIFACT_INPUT.sanitizer,
      findings: [
        { ...first, path: second.path },
        { ...second, path: first.path },
      ],
    },
  ];
  for (const sanitizer of attributeAndPathSwaps) {
    assert.notEqual(
      computeArtifactIdentity({ ...ARTIFACT_INPUT, sanitizer }).artifactId,
      base,
    );
  }
  assert.notEqual(
    computeArtifactIdentity({
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, bindingDigest: "d".repeat(64) },
    }).artifactId,
    base,
  );
  assert.notEqual(
    computeArtifactIdentity({
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, id: "synthetic-sanitizer-v2" },
    }).artifactId,
    base,
  );
  assert.notEqual(
    computeArtifactIdentity({ ...ARTIFACT_INPUT, attemptId: "d".repeat(64) }).artifactId,
    base,
  );
  assert.notEqual(
    computeArtifactIdentity({ ...ARTIFACT_INPUT, documentSha256: "d".repeat(64) }).artifactId,
    base,
  );
});

test("rejects malformed artifact identity inputs", () => {
  const sparseFindings = new Array(1);
  const findingsWithProperty = [...ARTIFACT_INPUT.sanitizer.findings] as unknown[] & {
    extra?: string;
  };
  findingsWithProperty.extra = "synthetic";
  const invalidInputs: unknown[] = [
    undefined,
    { ...ARTIFACT_INPUT, document: { synthetic: "value" } },
    { ...ARTIFACT_INPUT, attemptId: "A".repeat(64) },
    { ...ARTIFACT_INPUT, documentSha256: "b".repeat(63) },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, id: "synthetic sanitizer" },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, protocolVersion: 2 },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, bindingDigest: null },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, findings: new Array(101).fill({}) },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, findings: sparseFindings },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: { ...ARTIFACT_INPUT.sanitizer, findings: findingsWithProperty },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: {
        ...ARTIFACT_INPUT.sanitizer,
        findings: [{ ...ARTIFACT_INPUT.sanitizer.findings[0], path: "/synthetic/*" }],
      },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: {
        ...ARTIFACT_INPUT.sanitizer,
        findings: [
          {
            code: "synthetic_code",
            severity: "warning",
            classification: "synthetic_classification",
            hardGate: false,
          },
        ],
      },
    },
    {
      ...ARTIFACT_INPUT,
      sanitizer: {
        ...ARTIFACT_INPUT.sanitizer,
        findings: [{ ...ARTIFACT_INPUT.sanitizer.findings[0], message: "synthetic value" }],
      },
    },
  ];

  for (const input of invalidInputs) {
    assert.throws(
      () => computeArtifactIdentity(input as ArtifactIdentityInput),
      /artifact identity input is invalid/u,
    );
  }
});
