import assert from "node:assert/strict";
import test from "node:test";

import {
  encodeCommandSanitizerRequest,
  MAX_COMMAND_SANITIZER_REQUEST_BYTES,
  parseCommandSanitizerResponse,
  snapshotCommandSanitizerRequest,
} from "../src/runner/command-sanitizer-wire.js";
import { computeCaseInputIdentity, computePolicyBindingDigest } from "../src/runner/identity.js";
import type { SanitizerRequest } from "../src/runner/types.js";

const POLICY_DIGEST = "a".repeat(64);

function validRequest(): SanitizerRequest {
  const identity = computeCaseInputIdentity({
    caseId: "synthetic-case",
    documentKind: "synthetic_document",
    preparedImage: {
      mediaType: "image/png",
      sha256: "b".repeat(64),
    },
  });
  const policyBindingDigest = computePolicyBindingDigest({
    caseInputIdentityDigest: identity.digest,
    policyVersion: 1,
    policyDigest: POLICY_DIGEST,
  });
  const policy = { syntheticRule: "remove-synthetic-field" };
  return {
    caseInputIdentity: identity,
    documentKind: identity.documentKind,
    policyEnvelope: {
      envelopeVersion: 1,
      target: {
        identityVersion: 1,
        caseId: identity.caseId,
        documentKind: identity.documentKind,
        preparedImage: identity.preparedImage,
        caseInputIdentityDigest: identity.digest,
      },
      policyVersion: 1,
      policy,
    },
    policy,
    policyVersion: 1,
    policyDigest: POLICY_DIGEST,
    policyBindingDigest,
    document: { syntheticPrivateField: "SYNTHETIC-PRIVATE-VALUE" },
    provider: {
      id: "synthetic-provider",
      route: "synthetic-route",
      requested: { model: null, effort: null, maxTokens: null },
      respondedModel: null,
      effectiveEffort: null,
      usage: { available: false },
      stopReason: null,
    },
    provenance: {
      harnessVersion: "synthetic-harness",
      harnessCommit: null,
      promptVersion: "synthetic-prompt",
      preprocessVersion: "synthetic-preprocess",
      sourceCommit: null,
    },
  };
}

function validResponse(request = snapshotCommandSanitizerRequest(validRequest())): object {
  return {
    responseVersion: 1,
    sanitizedDocument: { syntheticSafeField: "SYNTHETIC-SAFE-VALUE" },
    sanitizerId: "synthetic-sanitizer",
    protocolVersion: 1,
    policyVersion: request.policyVersion,
    policyDigest: request.policyDigest,
    caseInputIdentityVersion: 1,
    caseInputIdentityDigest: request.caseInputIdentity.digest,
    policyTargetIdentityDigest: request.caseInputIdentity.digest,
    policyBindingDigest: request.policyBindingDigest,
    findings: [
      {
        code: "synthetic-finding",
        severity: "warning",
        classification: "synthetic-classification",
        hardGate: false,
        path: "/syntheticPrivateField",
      },
    ],
  };
}

test("snapshots and encodes one target-bound sanitizer request", () => {
  const source = validRequest();
  const snapshot = snapshotCommandSanitizerRequest(source);
  source.document = { mutated: true };
  source.policy.syntheticRule = "mutated";

  assert.equal(snapshot.requestVersion, 1);
  assert.equal("policy" in snapshot, false);
  assert.deepEqual(snapshot.document, { syntheticPrivateField: "SYNTHETIC-PRIVATE-VALUE" });
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.caseInputIdentity), true);
  const encoded = encodeCommandSanitizerRequest(snapshot);
  try {
    assert.equal(encoded.at(-1), 0x0a);
    assert.deepEqual(JSON.parse(encoded.toString("utf8")), snapshot);
  } finally {
    encoded.fill(0);
  }
});

test("rejects unbound, incomplete, unknown, and hostile requests", () => {
  const mismatchedDocumentKind = validRequest();
  mismatchedDocumentKind.documentKind = "other_document";
  const mismatchedPolicy = validRequest();
  mismatchedPolicy.policy = { syntheticRule: "different" };
  const mismatchedBinding = validRequest();
  mismatchedBinding.policyBindingDigest = "c".repeat(64);
  const unknownField = { ...validRequest(), syntheticUnknown: true } as never;
  const missingField = validRequest() as Partial<SanitizerRequest>;
  delete missingField.provider;
  const hostile = Object.defineProperty(validRequest(), "document", {
    enumerable: true,
    get: () => {
      throw new Error("SYNTHETIC-PRIVATE-VALUE");
    },
  });

  for (const candidate of [
    mismatchedDocumentKind,
    mismatchedPolicy,
    mismatchedBinding,
    unknownField,
    missingField as SanitizerRequest,
    hostile,
  ]) {
    assert.throws(() => snapshotCommandSanitizerRequest(candidate));
  }
});

test("applies the request limit to wire bytes after removing duplicate policy", () => {
  const request = validRequest();
  const policy = { syntheticPayload: "p".repeat(4_100_000) };
  request.policy = policy;
  request.policyEnvelope.policy = policy;
  request.document = { syntheticPayload: "d".repeat(8_700_000) };

  const snapshot = snapshotCommandSanitizerRequest(request);
  const encoded = encodeCommandSanitizerRequest(snapshot);
  try {
    assert.equal(encoded.byteLength < MAX_COMMAND_SANITIZER_REQUEST_BYTES, true);
    assert.equal(Buffer.byteLength(JSON.stringify(request)) > MAX_COMMAND_SANITIZER_REQUEST_BYTES, true);
  } finally {
    encoded.fill(0);
  }

  const oversized = validRequest();
  oversized.document = { syntheticPayload: "x".repeat(MAX_COMMAND_SANITIZER_REQUEST_BYTES) };
  const oversizedSnapshot = snapshotCommandSanitizerRequest(oversized);
  assert.throws(() => encodeCommandSanitizerRequest(oversizedSnapshot));
});

test("parses one strict response and binds every identity", () => {
  const request = snapshotCommandSanitizerRequest(validRequest());
  const parsed = parseCommandSanitizerResponse(
    Buffer.from(JSON.stringify(validResponse(request))),
    "synthetic-sanitizer",
    request,
  );

  assert.deepEqual(parsed.sanitizedDocument, {
    syntheticSafeField: "SYNTHETIC-SAFE-VALUE",
  });
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.findings), true);
});

test("rejects malformed, duplicate, unknown, and unbound responses", () => {
  const request = snapshotCommandSanitizerRequest(validRequest());
  const base = validResponse(request) as Record<string, unknown>;
  const missingField = { ...base };
  delete missingField.policyDigest;
  const cases: Uint8Array[] = [
    Uint8Array.of(0xff),
    Buffer.from('{"responseVersion":1,"responseVersion":1}'),
    Buffer.from(`${JSON.stringify(base)} trailing`),
    Buffer.from(`\n${JSON.stringify(base)}`),
    Buffer.from(`${JSON.stringify(base)}\n`),
    Buffer.from(JSON.stringify(missingField)),
    Buffer.from(JSON.stringify({ ...base, syntheticUnknown: true })),
    Buffer.from(JSON.stringify({ ...base, policyBindingDigest: "d".repeat(64) })),
    Buffer.from(
      JSON.stringify({
        ...base,
        findings: [
          {
            code: "synthetic-finding",
            severity: "warning",
            classification: "synthetic-classification",
            hardGate: false,
            path: "/invalid~path",
          },
        ],
      }),
    ),
  ];

  for (const bytes of cases) {
    assert.throws(() =>
      parseCommandSanitizerResponse(bytes, "synthetic-sanitizer", request),
    );
  }
});
