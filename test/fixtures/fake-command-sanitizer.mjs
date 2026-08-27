import { appendFile, readdir, stat, writeFile } from "node:fs/promises";

const mode = process.argv[2] ?? "success";
const markerPath = process.argv[3];

if (mode === "spawn-marker") {
  if (markerPath !== undefined) await writeFile(markerPath, "spawned", "utf8");
  setInterval(() => undefined, 1_000);
} else {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const bytes = Buffer.concat(chunks);
  const source = bytes.toString("utf8");
  const request = JSON.parse(source);

  if (mode === "record-spawn-and-hang") {
    if (markerPath !== undefined) {
      await writeFile(markerPath, JSON.stringify({ cwd: process.cwd() }), "utf8");
    }
    setInterval(() => undefined, 1_000);
  } else if (mode === "nonzero") {
    process.stderr.write("synthetic child failure\n");
    process.exitCode = 7;
  } else if (mode === "invalid-json") {
    process.stdout.write("{not-json");
  } else if (mode === "duplicate-json") {
    process.stdout.write('{"responseVersion":1,"responseVersion":1}');
  } else if (mode === "unknown-field") {
    process.stdout.write(JSON.stringify({ ...response(request), unexpected: true }));
  } else if (mode === "bad-finding") {
    const value = response(request);
    value.findings = [{
      code: "synthetic-finding",
      severity: "warning",
      classification: "synthetic-class",
      hardGate: false,
      nested: "unexpected",
    }];
    process.stdout.write(JSON.stringify(value));
  } else if (mode === "identity-mismatch") {
    const value = response(request);
    value.policyBindingDigest = "0".repeat(64);
    process.stdout.write(JSON.stringify(value));
  } else if (mode === "overflow") {
    process.stdout.write("x".repeat(256 * 1024));
    setInterval(() => undefined, 1_000);
  } else if (mode === "stderr-overflow") {
    process.stderr.write("x".repeat(256 * 1024));
    setInterval(() => undefined, 1_000);
  } else if (mode === "inspect") {
    const cwdStat = await stat(process.cwd());
    const environmentKeys = Object.keys(process.env).sort();
    const rawMarker = request.document.syntheticRawMarker;
    const policyMarker = request.policyEnvelope.policy.syntheticPolicyMarker;
    if (
      request.requestVersion !== 1 ||
      !source.endsWith("\n") ||
      source.slice(0, -1).includes("\n") ||
      (await readdir(process.cwd())).length !== 0 ||
      process.argv.includes(rawMarker) ||
      process.argv.includes(policyMarker) ||
      Object.values(process.env).includes(rawMarker) ||
      Object.values(process.env).includes(policyMarker)
    ) {
      process.exitCode = 8;
    } else {
      const value = response(request);
      value.sanitizedDocument = {
        syntheticSanitized: true,
        cwdPrivate: process.platform === "win32" || (cwdStat.mode & 0o777) === 0o700,
        cwdEmpty: true,
        environmentKeys,
        allowedValue: process.env.SYNTHETIC_SANITIZER_ALLOWED ?? null,
        requestKeys: Object.keys(request).sort(),
        stdinEndedWithLf: true,
      };
      value.findings = [{
        code: "synthetic-finding",
        severity: "warning",
        classification: "synthetic-class",
        hardGate: false,
        path: "/synthetic",
      }];
      process.stdout.write(JSON.stringify(value));
    }
  } else if (mode === "raw-error") {
    process.stderr.write(String(request.document.syntheticRawMarker));
    process.stderr.write(String(request.policyEnvelope.policy.syntheticPolicyMarker));
    process.exitCode = 9;
  } else if (mode === "write-cwd-marker") {
    await appendFile("synthetic-output", "not allowed to survive cleanup", "utf8");
    process.stdout.write(JSON.stringify(response(request)));
  } else {
    process.stdout.write(JSON.stringify(response(request)));
  }
}

function response(request) {
  return {
    responseVersion: 1,
    sanitizedDocument: request.document,
    sanitizerId: "synthetic-command-sanitizer",
    protocolVersion: 1,
    policyVersion: request.policyVersion,
    policyDigest: request.policyDigest,
    caseInputIdentityVersion: request.caseInputIdentity.identityVersion,
    caseInputIdentityDigest: request.caseInputIdentity.digest,
    policyTargetIdentityDigest: request.policyEnvelope.target.caseInputIdentityDigest,
    policyBindingDigest: request.policyBindingDigest,
    findings: [{
      code: "synthetic-finding",
      severity: "warning",
      classification: "synthetic-class",
      hardGate: false,
      path: "/synthetic/private-path",
    }],
  };
}
