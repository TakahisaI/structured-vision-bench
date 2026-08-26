import { readFile } from "node:fs/promises";
import path from "node:path";

import { listTextFiles } from "./files.mjs";

const SECRET_PATTERNS = [
  ["macOS absolute user path", /\/Users\/[A-Za-z0-9._-]+\//u],
  ["Linux absolute user path", /\/home\/[A-Za-z0-9._-]+\//u],
  ["Windows absolute user path", /[A-Za-z]:\\Users\\[^\\\s]+\\/u],
  ["OpenAI-style secret", /\bsk-[A-Za-z0-9_-]{12,}\b/u],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u],
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u],
  ["assigned API key", /\b[A-Z0-9_]*API_KEY\s*=\s*[^\s$<{][^\s]*/u],
];

const violations = [];
const files = await listTextFiles();

for (const file of files) {
  const relative = path.relative(process.cwd(), file);
  const source = await readFile(file, "utf8");

  if (/\r/u.test(source)) violations.push(`${relative}: CR line ending`);
  if (/[ \t]+$/mu.test(source)) violations.push(`${relative}: trailing whitespace`);
  if (!source.endsWith("\n")) violations.push(`${relative}: missing final newline`);
  if (/\t/u.test(source) && /\.(?:[cm]?[jt]s|json|ya?ml)$/u.test(relative)) {
    violations.push(`${relative}: tab character in source/config`);
  }

  for (const [label, pattern] of SECRET_PATTERNS) {
    if (pattern.test(source)) violations.push(`${relative}: prohibited ${label}`);
  }
}

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
if (packageJson.private !== true) violations.push("package.json: private must remain true");

const workflow = await readFile(".github/workflows/ci.yml", "utf8");
for (const command of ["codex", "app-server", "openai", "anthropic", "curl ", "wget "]) {
  if (workflow.toLowerCase().includes(command)) {
    violations.push(`.github/workflows/ci.yml: external-provider command is forbidden: ${command}`);
  }
}

if (violations.length > 0) {
  for (const violation of violations) console.error(violation);
  process.exitCode = 1;
}
