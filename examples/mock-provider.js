#!/usr/bin/env node

let input = "";
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
if (request.version !== 1 || typeof request.imagePath !== "string") process.exit(2);
process.stdout.write(JSON.stringify({
  invoiceNumber: "SYNTH-001",
  total: 42.5,
  lines: [{ description: "Synthetic item", quantity: 2 }]
}));
