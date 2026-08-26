// Verify the exact patterns shipped in schemas/bundle-v1.schema.json.
// Wired into `npm test` via test/pointer-pattern.test.ts; this script exists
// for manual spot checks (run: node scripts/verify-pointer-patterns.mjs).
import { readFileSync } from "node:fs";

const schema = JSON.parse(readFileSync("schemas/bundle-v1.schema.json", "utf8"));
const defs = schema.$defs;

let bad = 0;
function chk(name, defName, s, expected) {
  const got = new RegExp(defs[defName].pattern, "u").test(s);
  if (got !== expected) {
    console.log(`FAIL ${name} ${defName} ${JSON.stringify(s)} want=${expected} got=${got}`);
    bad += 1;
  }
}

// plainPointer: literal '*' anywhere in a segment, including '**'
[
  ["/customer/name", true], ["/li*nes", true], ["/x*y/z", true], ["/li**nes", true],
  ["/**", true], ["/a/**", true], ["/**/b", true], ["/***", true],
  ["/a/b/c", true], ["/a~1b/c~0d", true], ["/lines", true], ["/invoiceNumber", true], ["/~1", true],
  ["/", false], ["/a/", false], ["/*", false], ["/a/*", false], ["/*/x", false],
  ["a", false], ["a/b", false], ["/a//b", false], ["/~2x", false], ["/a~b", false],
].forEach(([s, e]) => chk("plain", "plainPointer", s, e));

// relativeFieldPointer
[
  ["/amount", true], ["/line*No", true], ["/**", true], ["/a~1b", true],
  ["/", false], ["/*", false], ["/a/b", false], ["x", false], ["/a/", false],
].forEach(([s, e]) => chk("relField", "relativeFieldPointer", s, e));

// criticalPointer: multi-segment scalar branch + single wildcard branch.
// NOTE: "/a/**", "/lines/**", "/a/**/c" pass the SYNTAX level (plain pointers
// with literal '**' are legal); whether they name a declared array or a
// compared field is enforced at cross-field level by comparison_contract_invalid.
[
  ["/totalAmount", true], ["/customer/name", true], ["/x/y/amount", true],
  ["/lines/*/amount", true], ["/a/*/b", true], ["/a/b/*/c", true], ["/li*nes/*/amount", true],
  // array path "/**" is a legal literal name; wildcard to /b keeps a valid shape:
  ["/**/*/b", true],
  ["/a/**", true], ["/lines/**", true], ["/a/**/c", true],
  ["/", false], ["/*", false], ["/*/x", false], ["/a/*", false],
  ["/*/b", false],
  ["/a/*/b/c", false],
].forEach(([s, e]) => chk("critical", "criticalPointer", s, e));

console.log(bad === 0 ? "ALL SHIPPED PATTERN TESTS PASS" : `${bad} FAILURES`);
process.exitCode = bad === 0 ? 0 : 1;
