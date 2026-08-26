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

// plainPointer: leading single star literals accepted (P1 fix), whole-star
// segments reserved, escapes validated.
[
  ["/*field", true], ["/rows/*id", true], ["/*~0", true], ["/items/*code", true],
  ["/**", true], ["/a/**", true], ["/**/b", true], ["/***", true],
  ["/li*nes", true], ["/li**nes", true], ["/x*y/z", true],
  ["/customer/name", true], ["/a~1b/c~0d", true], ["/lines", true], ["/~1", true],
  ["/*", false], ["/a/*", false], ["/*/x", false],
  ["/", false], ["/a/", false], ["a", false], ["a/b", false], ["/a//b", false],
  ["/~2x", false], ["/a~b", false],
].forEach(([s, e]) => chk("plain", "plainPointer", s, e));

[
  ["/*field", true], ["/amount", true], ["/**", true], ["/a~1b", true],
  ["/*", false], ["/", false], ["/a/b", false], ["x", false], ["/a/", false],
].forEach(([s, e]) => chk("relField", "relativeFieldPointer", s, e));

// NOTE: "/totalAmount" (no wildcard) and "/lines/**" (literal '**', no
// whole-star segment) pass the SYNTAX level as plain pointers; whether they
// name a declared array or a compared field is enforced at cross-field level
// by comparison_contract_invalid.
[
  // scalar branch
  ["/totalAmount", true], ["/header/total", true], ["/rows/*id", true],
  ["/lines/**", true],
  // wildcard branch — including literal names containing stars on either side
  ["/lines/*/amount", true], ["/li*nes/*/amount", true],
  ["/*array/*/value", true], ["/lines/*/*field", true], ["/**/*/b", true],
  // rejected shapes
  ["/*", false], ["/*/x", false], ["/a/*", false],
].forEach(([s, e]) => chk("critical", "criticalPointer", s, e));

console.log(bad === 0 ? "ALL SHIPPED PATTERN TESTS PASS" : `${bad} FAILURES`);
process.exitCode = bad === 0 ? 0 : 1;
