// Verify the exact patterns shipped in schemas/bundle-v1.schema.json (run: node scripts/verify-pointer-patterns.mjs)
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

// plainPointer: literal inner '*', whole-star segments rejected
[
  ["/customer/name", true], ["/li*nes", true], ["/x*y/z", true], ["/li**nes", true],
  ["/a/b/c", true], ["/a~1b/c~0d", true], ["/lines", true], ["/invoiceNumber", true],
  ["/", false], ["/a/", false], ["/*", false], ["/a/*", false], ["/*/x", false],
  ["a", false], ["a/b", false], ["/a//b", false], ["/~2x", false], ["/a~b", false], ["/~1", true],
].forEach(([s, e]) => chk("plain", "plainPointer", s, e));

// relativeFieldPointer
[
  ["/amount", true], ["/line*No", true], ["/a~1b", true], ["/", false], ["/*", false],
  ["/a/b", false], ["x", false],
].forEach(([s, e]) => chk("relField", "relativeFieldPointer", s, e));

// criticalPointer: multi-segment scalar branch + single wildcard branch
[
  ["/totalAmount", true], ["/customer/name", true], ["/x/y/amount", true],
  ["/lines/*/amount", true], ["/a/*/b", true], ["/a/b/*/c", true], ["/li*nes/*/amount", true],
  ["/", false], ["/*", false], ["/*/x", false], ["/a/*", false], ["/a/**", false],
  ["/a/*/b/c", false],
].forEach(([s, e]) => chk("critical", "criticalPointer", s, e));

console.log(bad === 0 ? "ALL SHIPPED PATTERN TESTS PASS" : `${bad} FAILURES`);
