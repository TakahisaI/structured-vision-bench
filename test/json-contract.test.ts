import assert from "node:assert/strict";
import { decodeUtf8Strict, JsonContractError, parseJson } from "../src/bundle/json.js";
import test from "node:test";

const encoder = new TextEncoder();

test("decodeUtf8Strict rejects invalid UTF-8 instead of replacing with U+FFFD", () => {
  // Raw bytes: '{"a":"<0xFF 0xFE>"}' — 0xFF/0xFE are never valid UTF-8.
  const invalid = new Uint8Array([0x22, 0x61, 0x3a, 0x22, 0xff, 0xfe, 0x22, 0x7d]);
  assert.throws(
    () => decodeUtf8Strict(invalid, "probe"),
    (error: unknown) => error instanceof JsonContractError,
  );
  // Valid multi-byte content still decodes.
  assert.equal(decodeUtf8Strict(encoder.encode('{"a":"円"}'), "probe"), '{"a":"円"}');
});

test("parseJson rejects duplicate object members", () => {
  assert.throws(() => parseJson('{"amount":100,"amount":200}', "probe"));
  // Nested duplicates are also caught.
  assert.throws(() => parseJson('{"outer":{"x":1,"x":2}}', "probe"));
  // Distinct members are fine.
  assert.deepEqual(parseJson('{"amount":100,"other":200}', "probe"), { amount: 100, other: 200 });
});

test("parseJson rejects numbers outside the binary64 domain", () => {
  assert.throws(() => parseJson("1e400", "probe")); // would become Infinity
  assert.throws(() => parseJson('{"n":-1e400}', "probe"));
  // Large-but-finite integers are allowed; binary64 rounding is the declared
  // v1 semantics and documented in docs/bundle-v1.md.
  assert.deepEqual(parseJson("9007199254740993", "probe"), 9007199254740992);
});

test("parseJson keeps ordinary documents working", () => {
  const value = parseJson('{"a":[1,2,{"b":null}],"c":"x"}', "probe");
  assert.deepEqual(value, { a: [1, 2, { b: null }], c: "x" });
});
