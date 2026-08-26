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

test("decodes escaped strings without skipping the following character", () => {
  const cases: Array<[string, unknown]> = [
    ['"\\u0061"', "a"],
    ['"x\\u0061"', "xa"],
    ['"\\u0061x"', "ax"],
    ['{"name":"\\u0061"}', { name: "a" }],
    ['["\\u0061", "x"]', ["a", "x"]],
  ];

  for (const [source, expected] of cases) {
    assert.deepEqual(parseJson(source, "probe"), expected, source);
  }
});

test("rejects duplicate object members after decoding escaped names", () => {
  const duplicateKeys = [
    '{"a/b":1,"a\\/b":2}',
    '{"a\\"b":1,"a\\u0022b":2}',
    '{"a\\\\b":1,"a\\u005Cb":2}',
    '{"ax":1,"\\u0061x":2}',
    '{"😀":1,"\\uD83D\\uDE00":2}',
  ];

  for (const source of duplicateKeys) {
    assert.throws(
      () => parseJson(source, "probe"),
      (error: unknown) =>
        error instanceof JsonContractError &&
        error.message === "probe is not valid JSON: contains a duplicate object member",
      source,
    );
  }
});

test("parseJson rejects numbers outside the binary64 domain", () => {
  assert.throws(
    () => parseJson("1e400", "probe"),
    (error: unknown) =>
      error instanceof JsonContractError &&
      error.message === "probe is not valid JSON: contains a number outside the binary64 domain",
  );
  assert.throws(() => parseJson('{"n":-1e400}', "probe"));
  // Large-but-finite integers are allowed; binary64 rounding is the declared
  // v1 semantics and documented in docs/bundle-v1.md.
  assert.deepEqual(parseJson("9007199254740993", "probe"), 9007199254740992);
});

test("parseJson keeps ordinary documents working", () => {
  const value = parseJson('{"a":[1,2,{"b":null}],"c":"x"}', "probe");
  assert.deepEqual(value, { a: [1, 2, { b: null }], c: "x" });
});
