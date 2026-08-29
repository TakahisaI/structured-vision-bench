export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export class JsonContractError extends Error {}

const applyIntrinsic = Reflect.apply;
const arrayIsArrayIntrinsic = Array.isArray;
const jsonParseIntrinsic = JSON.parse;
const jsonStringifyIntrinsic = JSON.stringify;
const numberIntrinsic = Number;
const numberIsFiniteIntrinsic = Number.isFinite;
const numberParseIntIntrinsic = Number.parseInt;
const objectCreateIntrinsic = Object.create;
const objectGetOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOfIntrinsic = Object.getPrototypeOf;
const objectHasOwnIntrinsic = Object.hasOwn;
const objectKeysIntrinsic = Object.keys;
const objectPrototypeIntrinsic = Object.prototype;
const regExpTestIntrinsic = RegExp.prototype.test;
const setAddIntrinsic = Set.prototype.add;
const setHasIntrinsic = Set.prototype.has;
const SetIntrinsic = Set;
const stringCharCodeAtIntrinsic = String.prototype.charCodeAt;
const stringFromCharCodeIntrinsic = String.fromCharCode;
const stringSliceIntrinsic = String.prototype.slice;
const stringStartsWithIntrinsic = String.prototype.startsWith;
const structuredCloneIntrinsic = structuredClone;
const TextDecoderIntrinsic = TextDecoder;
const textDecoderDecodeIntrinsic = TextDecoderIntrinsic.prototype.decode;
const TextEncoderIntrinsic = TextEncoder;
const textEncoderEncodeIntrinsic = TextEncoderIntrinsic.prototype.encode;
const weakSetAddIntrinsic = WeakSet.prototype.add;
const weakSetDeleteIntrinsic = WeakSet.prototype.delete;
const weakSetHasIntrinsic = WeakSet.prototype.has;
const WeakSetIntrinsic = WeakSet;

export function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  const prototype =
    typeof value === "object" && value !== null
      ? objectGetPrototypeOfIntrinsic(value)
      : undefined;
  return (
    typeof value === "object" &&
    value !== null &&
    !arrayIsArrayIntrinsic(value) &&
    (prototype === objectPrototypeIntrinsic || prototype === null)
  );
}

export function isJsonValue(
  value: unknown,
  seen = new WeakSetIntrinsic<object>(),
): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return numberIsFiniteIntrinsic(value);
  if (typeof value !== "object") return false;
  if (applyIntrinsic(weakSetHasIntrinsic, seen, [value])) return false;
  applyIntrinsic(weakSetAddIntrinsic, seen, [value]);
  try {
    if (arrayIsArrayIntrinsic(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (objectHasOwnIntrinsic(value, index) && !isJsonValue(value[index], seen)) {
          return false;
        }
      }
      return true;
    }
    if (!isJsonObject(value)) return false;
    const keys = objectKeysIntrinsic(value);
    for (let index = 0; index < keys.length; index += 1) {
      const property = objectGetOwnPropertyDescriptorIntrinsic(value, keys[index]!);
      if (
        property === undefined ||
        !("value" in property) ||
        !isJsonValue(property.value, seen)
      ) {
        return false;
      }
    }
    return true;
  } finally {
    applyIntrinsic(weakSetDeleteIntrinsic, seen, [value]);
  }
}

/**
 * Decodes UTF-8 bytes strictly. Invalid byte sequences throw instead of being
 * silently replaced with U+FFFD, and a leading UTF-8 BOM is rejected so every
 * reader of the same bundle sees the same characters.
 */
export function decodeUtf8Strict(bytes: Uint8Array, label: string): string {
  if (startsWithUtf8Bom(bytes)) {
    throw new JsonContractError(`${label} must not start with a UTF-8 BOM`);
  }
  try {
    const decoder = new TextDecoderIntrinsic("utf-8", { fatal: true, ignoreBOM: true });
    return applyIntrinsic(textDecoderDecodeIntrinsic, decoder, [bytes]) as string;
  } catch {
    throw new JsonContractError(`${label} is not valid UTF-8`);
  }
}

/**
 * Parses JSON under the v1 exactness contract:
 * - invalid UTF-8 is rejected (no U+FFFD replacement);
 * - strings contain only Unicode scalar values;
 * - duplicate object members are rejected instead of silently last-wins;
 * - every number must fit the IEEE-754 binary64 domain without overflow.
 *
 * The source is scanned once for structure and member uniqueness, then handed
 * to JSON.parse for value construction with a non-finite guard as backstop.
 */
export function parseJson(source: string, label: string): JsonValue {
  scanJsonContract(source, label);
  let parsed: unknown;
  try {
    parsed = jsonParseIntrinsic(source);
  } catch {
    // The scanner accepted it, so this is unreachable in practice; kept as a
    // safety net that never leaks internals.
    throw new Error(`${label} is not valid JSON`);
  }
  assertFiniteNumbers(parsed, label);
  return parsed as JsonValue;
}

/**
 * Re-encodes an in-memory value through the same strict JSON contract used for
 * bytes. Structured cloning removes provider-owned prototypes, snapshots
 * getters once, and rejects functions that could otherwise affect JSON.stringify
 * via toJSON.
 */
export function normalizeJsonValue(value: unknown, label: string, maxBytes?: number): JsonValue {
  let snapshot: JsonValue;
  let source: string | undefined;
  try {
    snapshot = snapshotJsonValue(structuredCloneIntrinsic(value), new WeakSetIntrinsic<object>());
    source = stringifyJsonValue(snapshot);
  } catch {
    throw new JsonContractError(`${label} is not valid JSON`);
  }
  if (source === undefined) throw new JsonContractError(`${label} is not valid JSON`);
  const encoder = new TextEncoderIntrinsic();
  const encoded = applyIntrinsic(textEncoderEncodeIntrinsic, encoder, [source]) as Uint8Array;
  if (maxBytes !== undefined && encoded.length > maxBytes) {
    throw new JsonContractError(`${label} exceeds its size limit`);
  }
  return parseJson(source, label);
}

/** Serializes a validated JSON value without consulting replaceable prototypes or toJSON. */
export function stringifyJsonValue(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return jsonStringifyIntrinsic(value);
  }
  if (typeof value === "number") {
    if (!numberIsFiniteIntrinsic(value)) throw new JsonContractError("value is not valid JSON");
    return jsonStringifyIntrinsic(value);
  }
  if (arrayIsArrayIntrinsic(value)) {
    let source = "[";
    for (let index = 0; index < value.length; index += 1) {
      if (index !== 0) source += ",";
      if (!objectHasOwnIntrinsic(value, index)) {
        throw new JsonContractError("value is not valid JSON");
      }
      source += stringifyJsonValue(value[index]!);
    }
    return `${source}]`;
  }
  if (!isJsonObject(value)) throw new JsonContractError("value is not valid JSON");
  const keys = objectKeysIntrinsic(value);
  let source = "{";
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    const property = objectGetOwnPropertyDescriptorIntrinsic(value, key);
    if (property === undefined || !("value" in property)) {
      throw new JsonContractError("value is not valid JSON");
    }
    if (index !== 0) source += ",";
    source += `${jsonStringifyIntrinsic(key)}:${stringifyJsonValue(property.value as JsonValue)}`;
  }
  return `${source}}`;
}

function snapshotJsonValue(value: unknown, seen: WeakSet<object>): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!numberIsFiniteIntrinsic(value)) throw new Error();
    return value;
  }
  if (typeof value !== "object" || applyIntrinsic(weakSetHasIntrinsic, seen, [value])) {
    throw new Error();
  }
  applyIntrinsic(weakSetAddIntrinsic, seen, [value]);
  try {
    if (arrayIsArrayIntrinsic(value)) {
      const result: JsonValue[] = [];
      for (let index = 0; index < value.length; index += 1) {
        result[index] = objectHasOwnIntrinsic(value, index)
          ? snapshotJsonValue(value[index], seen)
          : null;
      }
      return result;
    }
    if (!isJsonObject(value)) throw new Error();
    const result = objectCreateIntrinsic(null) as Record<string, JsonValue>;
    const keys = objectKeysIntrinsic(value);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index]!;
      const property = objectGetOwnPropertyDescriptorIntrinsic(value, key);
      if (property === undefined || !("value" in property)) throw new Error();
      result[key] = snapshotJsonValue(property.value, seen);
    }
    return result;
  } finally {
    applyIntrinsic(weakSetDeleteIntrinsic, seen, [value]);
  }
}

function assertFiniteNumbers(value: unknown, label: string): void {
  if (typeof value === "number") {
    if (!numberIsFiniteIntrinsic(value)) {
      throw new JsonContractError(`${label} contains a number outside the binary64 domain`);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    const keys = objectKeysIntrinsic(value);
    for (let index = 0; index < keys.length; index += 1) {
      const property = objectGetOwnPropertyDescriptorIntrinsic(value, keys[index]!);
      if (property !== undefined && "value" in property) {
        assertFiniteNumbers(property.value, label);
      }
    }
  }
}

const JSON_STRING_ESCAPE = /^["\\/bfnrt]$/u;
const JSON_DIGIT = /[0-9]/u;
const JSON_HEX = /[0-9a-fA-F]/u;

function fail(message: string): never {
  throw new JsonContractError(`is not valid JSON: ${message}`);
}

/** Single-pass structural scan enforcing uniqueness and number range. */
function scanJsonContract(source: string, label: string): void {
  let position = 0;
  const length = source.length;

  function skipWhitespace(): void {
    while (
      position < length &&
      (source[position] === " " ||
        source[position] === "\t" ||
        source[position] === "\n" ||
        source[position] === "\r")
    ) {
      position += 1;
    }
  }

  function scanString(): string {
    position += 1; // opening quote
    let value = "";
    while (position < length) {
      const character = source[position]!;
      if (character === '"') {
        position += 1;
        return value;
      }
      const code = applyIntrinsic(stringCharCodeAtIntrinsic, character, [0]) as number;
      if (code < 0x20) fail("unescaped control character in string");
      if (isHighSurrogate(code)) {
        const low = applyIntrinsic(stringCharCodeAtIntrinsic, source, [position + 1]) as number;
        if (!isLowSurrogate(low)) fail("contains an invalid Unicode surrogate pair");
        value += applyIntrinsic(stringSliceIntrinsic, source, [position, position + 2]) as string;
        position += 2;
        continue;
      }
      if (isLowSurrogate(code)) fail("contains an invalid Unicode surrogate pair");
      if (character !== "\\") {
        value += character;
        position += 1;
        continue;
      }

      position += 1;
      const escape = source[position];
      if (escape === undefined) fail("unterminated string");
      if (escape === "u") {
        value += scanUnicodeEscape();
        continue;
      }
      if (!applyIntrinsic(regExpTestIntrinsic, JSON_STRING_ESCAPE, [escape])) {
        fail("invalid escape sequence");
      }
      value += decodeSimpleEscape(escape);
      position += 1;
    }
    fail("unterminated string");
  }

  function scanUnicodeEscape(): string {
    const codeUnit = scanUnicodeCodeUnit();
    if (isHighSurrogate(codeUnit)) {
      if (source[position] !== "\\" || source[position + 1] !== "u") {
        fail("contains an invalid Unicode surrogate pair");
      }
      position += 1; // the backslash before the low surrogate escape
      const low = scanUnicodeCodeUnit();
      if (!isLowSurrogate(low)) fail("contains an invalid Unicode surrogate pair");
      return stringFromCharCodeIntrinsic(codeUnit, low);
    }
    if (isLowSurrogate(codeUnit)) fail("contains an invalid Unicode surrogate pair");
    return stringFromCharCodeIntrinsic(codeUnit);
  }

  function scanUnicodeCodeUnit(): number {
    position += 1; // the "u" in the escape
    let codePoint = 0;
    for (let digit = 0; digit < 4; digit += 1) {
      const character = source[position];
      if (character === undefined || !applyIntrinsic(regExpTestIntrinsic, JSON_HEX, [character])) {
        fail("invalid \\u escape");
      }
      codePoint = codePoint * 16 + numberParseIntIntrinsic(character, 16);
      position += 1;
    }
    return codePoint;
  }

  function decodeSimpleEscape(escape: string): string {
    switch (escape) {
      case '"':
        return '"';
      case "\\":
        return "\\";
      case "/":
        return "/";
      case "b":
        return "\b";
      case "f":
        return "\f";
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      default:
        fail("invalid escape sequence");
    }
  }

  function scanNumber(): void {
    const start = position;
    if (source[position] === "-") position += 1;
    if (source[position] === "0") {
      position += 1;
    } else if (applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
      position += 1;
      while (applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
        position += 1;
      }
    } else {
      fail("invalid number");
    }
    if (source[position] === ".") {
      position += 1;
      if (!applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
        fail("invalid number fraction");
      }
      while (applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
        position += 1;
      }
    }
    if (source[position] === "e" || source[position] === "E") {
      position += 1;
      if (source[position] === "+" || source[position] === "-") position += 1;
      if (!applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
        fail("invalid number exponent");
      }
      while (applyIntrinsic(regExpTestIntrinsic, JSON_DIGIT, [source[position] ?? ""])) {
        position += 1;
      }
    }
    if (
      !numberIsFiniteIntrinsic(
        numberIntrinsic(applyIntrinsic(stringSliceIntrinsic, source, [start, position]) as string),
      )
    ) {
      fail("contains a number outside the binary64 domain");
    }
  }

  function scanValue(): void {
    skipWhitespace();
    const first = source[position];
    if (first === "{") return scanObject();
    if (first === "[") return scanArray();
    if (first === '"') {
      scanString();
      return;
    }
    if (applyIntrinsic(stringStartsWithIntrinsic, source, ["true", position])) {
      position += 4;
      return;
    }
    if (applyIntrinsic(stringStartsWithIntrinsic, source, ["false", position])) {
      position += 5;
      return;
    }
    if (applyIntrinsic(stringStartsWithIntrinsic, source, ["null", position])) {
      position += 4;
      return;
    }
    scanNumber();
  }

  function scanObject(): void {
    position += 1;
    skipWhitespace();
    const members = new SetIntrinsic<string>();
    if (source[position] === "}") {
      position += 1;
      return;
    }
    for (;;) {
      skipWhitespace();
      if (source[position] !== '"') fail("expected object key");
      const key = scanString();
      if (applyIntrinsic(setHasIntrinsic, members, [key])) {
        fail("contains a duplicate object member");
      }
      applyIntrinsic(setAddIntrinsic, members, [key]);
      skipWhitespace();
      if (source[position] !== ":") fail('expected ":"');
      position += 1;
      scanValue();
      skipWhitespace();
      if (source[position] === ",") {
        position += 1;
        continue;
      }
      if (source[position] === "}") {
        position += 1;
        return;
      }
      fail('expected "," or "}"');
    }
  }

  function scanArray(): void {
    position += 1;
    skipWhitespace();
    if (source[position] === "]") {
      position += 1;
      return;
    }
    for (;;) {
      scanValue();
      skipWhitespace();
      if (source[position] === ",") {
        position += 1;
        continue;
      }
      if (source[position] === "]") {
        position += 1;
        return;
      }
      fail('expected "," or "]"');
    }
  }

  try {
    scanValue();
    skipWhitespace();
    if (position !== length) fail("trailing content after JSON value");
  } catch (error) {
    if (error instanceof JsonContractError) {
      throw new JsonContractError(`${label} ${error.message}`);
    }
    throw error;
  }
}

function isHighSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xd800 && codeUnit <= 0xdbff;
}

function isLowSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xdc00 && codeUnit <= 0xdfff;
}

function startsWithUtf8Bom(bytes: Uint8Array): boolean {
  return bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
}
