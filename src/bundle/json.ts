export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export class JsonContractError extends Error {}

export function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
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
    parsed = JSON.parse(source);
  } catch {
    // The scanner accepted it, so this is unreachable in practice; kept as a
    // safety net that never leaks internals.
    throw new Error(`${label} is not valid JSON`);
  }
  assertFiniteNumbers(parsed, label);
  return parsed as JsonValue;
}

function assertFiniteNumbers(value: unknown, label: string): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new JsonContractError(`${label} contains a number outside the binary64 domain`);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) assertFiniteNumbers(child, label);
  }
}

const JSON_STRING_ESCAPE = /^["\\/bfnrt]$/u;
const JSON_DIGIT = /[0-9]/u;

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
      const code = character.charCodeAt(0);
      if (code < 0x20) fail("unescaped control character in string");
      if (isHighSurrogate(code)) {
        const low = source.charCodeAt(position + 1);
        if (!isLowSurrogate(low)) fail("contains an invalid Unicode surrogate pair");
        value += source.slice(position, position + 2);
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
      if (!JSON_STRING_ESCAPE.test(escape)) fail("invalid escape sequence");
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
      return String.fromCharCode(codeUnit, low);
    }
    if (isLowSurrogate(codeUnit)) fail("contains an invalid Unicode surrogate pair");
    return String.fromCharCode(codeUnit);
  }

  function scanUnicodeCodeUnit(): number {
    position += 1; // the "u" in the escape
    let codePoint = 0;
    for (let digit = 0; digit < 4; digit += 1) {
      const character = source[position];
      if (character === undefined || !/[0-9a-fA-F]/u.test(character)) {
        fail("invalid \\u escape");
      }
      codePoint = codePoint * 16 + Number.parseInt(character, 16);
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
    } else if (JSON_DIGIT.test(source[position] ?? "")) {
      position += 1;
      while (JSON_DIGIT.test(source[position] ?? "")) position += 1;
    } else {
      fail("invalid number");
    }
    if (source[position] === ".") {
      position += 1;
      if (!JSON_DIGIT.test(source[position] ?? "")) fail("invalid number fraction");
      while (JSON_DIGIT.test(source[position] ?? "")) position += 1;
    }
    if (source[position] === "e" || source[position] === "E") {
      position += 1;
      if (source[position] === "+" || source[position] === "-") position += 1;
      if (!JSON_DIGIT.test(source[position] ?? "")) fail("invalid number exponent");
      while (JSON_DIGIT.test(source[position] ?? "")) position += 1;
    }
    if (!Number.isFinite(Number(source.slice(start, position)))) {
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
    if (source.startsWith("true", position)) {
      position += 4;
      return;
    }
    if (source.startsWith("false", position)) {
      position += 5;
      return;
    }
    if (source.startsWith("null", position)) {
      position += 4;
      return;
    }
    scanNumber();
  }

  function scanObject(): void {
    position += 1;
    skipWhitespace();
    const members = new Set<string>();
    if (source[position] === "}") {
      position += 1;
      return;
    }
    for (;;) {
      skipWhitespace();
      if (source[position] !== '"') fail("expected object key");
      const key = scanString();
      if (members.has(key)) fail("contains a duplicate object member");
      members.add(key);
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
