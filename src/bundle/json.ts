export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export class JsonContractError extends Error {}

export function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decodes UTF-8 bytes strictly. Invalid byte sequences throw instead of being
 * silently replaced with U+FFFD, so every reader of the same bundle sees the
 * same characters.
 */
export function decodeUtf8Strict(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new JsonContractError(`${label} is not valid UTF-8`);
  }
}

/**
 * Parses JSON under the v1 exactness contract:
 * - invalid UTF-8 is rejected (no U+FFFD replacement);
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
    while (position < length && source[position] !== '"') {
      const code = source.charCodeAt(position);
      if (code < 0x20) fail("unescaped control character in string");
      if (code === 0x5c) {
        position += 1;
        const escape = source[position];
        if (escape === "u") {
          position += 1;
          for (let digit = 0; digit < 4; digit += 1) {
            if (!/[0-9a-fA-F]/u.test(source[position] ?? "")) fail("invalid \\u escape");
            position += 1;
          }
        } else if (!JSON_STRING_ESCAPE.test(escape ?? "")) {
          fail("invalid escape sequence");
        }
      }
      position += 1;
    }
    if (source[position] !== '"') fail("unterminated string");
    position += 1;
    return "";
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
      fail(`number ${source.slice(start, position)} overflows the binary64 domain`);
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
      const keyStart = position;
      scanString();
      const key = source.slice(keyStart, position);
      if (members.has(key)) fail(`duplicate object member ${key}`);
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
