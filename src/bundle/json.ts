export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function isJsonObject(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseJson(source: string, label: string): JsonValue {
  try {
    return JSON.parse(source) as JsonValue;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}
