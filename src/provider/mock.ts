import { isJsonObject, type JsonValue } from "../bundle/json.js";
import type {
  Provider,
  ProviderAdapterContext,
  ProviderModelRequest,
  ProviderResponse,
} from "../runner/types.js";

export type MockProviderOptions = {
  document?: JsonValue;
  providerId?: string;
  route?: string;
  respondedModel?: string | null;
  effectiveEffort?: string | null;
  onRequest?: (request: ProviderModelRequest, context: ProviderAdapterContext) => void | Promise<void>;
  onInvoke?: (request: ProviderModelRequest, context: ProviderAdapterContext) => void | Promise<void>;
  onImageRead?: () => void | Promise<void>;
};

/** A deterministic provider double for public synthetic fixtures and tests. */
export function createMockProvider(options: MockProviderOptions = {}): Provider {
  const providerId = options.providerId ?? "mock";
  const route = options.route ?? "mock";
  return {
    id: providerId,
    route,
    async invoke(request, context): Promise<ProviderResponse> {
      await options.onRequest?.(request, context);
      await options.onInvoke?.(request, context);
      await request.image.readBytes();
      await options.onImageRead?.();
      await request.system.readText();
      await request.instruction.readText();
      return {
        rawDocument: options.document !== undefined ? options.document : documentForSchema(request.schema),
        respondedModel: options.respondedModel === undefined ? "mock-v1" : options.respondedModel,
        effectiveEffort:
          options.effectiveEffort === undefined ? request.requested.effort : options.effectiveEffort,
        usage: { available: false },
        stopReason: "stop",
      };
    },
  };
}

function documentForSchema(schema: JsonValue): JsonValue {
  return exampleForSchema(schema, new Set());
}

function exampleForSchema(schema: JsonValue, resolving: Set<string>): JsonValue {
  if (!isJsonObject(schema)) return null;
  if (Object.hasOwn(schema, "const")) {
    const constant = schema.const;
    if (constant !== undefined) return constant;
  }
  const enumeration = schema.enum;
  if (Array.isArray(enumeration) && enumeration.length > 0) {
    const first = enumeration[0];
    if (first !== undefined) return first;
  }

  const reference = schema.$ref;
  if (typeof reference === "string" && !resolving.has(reference)) {
    // The mock intentionally does not resolve external schemas. Local refs can
    // be handled by callers that provide an explicit document instead.
    return null;
  }

  const type = schema.type;
  if (type === "object" || (type === undefined && isJsonObject(schema.properties))) {
    const result: Record<string, JsonValue> = {};
    const properties = isJsonObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required)
      ? schema.required.filter((entry): entry is string => typeof entry === "string")
      : Object.keys(properties);
    for (const key of required) {
      const propertySchema = properties[key];
      if (propertySchema !== undefined) result[key] = exampleForSchema(propertySchema, resolving);
    }
    return result;
  }
  if (type === "array") {
    const minimum = typeof schema.minItems === "number" ? schema.minItems : 0;
    const itemSchema = schema.items;
    if (minimum > 0 && itemSchema !== undefined) {
      return Array.from({ length: minimum }, () => exampleForSchema(itemSchema, resolving));
    }
    return [];
  }
  if (type === "string") return stringExample(schema);
  if (type === "integer" || type === "number") {
    if (typeof schema.minimum === "number") return schema.minimum;
    return 0;
  }
  if (type === "boolean") return false;
  if (type === "null") return null;
  return null;
}

function stringExample(schema: Record<string, JsonValue>): string {
  const minimum = typeof schema.minLength === "number" ? schema.minLength : 0;
  const value = "synthetic";
  if (value.length >= minimum) return value;
  return value.padEnd(minimum, "x");
}
