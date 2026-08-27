import { isJsonObject, type JsonValue } from "../bundle/json.js";
import { validateJsonSchema } from "../bundle/schema-validator.js";
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
  const candidate = exampleForSchema(schema, schema, new Set());
  return validateJsonSchema(schema, candidate).length === 0 ? candidate : null;
}

function exampleForSchema(
  schema: JsonValue,
  rootSchema: JsonValue,
  resolving: Set<string>,
): JsonValue {
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
  if (typeof reference === "string") {
    if (resolving.has(reference)) return null;
    const resolved = resolveLocalReference(rootSchema, reference);
    if (resolved === undefined) return null;
    const nextResolving = new Set(resolving);
    nextResolving.add(reference);
    return exampleForSchema(resolved, rootSchema, nextResolving);
  }

  for (const keyword of ["anyOf", "oneOf"] as const) {
    const alternatives = schema[keyword];
    if (Array.isArray(alternatives)) {
      for (const alternative of alternatives) {
        const candidate = exampleForSchema(alternative, rootSchema, resolving);
        if (candidateMatchesSchema(schema, candidate, rootSchema)) return candidate;
      }
    }
  }

  const allOf = schema.allOf;
  if (Array.isArray(allOf)) {
    const candidates = allOf.map((alternative) =>
      exampleForSchema(alternative, rootSchema, resolving),
    );
    if (candidates.every(isJsonObject)) {
      const merged = Object.assign({}, ...candidates);
      if (candidateMatchesSchema(schema, merged, rootSchema)) return merged;
    }
    return candidates.find((candidate) => candidateMatchesSchema(schema, candidate, rootSchema)) ?? null;
  }

  const type = schema.type;
  if (Array.isArray(type)) {
    for (const candidateType of type) {
      if (typeof candidateType === "string") {
        const candidate = exampleForType(schema, candidateType, rootSchema, resolving);
        const candidateSchema = { ...schema, type: candidateType };
        if (candidateMatchesSchema(candidateSchema, candidate, rootSchema)) return candidate;
      }
    }
    return null;
  }
  if (typeof type === "string") return exampleForType(schema, type, rootSchema, resolving);
  if (isJsonObject(schema.properties)) return exampleForObject(schema, rootSchema, resolving);
  return null;
}

function exampleForType(
  schema: Record<string, JsonValue>,
  type: string,
  rootSchema: JsonValue,
  resolving: Set<string>,
): JsonValue {
  if (type === "object") return exampleForObject(schema, rootSchema, resolving);
  if (type === "array") {
    const minimum = typeof schema.minItems === "number" && schema.minItems > 0 ? schema.minItems : 0;
    const itemSchema = schema.items;
    if (!isJsonObject(itemSchema) || minimum > 64) return [];
    return Array.from({ length: minimum }, () => exampleForSchema(itemSchema, rootSchema, resolving));
  }
  if (type === "string") return stringExample(schema);
  if (type === "integer" || type === "number") {
    if (typeof schema.minimum === "number" && Number.isFinite(schema.minimum)) {
      return type === "integer" ? Math.ceil(schema.minimum) : schema.minimum;
    }
    return 0;
  }
  if (type === "boolean") return false;
  if (type === "null") return null;
  return null;
}

function exampleForObject(
  schema: Record<string, JsonValue>,
  rootSchema: JsonValue,
  resolving: Set<string>,
): JsonValue {
  const result: Record<string, JsonValue> = {};
  const properties = isJsonObject(schema.properties) ? schema.properties : {};
  const required = Array.isArray(schema.required)
    ? schema.required.filter((entry): entry is string => typeof entry === "string")
    : [];
  for (const key of required) {
    const propertySchema = properties[key];
    if (propertySchema !== undefined) {
      result[key] = exampleForSchema(propertySchema, rootSchema, resolving);
    }
  }
  const minimum = typeof schema.minProperties === "number" ? schema.minProperties : 0;
  if (minimum <= 64) {
    for (const key of Object.keys(properties)) {
      if (Object.keys(result).length >= minimum) break;
      if (!Object.hasOwn(result, key)) {
        result[key] = exampleForSchema(properties[key]!, rootSchema, resolving);
      }
    }
  }
  return result;
}

function stringExample(schema: Record<string, JsonValue>): string {
  const minimum = typeof schema.minLength === "number" ? schema.minLength : 0;
  const boundedMinimum = Math.min(Math.max(0, minimum), 1024);
  const value = schema.format === "date-time" ? "2024-01-01T00:00:00Z" : "synthetic";
  if (minimum > 1024) return "";
  if (value.length >= minimum) return value;
  return value.padEnd(boundedMinimum, "x");
}

function resolveLocalReference(rootSchema: JsonValue, reference: string): JsonValue | undefined {
  if (!reference.startsWith("#")) return undefined;
  let pointer: string;
  try {
    pointer = decodeURIComponent(reference.slice(1));
  } catch {
    return undefined;
  }
  if (pointer === "") return rootSchema;
  if (!pointer.startsWith("/")) return undefined;
  let current: JsonValue = rootSchema;
  for (const rawSegment of pointer.slice(1).split("/")) {
    const segment = rawSegment.replace(/~1/gu, "/").replace(/~0/gu, "~");
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(segment)) return undefined;
      const index = Number(segment);
      if (index >= current.length) return undefined;
      current = current[index]!;
    } else if (isJsonObject(current) && Object.hasOwn(current, segment)) {
      current = current[segment]!;
    } else {
      return undefined;
    }
  }
  return current;
}

function candidateMatchesSchema(
  schema: JsonValue,
  candidate: JsonValue,
  rootSchema: JsonValue,
): boolean {
  if (!isJsonObject(schema)) return false;
  const scopedSchema: Record<string, JsonValue> = { ...schema };
  if (isJsonObject(rootSchema)) {
    if (scopedSchema.$defs === undefined && rootSchema.$defs !== undefined) {
      scopedSchema.$defs = rootSchema.$defs;
    }
    if (scopedSchema.definitions === undefined && rootSchema.definitions !== undefined) {
      scopedSchema.definitions = rootSchema.definitions;
    }
  }
  return validateJsonSchema(scopedSchema, candidate).length === 0;
}
