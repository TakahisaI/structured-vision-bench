import type { JsonValue } from "../bundle/json.js";

export const MAX_SANITIZER_FINDING_PATH_LENGTH = 1024;
export const MAX_SANITIZER_FINDING_PATH_PATTERNS = 100;

const JSON_POINTER_PATTERN = /^(?:\/(?:[^~/]|~[01])*)*$/u;

/** Snapshots the consumer-owned allowlist used at the runner persistence boundary. */
export function snapshotSanitizerFindingPathPatterns(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > MAX_SANITIZER_FINDING_PATH_PATTERNS) {
    throw new Error();
  }
  const patterns: string[] = [];
  const seen = new Set<string>();
  for (const pattern of value) {
    const segments = isBoundedJsonPointer(pattern) ? pointerSegments(pattern) : [];
    if (
      !isBoundedJsonPointer(pattern) ||
      segments.filter((segment) => segment === "*").length > 1 ||
      seen.has(pattern)
    ) {
      throw new Error();
    }
    seen.add(pattern);
    patterns.push(pattern);
  }
  patterns.sort();
  return Object.freeze(patterns);
}

/** Validates one exact persisted path; a full `*` segment is not an exact pointer. */
export function isSanitizerFindingPath(value: unknown): value is string {
  return (
    isBoundedJsonPointer(value) &&
    pointerSegments(value).every((segment) => segment !== "*")
  );
}

/** Matches an exact pointer or one array wildcard against the pre-sanitization document. */
export function sanitizerFindingPathIsAllowed(
  path: string,
  patterns: readonly string[],
  document: JsonValue,
): boolean {
  if (!isSanitizerFindingPath(path)) return false;
  const pathSegments = pointerSegments(path);
  return patterns.some((pattern) => {
    if (pattern === path) return true;
    const patternSegments = pointerSegments(pattern);
    return (
      wildcardPatternMatchesPath(pathSegments, patternSegments) &&
      wildcardIndexExistsInDocument(document, pathSegments, patternSegments)
    );
  });
}

/** Re-checks a persisted path shape against committed patterns without rediscovering document data. */
export function sanitizerFindingPathMatchesPatterns(
  path: string,
  patterns: readonly string[],
): boolean {
  if (!isSanitizerFindingPath(path)) return false;
  const pathSegments = pointerSegments(path);
  return patterns.some((pattern) => {
    if (pattern === path) return true;
    return wildcardPatternMatchesPath(pathSegments, pointerSegments(pattern));
  });
}

function wildcardPatternMatchesPath(
  pathSegments: readonly string[],
  patternSegments: readonly string[],
): boolean {
  if (pathSegments.length !== patternSegments.length) return false;
  const wildcardIndex = patternSegments.indexOf("*");
  if (
    wildcardIndex < 0 ||
    patternSegments.lastIndexOf("*") !== wildcardIndex ||
    !isCanonicalArrayIndex(pathSegments[wildcardIndex]!)
  ) {
    return false;
  }
  return patternSegments.every(
    (segment, index) => segment === "*" || segment === pathSegments[index],
  );
}

function wildcardIndexExistsInDocument(
  document: JsonValue,
  pathSegments: readonly string[],
  patternSegments: readonly string[],
): boolean {
  let current: JsonValue = document;
  for (let index = 0; index < pathSegments.length; index += 1) {
    const pathSegment = pathSegments[index]!;
    if (patternSegments[index] === "*") {
      if (!Array.isArray(current) || !isCanonicalArrayIndex(pathSegment)) return false;
      const arrayIndex = Number(pathSegment);
      if (arrayIndex >= current.length) return false;
      return true;
    }
    const member = decodePointerSegment(pathSegment);
    if (Array.isArray(current)) {
      if (!isCanonicalArrayIndex(pathSegment)) return false;
      const arrayIndex = Number(pathSegment);
      if (arrayIndex >= current.length) return false;
      current = current[arrayIndex]!;
    } else if (
      current !== null &&
      typeof current === "object" &&
      Object.hasOwn(current, member)
    ) {
      current = current[member]!;
    } else {
      return false;
    }
  }
  return true;
}

function isCanonicalArrayIndex(value: string): boolean {
  return /^(?:0|[1-9][0-9]*)$/u.test(value) && Number(value) <= 0xffff_ffff - 1;
}

function decodePointerSegment(value: string): string {
  return value.replaceAll("~1", "/").replaceAll("~0", "~");
}

function isBoundedJsonPointer(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= MAX_SANITIZER_FINDING_PATH_LENGTH * 2 &&
    [...value].length <= MAX_SANITIZER_FINDING_PATH_LENGTH &&
    hasOnlyUnicodeScalarValues(value) &&
    JSON_POINTER_PATTERN.test(value)
  );
}

function hasOnlyUnicodeScalarValues(value: string): boolean {
  return [...value].every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint < 0xd800 || codePoint > 0xdfff);
  });
}

function pointerSegments(pointer: string): string[] {
  return pointer === "" ? [] : pointer.slice(1).split("/");
}
