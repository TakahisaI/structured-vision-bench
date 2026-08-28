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
    if (
      !isBoundedJsonPointer(pattern) ||
      pointerSegments(pattern).includes("*") ||
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

/** Matches only a consumer-owned exact pointer. */
export function sanitizerFindingPathIsAllowed(
  path: string,
  patterns: readonly string[],
): boolean {
  return isSanitizerFindingPath(path) && patterns.includes(path);
}

/** Re-checks a persisted path against the committed consumer patterns. */
export function sanitizerFindingPathMatchesPatterns(
  path: string,
  patterns: readonly string[],
): boolean {
  return sanitizerFindingPathIsAllowed(path, patterns);
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
