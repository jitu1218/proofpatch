/**
 * Snapshot path canonicalization (Phase 2, Step 2).
 *
 * Two jobs, and nothing else (no hashing yet):
 *  1. REJECT unsafe or ambiguous file paths. A bad path is never repaired or
 *     "cleaned up": if we silently changed a path, we would validate (and later
 *     fingerprint) a different file than the one the caller meant.
 *  2. SORT files in one fixed order (raw UTF-8 byte order) so the same set of
 *     files always lists in the same order, whatever order they arrived in.
 *
 * Deliberately does NOT use `node:path`: its behaviour differs between Windows
 * and Linux. These rules are plain string rules and behave identically on both.
 *
 * Accepted path shape (a "snapshot path"): repo-relative, "/" separated,
 * e.g. "src/flask/app.py". Case is kept as given; paths must already be
 * NFC-normalized.
 *
 * KNOWN LIMITATIONS (not handled in this step, by design):
 *  - Case-insensitive collisions ("README.md" vs "readme.md") are treated as
 *    two different files. They collide on Windows/macOS disks; the materialize
 *    + verify steps (Step 5) must catch that.
 *  - Windows-only name problems (reserved names like "CON", trailing dots or
 *    spaces, ":" inside a name such as NTFS streams) are not checked here.
 *  - Paths must use NFC Unicode normalization. Decomposed forms are rejected
 *    so normalization-equivalent names cannot collide on a target filesystem.
 */

/**
 * Why a path was rejected. Checks run in this order and the FIRST match wins,
 * so a path with several problems always reports the same code.
 */
export type SnapshotPathProblem =
  | 'not_string' // not a JavaScript string at all
  | 'empty' // ""
  | 'nul' // contains a NUL (\0) character
  | 'invalid_unicode' // contains a lone surrogate, so it has no exact UTF-8 form
  | 'non_canonical_unicode' // is not NFC-normalized
  | 'backslash' // contains "\" (Windows separator); only "/" is allowed
  | 'drive_letter' // starts with a Windows drive such as "C:"
  | 'absolute' // starts with "/"
  | 'empty_segment' // doubled or trailing "/" such as "a//b" or "a/"
  | 'dot_segment' // a "." segment such as "./a" or "a/./b"
  | 'traversal' // a ".." segment such as "../a" or "a/../b"
  | 'duplicate'; // the same path appears twice in one snapshot

const EXPLANATIONS: Record<SnapshotPathProblem, string> = {
  not_string: 'path is not a string',
  empty: 'path is empty',
  nul: 'path contains a NUL character',
  invalid_unicode: 'path is not well-formed Unicode (lone surrogate)',
  non_canonical_unicode: 'path is not NFC-normalized',
  backslash: 'path contains a backslash; only "/" separators are allowed',
  drive_letter: 'path starts with a Windows drive letter',
  absolute: 'path is absolute (starts with "/")',
  empty_segment: 'path has an empty segment (doubled or trailing "/")',
  dot_segment: 'path contains a "." segment',
  traversal: 'path contains a ".." segment',
  duplicate: 'path appears more than once in the snapshot',
};

/** Thrown for any rejected path. `code` says why, `path` is the offending value. */
export class SnapshotPathError extends Error {
  readonly code: SnapshotPathProblem;
  readonly path: unknown;

  constructor(code: SnapshotPathProblem, path: unknown) {
    // JSON.stringify makes control characters visible ("a\u0000b") so the
    // message itself stays readable and cannot contain a raw NUL.
    super(`Unsafe snapshot path ${safeDisplay(path)}: ${EXPLANATIONS[code]}`);
    this.name = 'SnapshotPathError';
    this.code = code;
    this.path = path;
  }
}

function safeDisplay(value: unknown): string {
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  return `(${typeof value})`;
}

// A UTF-16 surrogate without its partner. Such a string cannot be encoded to
// UTF-8 exactly (it becomes U+FFFD), which would make two different paths look
// identical when hashed or sorted by bytes. No "u" flag: we inspect raw code units.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const DRIVE_LETTER = /^[A-Za-z]:/;

/**
 * Returns why a single path is unsafe, or null if it is acceptable.
 * Does not look at other paths, so it never reports 'duplicate'.
 * Never changes the path.
 */
export function findPathProblem(path: unknown): Exclude<SnapshotPathProblem, 'duplicate'> | null {
  if (typeof path !== 'string') return 'not_string';
  if (path === '') return 'empty';
  if (path.includes('\0')) return 'nul';
  if (LONE_SURROGATE.test(path)) return 'invalid_unicode';
  if (path.normalize('NFC') !== path) return 'non_canonical_unicode';
  if (path.includes('\\')) return 'backslash';
  if (DRIVE_LETTER.test(path)) return 'drive_letter';
  if (path.startsWith('/')) return 'absolute';

  for (const segment of path.split('/')) {
    if (segment === '') return 'empty_segment';
    if (segment === '.') return 'dot_segment';
    if (segment === '..') return 'traversal';
  }
  return null;
}

/** Throws SnapshotPathError if the path is unsafe; otherwise returns nothing. */
export function assertSafeSnapshotPath(path: unknown): void {
  const problem = findPathProblem(path);
  if (problem !== null) {
    throw new SnapshotPathError(problem, path);
  }
}

/**
 * Compares two paths by their raw UTF-8 bytes (like `memcmp`).
 * Returns a negative number, 0 or a positive number.
 *
 * Not `localeCompare` (depends on language/ICU settings, so two machines could
 * order differently) and not the default `sort()` (compares UTF-16 code units,
 * which disagrees with UTF-8 byte order for characters outside the BMP).
 */
export function comparePathsByteOrder(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * Validates every item's `path` and returns a NEW array sorted by path in byte
 * order. Works on any object with a `path`, so later steps can keep the file
 * content attached. The input array is never modified, and paths are never
 * rewritten.
 *
 * Throws SnapshotPathError (and returns nothing) if any path is unsafe or if
 * two items share the same path.
 *
 * Why the result is deterministic: all paths are valid, therefore well-formed,
 * therefore exact UTF-8; and all are unique. Distinct byte strings have a
 * strict order, so no two items ever tie and the input order cannot leak in.
 */
export function canonicalizeByPath<T extends { readonly path: string }>(
  items: readonly T[],
): readonly T[] {
  const seen = new Set<string>();
  const keyed = items.map((item) => {
    assertSafeSnapshotPath(item.path);
    if (seen.has(item.path)) {
      throw new SnapshotPathError('duplicate', item.path);
    }
    seen.add(item.path);
    // Encode once per item instead of once per comparison.
    return { item, key: Buffer.from(item.path, 'utf8') };
  });

  keyed.sort((x, y) => Buffer.compare(x.key, y.key));
  return keyed.map((entry) => entry.item);
}
