/**
 * Runtime tests for snapshot path canonicalization (Phase 2, Step 2).
 * All fixtures are synthetic. They do not depend on any Member 4 API.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  assertSafeSnapshotPath,
  canonicalizeByPath,
  comparePathsByteOrder,
  findPathProblem,
  SnapshotPathError,
  type SnapshotPathProblem,
  type StagedFile,
} from '../../src/index.js';

// ---------------------------------------------------------------------------
// helpers (test-only)
// ---------------------------------------------------------------------------

/** Every ordering of the items (n! results; keep n small). */
function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  const result: T[][] = [];
  items.forEach((item, i) => {
    const rest = [...items.slice(0, i), ...items.slice(i + 1)];
    for (const tail of permutations(rest)) result.push([item, ...tail]);
  });
  return result;
}

/** Small deterministic pseudo-random generator, so "random" tests never flake. */
function seededRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled<T>(items: readonly T[], random: () => number): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j] as T, copy[i] as T];
  }
  return copy;
}

const asFiles = (paths: readonly string[]): StagedFile[] =>
  paths.map((path) => ({ path, content: `content of ${path}` }));

const pathsOf = (files: readonly { path: string }[]): string[] => files.map((f) => f.path);

// ---------------------------------------------------------------------------
// 1. Valid paths are accepted
// ---------------------------------------------------------------------------

describe('valid paths are accepted', () => {
  const valid = [
    'a',
    'a.txt',
    'src/app.py',
    'src/flask/__init__.py',
    '.github/workflows/ci.yml', // a segment may START with a dot
    '.env.example',
    'a..b', // ".." inside a name is not traversal
    'dir/..hidden', // ".." only counts as a whole segment
    'name with spaces/file (1).txt',
    'caf\u00e9/menu.txt',
    '\u6587\u4ef6/\u6e90.py',
    '\u{1F600}/emoji.txt', // valid surrogate pair
    '%2e%2e/a', // percent-encoding is NOT decoded, so this is an ordinary name
    'UPPER/lower.TXT',
  ];

  for (const path of valid) {
    it(`accepts ${JSON.stringify(path)}`, () => {
      assert.equal(findPathProblem(path), null);
      assert.doesNotThrow(() => assertSafeSnapshotPath(path));
    });
  }
});

// ---------------------------------------------------------------------------
// 2. Unsafe paths are rejected, with the documented reason code
// ---------------------------------------------------------------------------

describe('unsafe paths are rejected', () => {
  const unsafe: ReadonlyArray<readonly [SnapshotPathProblem, readonly unknown[]]> = [
    ['empty', ['']],
    ['nul', ['a\0b', '\0', 'src/app.py\0.txt', 'a/\0/b']],
    ['invalid_unicode', ['\uD800', 'a\uDC00b', 'x\uD83D', '\uD83D\uD83D\uDE00']],
    [
      'backslash',
      ['a\\b', 'src\\app.py', '\\a', 'a\\', 'C:\\Windows\\system32', '\\\\server\\share\\f', '..\\a'],
    ],
    ['drive_letter', ['C:/Windows/x', 'c:/x', 'Z:/', 'C:', 'C:relative/path', 'd:file.txt']],
    ['absolute', ['/etc/passwd', '/', '//server/share', '/a/b']],
    ['empty_segment', ['a//b', 'a/', 'src//app.py', 'a/b/', 'a///b']],
    ['dot_segment', ['.', './a', 'a/./b', 'a/.', './']],
    ['traversal', ['..', '../a', 'a/..', 'a/../b', 'a/b/../../../c', '../../etc/passwd']],
    ['not_string', [undefined, null, 42, {}, ['a.txt'], true]],
  ];

  for (const [code, examples] of unsafe) {
    describe(`code "${code}"`, () => {
      for (const example of examples) {
        const label = typeof example === 'string' ? JSON.stringify(example) : String(typeof example);

        it(`rejects ${label}`, () => {
          assert.equal(findPathProblem(example), code);
          assert.throws(
            () => assertSafeSnapshotPath(example),
            (error: unknown) => {
              assert.ok(error instanceof SnapshotPathError);
              assert.equal(error.code, code);
              return true;
            },
          );
        });
      }
    });
  }

  it('checks run in a fixed order so a path with several problems has one stable code', () => {
    assert.equal(findPathProblem('C:\\..\\x'), 'backslash'); // backslash beats drive letter and ".."
    assert.equal(findPathProblem('/../x'), 'absolute'); // absolute beats ".."
    assert.equal(findPathProblem('a//../b'), 'empty_segment'); // first bad segment wins
    assert.equal(findPathProblem('\0\\'), 'nul'); // NUL beats backslash
  });
});

// ---------------------------------------------------------------------------
// 3. Rejected paths are NEVER silently repaired
// ---------------------------------------------------------------------------

describe('no silent normalization', () => {
  it('rejects instead of cleaning "a//b", "./a" and "a/../b"', () => {
    for (const bad of ['a//b', './a', 'a/../b', 'a/./b']) {
      assert.throws(() => canonicalizeByPath(asFiles([bad])), SnapshotPathError, bad);
    }
  });

  it('returns accepted paths exactly as given (no case folding, no decoding)', () => {
    const input = ['README.md', 'Src/App.py', '%41.txt', 'a b.txt'];
    assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(input))).sort(), [...input].sort());
  });

  it('rejects decomposed Unicode paths to prevent normalization collisions', () => {
    const composed = 'caf\u00e9.txt'; // "é" as one character
    const decomposed = 'cafe\u0301.txt'; // "e" followed by a combining accent
    assert.notEqual(composed, decomposed);
    assert.doesNotThrow(() => canonicalizeByPath(asFiles([composed])));
    assert.throws(
      () => canonicalizeByPath(asFiles([decomposed])),
      { code: 'non_canonical_unicode' },
    );
  });

  it('treats paths differing only by case as different files (documented limitation)', () => {
    // Case-insensitive disk collisions are Step 5's job (materialize + verify).
    const result = canonicalizeByPath(asFiles(['readme.md', 'README.md']));
    assert.deepEqual(pathsOf(result), ['README.md', 'readme.md']);
  });
});

// ---------------------------------------------------------------------------
// 4. Duplicates
// ---------------------------------------------------------------------------

describe('duplicate paths', () => {
  it('rejects an exact duplicate and reports the path', () => {
    assert.throws(
      () => canonicalizeByPath(asFiles(['a.txt', 'b.txt', 'a.txt'])),
      (error: unknown) => {
        assert.ok(error instanceof SnapshotPathError);
        assert.equal(error.code, 'duplicate');
        assert.equal(error.path, 'a.txt');
        return true;
      },
    );
  });

  it('rejects duplicates even when the contents differ', () => {
    const files: StagedFile[] = [
      { path: 'x.py', content: 'one' },
      { path: 'x.py', content: 'two' },
    ];
    assert.throws(() => canonicalizeByPath(files), { code: 'duplicate' });
  });

  it('accepts the same name in different directories', () => {
    const result = canonicalizeByPath(asFiles(['a/index.js', 'b/index.js', 'index.js']));
    assert.equal(result.length, 3);
  });
});

// ---------------------------------------------------------------------------
// 5. Byte-order sorting
// ---------------------------------------------------------------------------

describe('byte-order sorting', () => {
  it('sorts simple ASCII paths', () => {
    assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(['b', 'a', 'c']))), ['a', 'b', 'c']);
  });

  it('puts uppercase before lowercase (ASCII byte order, not locale order)', () => {
    // localeCompare would give a, A, b, B on most machines. Bytes: "A"=0x41 < "a"=0x61.
    assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(['a', 'B', 'A', 'b']))), ['A', 'B', 'a', 'b']);
  });

  it('puts a non-ASCII letter after ASCII letters (locale order would put "é" before "z")', () => {
    assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(['\u00e9', 'z', 'a']))), ['a', 'z', '\u00e9']);
  });

  it('sorts the whole path string, so "-" < "." < "/" decides ties inside names', () => {
    // bytes: "-"=0x2D, "."=0x2E, "/"=0x2F
    assert.deepEqual(
      pathsOf(canonicalizeByPath(asFiles(['a/b', 'a.b', 'a-b']))),
      ['a-b', 'a.b', 'a/b'],
    );
  });

  it('puts a prefix before the longer path', () => {
    assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(['ab', 'a', 'abc']))), ['a', 'ab', 'abc']);
  });

  it('orders by UTF-8 bytes, which differs from the default JavaScript sort for emoji', () => {
    const emoji = '\u{1F600}.txt'; // UTF-8: F0 9F 98 80 ...  UTF-16: D83D DE00 ...
    const fullwidthTilde = '\uFF5E.txt'; // UTF-8: EF BD 9E ...  UTF-16: FF5E
    // Default sort() compares UTF-16 code units: D83D < FF5E, so the emoji comes first.
    assert.deepEqual([emoji, fullwidthTilde].sort(), [emoji, fullwidthTilde]);
    // Byte order: EF < F0, so the fullwidth tilde comes first. This is what we must use.
    assert.deepEqual(
      pathsOf(canonicalizeByPath(asFiles([emoji, fullwidthTilde]))),
      [fullwidthTilde, emoji],
    );
  });

  it('gives the same result for every input order (all 120 orderings of 5 paths)', () => {
    const paths = ['src/app.py', 'README.md', 'tests/test_app.py', 'src/\u00e9.py', '.github/ci.yml'];
    const expected = pathsOf(canonicalizeByPath(asFiles(paths)));
    for (const ordering of permutations(paths)) {
      assert.deepEqual(pathsOf(canonicalizeByPath(asFiles(ordering))), expected);
    }
  });

  it('matches an independent reference (Buffer.compare) on 500 pseudo-random paths', () => {
    const random = seededRandom(12345);
    const alphabet = ['a', 'b', 'Z', '0', '_', '-', '.', '\u00e9', '\u6587', '\uFF5E', '\u{1F600}'];
    const unique = new Set<string>();
    while (unique.size < 500) {
      const segments = 1 + Math.floor(random() * 3);
      const parts: string[] = [];
      for (let s = 0; s < segments; s++) {
        let name = '';
        const length = 1 + Math.floor(random() * 4);
        for (let c = 0; c < length; c++) name += alphabet[Math.floor(random() * alphabet.length)];
        if (name === '.' || name === '..') name += 'x'; // keep every generated path valid
        parts.push(name);
      }
      unique.add(parts.join('/'));
    }
    const paths = [...unique];
    const reference = [...paths].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

    const first = pathsOf(canonicalizeByPath(asFiles(shuffled(paths, random))));
    const second = pathsOf(canonicalizeByPath(asFiles(shuffled(paths, random))));
    assert.deepEqual(first, reference);
    assert.deepEqual(second, reference);
  });

  it('returns an empty list for an empty input', () => {
    assert.deepEqual(canonicalizeByPath([]), []);
  });
});

describe('comparePathsByteOrder', () => {
  it('returns negative, zero and positive consistently', () => {
    assert.ok(comparePathsByteOrder('a', 'b') < 0);
    assert.ok(comparePathsByteOrder('b', 'a') > 0);
    assert.equal(comparePathsByteOrder('same', 'same'), 0);
  });

  it('is antisymmetric on a mixed sample', () => {
    const sample = ['', 'a', 'A', 'ab', '\u00e9', '\uFF5E', '\u{1F600}', 'a/b', 'a.b'];
    for (const x of sample) {
      for (const y of sample) {
        // The two signs must cancel out (sum to 0); avoids comparing 0 with -0.
        assert.equal(Math.sign(comparePathsByteOrder(x, y)) + Math.sign(comparePathsByteOrder(y, x)), 0);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 6. canonicalizeByPath contract
// ---------------------------------------------------------------------------

describe('canonicalizeByPath contract', () => {
  it('does not modify the input array and returns a new one', () => {
    const input = asFiles(['b', 'a']);
    const snapshot = JSON.stringify(input);
    const output = canonicalizeByPath(input);
    assert.equal(JSON.stringify(input), snapshot);
    assert.notEqual(output, input);
  });

  it('keeps the same file objects, so content stays attached to its path', () => {
    const input = asFiles(['b.txt', 'a.txt']);
    const [first, second] = canonicalizeByPath(input);
    assert.equal(first, input[1]);
    assert.equal(second, input[0]);
    assert.equal(first?.content, 'content of a.txt');
  });

  it('throws and returns nothing if ANY path is unsafe, even when others are fine', () => {
    assert.throws(
      () => canonicalizeByPath(asFiles(['ok.txt', '../escape.txt', 'fine/also.txt'])),
      { code: 'traversal' },
    );
  });

  it('works with any object that has a path (not tied to one input type)', () => {
    const items = [
      { path: 'b', extra: 1 },
      { path: 'a', extra: 2 },
    ];
    assert.deepEqual(canonicalizeByPath(items).map((i) => i.extra), [2, 1]);
  });
});

// ---------------------------------------------------------------------------
// 7. Error object
// ---------------------------------------------------------------------------

describe('SnapshotPathError', () => {
  it('is an Error with a name, a code and the offending path', () => {
    const error = new SnapshotPathError('traversal', '../x');
    assert.ok(error instanceof Error);
    assert.equal(error.name, 'SnapshotPathError');
    assert.equal(error.code, 'traversal');
    assert.equal(error.path, '../x');
  });

  it('shows control characters escaped, never as raw characters', () => {
    const error = new SnapshotPathError('nul', 'a\0b');
    assert.ok(!error.message.includes('\0'), 'message must not contain a raw NUL');
    assert.ok(error.message.includes('\\u0000'));
  });

  it('does not print non-string values, only their type', () => {
    const error = new SnapshotPathError('not_string', { secret: 'value' });
    assert.ok(!error.message.includes('secret'));
    assert.ok(error.message.includes('object'));
  });
});
