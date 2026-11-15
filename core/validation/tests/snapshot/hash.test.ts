/**
 * Runtime tests for SHA-256 snapshot fingerprinting (Phase 2, Step 3).
 * All fixtures are synthetic. They do not depend on any Member 4 API.
 *
 * Where a value is a fixed literal ("golden" value), it was NOT produced by the
 * code under test: SHA-256 vectors come from the NIST/FIPS examples (and were
 * re-checked with the system `sha256sum`), and snapshot fingerprints were
 * computed by a separate Python implementation written only from the format
 * description in src/snapshot/hash.ts.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  buildSnapshotManifest,
  digestFile,
  FINGERPRINT_FORMAT_VERSION,
  FINGERPRINT_PREFIX,
  SnapshotContentError,
  SnapshotPathError,
  sha256Hex,
  type SnapshotManifest,
  type StagedFile,
} from '../../src/index.js';

// ---------------------------------------------------------------------------
// helpers (test-only)
// ---------------------------------------------------------------------------

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const file = (path: string, content: string): StagedFile => ({ path, content });

const fingerprintOf = (files: readonly StagedFile[]): string =>
  buildSnapshotManifest(files).fingerprint;

const FINGERPRINT_SHAPE = /^sha256:[0-9a-f]{64}$/;

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

/** Deterministic pseudo-random generator so "random" tests never flake. */
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

/**
 * A SECOND implementation of the v1 format, written inside the test straight
 * from the format description. If it ever disagrees with the real code, either
 * the code or the written format is wrong. `version` is a parameter only so we
 * can prove the version tag really is part of the hash input.
 */
function referenceFingerprint(files: readonly StagedFile[], version = 'v1'): string {
  const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };
  const lp = (b: Buffer): Buffer => Buffer.concat([u32(b.length), b]);

  const sorted = files
    .map((f) => ({ path: Buffer.from(f.path, 'utf8'), content: Buffer.from(f.content, 'utf8') }))
    .sort((a, b) => Buffer.compare(a.path, b.path));

  const parts: Buffer[] = [lp(Buffer.from('proofpatch-snapshot')), lp(Buffer.from(version)), u32(sorted.length)];
  for (const entry of sorted) {
    parts.push(lp(entry.path));
    parts.push(createHash('sha256').update(entry.content).digest()); // 32 raw bytes
  }
  return 'sha256:' + createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

// ---------------------------------------------------------------------------
// 1. Known SHA-256 test vectors (the primitive itself)
// ---------------------------------------------------------------------------

describe('sha256Hex known test vectors', () => {
  const vectors: ReadonlyArray<readonly [string, string, string]> = [
    ['empty input', '', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['"abc"', 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    [
      'FIPS 180-4 two-block message',
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    ],
    [
      'quick brown fox',
      'The quick brown fox jumps over the lazy dog',
      'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
    ],
  ];

  for (const [name, input, expected] of vectors) {
    it(`matches the published digest for ${name}`, () => {
      assert.equal(sha256Hex(utf8(input)), expected);
    });
  }

  it('matches the published digest for one million "a" characters', () => {
    assert.equal(
      sha256Hex(utf8('a'.repeat(1_000_000))),
      'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    );
  });

  it('returns 64 lowercase hex characters', () => {
    assert.match(sha256Hex(utf8('anything')), /^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// 2. Per-file digests
// ---------------------------------------------------------------------------

describe('digestFile', () => {
  it('hashes the exact UTF-8 bytes of the content', () => {
    assert.deepEqual(digestFile(file('a.txt', 'abc')), {
      path: 'a.txt',
      sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      bytes: 3,
    });
  });

  it('gives the well-known empty digest and 0 bytes for an empty file', () => {
    assert.deepEqual(digestFile(file('empty.txt', '')), {
      path: 'empty.txt',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      bytes: 0,
    });
  });

  it('counts UTF-8 BYTES, not characters', () => {
    assert.equal(digestFile(file('a', '\u00e9')).bytes, 2); // é = 2 bytes
    assert.equal(digestFile(file('a', '\u6587')).bytes, 3); // 文 = 3 bytes
    assert.equal(digestFile(file('a', '\u{1F600}')).bytes, 4); // emoji = 4 bytes
  });

  it('does not depend on the path (same content, different path -> same digest)', () => {
    assert.equal(digestFile(file('a.txt', 'same')).sha256, digestFile(file('b/c.txt', 'same')).sha256);
  });

  it('keeps NUL characters inside content (they are valid text here)', () => {
    assert.notEqual(digestFile(file('a', 'x\0y')).sha256, digestFile(file('a', 'xy')).sha256);
  });

  it('returns a frozen object', () => {
    assert.ok(Object.isFrozen(digestFile(file('a', 'x'))));
  });
});

// ---------------------------------------------------------------------------
// 3. Manifest shape
// ---------------------------------------------------------------------------

describe('buildSnapshotManifest shape', () => {
  const manifest: SnapshotManifest = buildSnapshotManifest([
    file('src/b.py', 'b'),
    file('README.md', 'readme'),
    file('src/a.py', 'a'),
  ]);

  it('declares format v1 and sha256', () => {
    assert.equal(manifest.formatVersion, 'v1');
    assert.equal(manifest.formatVersion, FINGERPRINT_FORMAT_VERSION);
    assert.equal(manifest.algorithm, 'sha256');
  });

  it('has a fingerprint of the form sha256:<64 lowercase hex>', () => {
    assert.match(manifest.fingerprint, FINGERPRINT_SHAPE);
    assert.ok(manifest.fingerprint.startsWith(FINGERPRINT_PREFIX));
  });

  it('lists files sorted by path in byte order, each with a digest and byte count', () => {
    assert.deepEqual(
      manifest.files.map((f) => f.path),
      ['README.md', 'src/a.py', 'src/b.py'],
    );
    for (const entry of manifest.files) {
      assert.match(entry.sha256, /^[0-9a-f]{64}$/);
      assert.ok(Number.isInteger(entry.bytes) && entry.bytes >= 0);
    }
  });

  it('never contains file content', () => {
    const json = JSON.stringify(buildSnapshotManifest([file('secret.txt', 'TOP-SECRET-VALUE')]));
    assert.ok(!json.includes('TOP-SECRET-VALUE'));
  });

  it('is deeply frozen (manifest, files array and every digest)', () => {
    assert.ok(Object.isFrozen(manifest));
    assert.ok(Object.isFrozen(manifest.files));
    assert.ok(manifest.files.every((f) => Object.isFrozen(f)));
    assert.throws(() => {
      (manifest as { fingerprint: string }).fingerprint = 'sha256:' + '0'.repeat(64);
    }, TypeError);
  });

  it('does not modify the input array or its files', () => {
    const input = [file('b', '2'), file('a', '1')];
    const before = JSON.stringify(input);
    buildSnapshotManifest(input);
    assert.equal(JSON.stringify(input), before);
  });
});

// ---------------------------------------------------------------------------
// 4. Golden vectors (computed by an independent implementation)
// ---------------------------------------------------------------------------

describe('golden fingerprints', () => {
  const GOLDEN_FILES: StagedFile[] = [
    file('src/app.py', 'print("hello")\n'),
    file('README.md', '# Demo\r\n'),
    file('tests/test_app.py', 'def test_ok():\n    assert True\n'),
    file('empty.txt', ''),
    file('docs/caf\u00e9.md', '\u00e9\u{1F600}'),
  ];

  it('produces the pinned fingerprint for a mixed 5-file snapshot', () => {
    assert.equal(
      fingerprintOf(GOLDEN_FILES),
      'sha256:e0b9038a771e28566fdfea57d459484a0c9867ea6e205a6d37c940b26c19db82',
    );
  });

  it('produces the pinned per-file digests, in sorted order, with UTF-8 byte counts', () => {
    assert.deepEqual(
      buildSnapshotManifest(GOLDEN_FILES).files.map((f) => [f.path, f.sha256, f.bytes]),
      [
        ['README.md', 'a0ac7db66ef769cfac4bfb742c3aa8d53c6c86d0b132c2a09936391f8935f6af', 8],
        ['docs/caf\u00e9.md', '1184d1f608158eea09d297565575892231550c403aaa913008d867a97cfd5c76', 6],
        ['empty.txt', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0],
        ['src/app.py', 'b80792336156c7b0f7fe02eeef24610d2d52a10d1810397744471d1dc5738180', 15],
        ['tests/test_app.py', 'deb22a8dcf2d38aed20a69016b83c4596f06b390b59eb3b0b99e0d66ba737376', 31],
      ],
    );
  });

  it('produces the pinned fingerprint for an empty snapshot', () => {
    assert.equal(
      fingerprintOf([]),
      'sha256:f8835b1518b803122f90223bc60f55246d5b9d576ba84e3cd098770479e02026',
    );
  });

  it('agrees with the in-test reference implementation of the written format', () => {
    assert.equal(fingerprintOf(GOLDEN_FILES), referenceFingerprint(GOLDEN_FILES));
    assert.equal(fingerprintOf([]), referenceFingerprint([]));
  });

  it('includes the version tag in the hash input (changing "v1" changes the result)', () => {
    assert.notEqual(referenceFingerprint(GOLDEN_FILES, 'v1'), referenceFingerprint(GOLDEN_FILES, 'v2'));
    assert.equal(fingerprintOf(GOLDEN_FILES), referenceFingerprint(GOLDEN_FILES, 'v1'));
    assert.notEqual(fingerprintOf(GOLDEN_FILES), referenceFingerprint(GOLDEN_FILES, 'v2'));
  });
});

// ---------------------------------------------------------------------------
// 5. Determinism and input-order independence
// ---------------------------------------------------------------------------

describe('determinism', () => {
  it('gives the same fingerprint when computed twice', () => {
    const files = [file('a', '1'), file('b', '2')];
    assert.equal(fingerprintOf(files), fingerprintOf(files));
  });

  it('gives the same fingerprint for freshly built equal inputs', () => {
    assert.equal(
      fingerprintOf([file('a', '1'), file('b', '2')]),
      fingerprintOf([file('a', '1'), file('b', '2')]),
    );
  });

  it('is independent of input order (all 120 orderings of 5 files)', () => {
    const files = [
      file('src/app.py', 'app'),
      file('README.md', 'readme'),
      file('tests/t.py', 'test'),
      file('src/\u00e9.py', 'accent'),
      file('.github/ci.yml', 'ci'),
    ];
    const expected = fingerprintOf(files);
    for (const ordering of permutations(files)) {
      assert.equal(fingerprintOf(ordering), expected);
    }
  });

  it('is independent of input order for 200 seeded pseudo-random files', () => {
    const random = seededRandom(2024);
    const files: StagedFile[] = [];
    for (let i = 0; i < 200; i++) {
      files.push(file(`dir${i % 7}/file${i}.txt`, `content-${Math.floor(random() * 1e9)}\n`));
    }
    const expected = fingerprintOf(files);
    for (let round = 0; round < 5; round++) {
      const copy = [...files];
      for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(random() * (i + 1));
        [copy[i], copy[j]] = [copy[j] as StagedFile, copy[i] as StagedFile];
      }
      assert.equal(fingerprintOf(copy), expected);
    }
    assert.equal(expected, referenceFingerprint(files));
  });

  it('ignores extra properties on the input objects (only path and content count)', () => {
    const plain = file('a.txt', 'x');
    const decorated = { ...plain, note: 'ignored', mode: 0o755 } as StagedFile;
    assert.equal(fingerprintOf([plain]), fingerprintOf([decorated]));
  });
});

// ---------------------------------------------------------------------------
// 6. Anything that matters must change the fingerprint
// ---------------------------------------------------------------------------

describe('changes produce a different fingerprint', () => {
  const base = [file('a.txt', 'alpha'), file('b.txt', 'beta')];
  const baseFingerprint = fingerprintOf(base);

  it('changing one byte of content', () => {
    assert.notEqual(fingerprintOf([file('a.txt', 'alpha'), file('b.txt', 'betb')]), baseFingerprint);
  });

  it('changing only the case of content', () => {
    assert.notEqual(fingerprintOf([file('a.txt', 'Alpha'), file('b.txt', 'beta')]), baseFingerprint);
  });

  it('adding a file', () => {
    assert.notEqual(fingerprintOf([...base, file('c.txt', 'gamma')]), baseFingerprint);
  });

  it('adding an EMPTY file', () => {
    assert.notEqual(fingerprintOf([...base, file('empty.txt', '')]), baseFingerprint);
  });

  it('removing a file', () => {
    assert.notEqual(fingerprintOf([file('a.txt', 'alpha')]), baseFingerprint);
  });

  it('removing every file (empty snapshot differs from a non-empty one)', () => {
    assert.notEqual(fingerprintOf([]), baseFingerprint);
    assert.notEqual(fingerprintOf([file('empty.txt', '')]), fingerprintOf([]));
  });

  it('renaming a file (same content, new path)', () => {
    assert.notEqual(fingerprintOf([file('renamed.txt', 'alpha'), file('b.txt', 'beta')]), baseFingerprint);
  });

  it('moving a file to another directory', () => {
    assert.notEqual(fingerprintOf([file('dir/a.txt', 'alpha'), file('b.txt', 'beta')]), baseFingerprint);
  });

  it('swapping the contents of two files (path <-> content binding)', () => {
    assert.notEqual(fingerprintOf([file('a.txt', 'beta'), file('b.txt', 'alpha')]), baseFingerprint);
  });

  it('changing only the case of a path', () => {
    assert.notEqual(fingerprintOf([file('A.txt', 'alpha'), file('b.txt', 'beta')]), baseFingerprint);
  });

  it('splitting content across two files', () => {
    assert.notEqual(fingerprintOf([file('a', 'xy')]), fingerprintOf([file('a', 'x'), file('b', 'y')]));
  });
});

describe('line endings and invisible characters are NOT normalized', () => {
  it('distinguishes CRLF from LF', () => {
    const lf = fingerprintOf([file('f.txt', 'line1\nline2\n')]);
    const crlf = fingerprintOf([file('f.txt', 'line1\r\nline2\r\n')]);
    assert.notEqual(lf, crlf);
    assert.equal(lf, 'sha256:' + referenceFingerprint([file('f.txt', 'line1\nline2\n')]).slice(7));
  });

  it('distinguishes a lone CR from LF and from CRLF', () => {
    const results = new Set(['a\rb', 'a\nb', 'a\r\nb'].map((c) => fingerprintOf([file('f', c)])));
    assert.equal(results.size, 3);
  });

  it('matches the independently computed LF and CRLF fingerprints', () => {
    assert.equal(
      fingerprintOf([file('f', 'a\nb')]),
      'sha256:df9b12fc5a9c88182a71fc943a70c9e50449b56a2ce2216b912c3250665177c3',
    );
    assert.equal(
      fingerprintOf([file('f', 'a\r\nb')]),
      'sha256:762ba869537bd8cc0a0e2564d49d4203aa3517b144260c676501f1c40efc995e',
    );
  });

  it('distinguishes a trailing newline', () => {
    assert.notEqual(fingerprintOf([file('f', 'x')]), fingerprintOf([file('f', 'x\n')]));
  });

  it('distinguishes a leading BOM (U+FEFF)', () => {
    assert.notEqual(fingerprintOf([file('f', 'x')]), fingerprintOf([file('f', '\uFEFFx')]));
  });

  it('distinguishes composed from decomposed Unicode in content', () => {
    assert.notEqual(
      fingerprintOf([file('f', 'caf\u00e9')]), // é as one character
      fingerprintOf([file('f', 'cafe\u0301')]), // e + combining accent
    );
  });
});

// ---------------------------------------------------------------------------
// 7. Unambiguous encoding (length prefixes, no concatenation tricks)
// ---------------------------------------------------------------------------

describe('unambiguous encoding', () => {
  it('path "a" + content "bc" differs from path "ab" + content "c"', () => {
    // Plain concatenation would see "abc" both times.
    assert.equal('a' + 'bc', 'ab' + 'c');
    assert.notEqual(fingerprintOf([file('a', 'bc')]), fingerprintOf([file('ab', 'c')]));
    assert.equal(
      fingerprintOf([file('a', 'bc')]),
      'sha256:cae2358fa6bd2c12d8258311c07905a998ffa8740e9747d90e65ee44f7e9167c',
    );
    assert.equal(
      fingerprintOf([file('ab', 'c')]),
      'sha256:85c471e5dac17acc046a5cda721d6d1316ee972e54668acc9c012568fc172d83',
    );
  });

  it('cannot be fooled by separator-like characters inside paths or content', () => {
    const tricky = [
      [file('a', '\n'), file('b', '')],
      [file('a', ''), file('b', '\n')],
      [file('a\n', ''), file('b', '')],
      [file('a', ':b:'), file('c', '')],
      [file('ab:c', ''), file('c', '')], // ("a:b" would be rejected by Step 2 as a drive-letter path)
    ];
    const results = new Set(tricky.map((files) => fingerprintOf(files)));
    assert.equal(results.size, tricky.length);
  });

  it('keeps two-file layouts distinct when the same text is split differently', () => {
    assert.notEqual(
      fingerprintOf([file('a', 'b'), file('c', 'd')]),
      fingerprintOf([file('a', 'bc'), file('d', '')]),
    );
  });

  it('matches the reference implementation for tricky inputs', () => {
    const files = [file('a/b', 'x\0y\r\n'), file('a.b', ''), file('\u{1F600}', '\u{1F600}'), file('z', 'a\nb')];
    assert.equal(fingerprintOf(files), referenceFingerprint(files));
  });
});

// ---------------------------------------------------------------------------
// 8. Rejection, never repair
// ---------------------------------------------------------------------------

describe('invalid input is rejected, never repaired', () => {
  it('rejects unsafe paths with SnapshotPathError (uses Step 2 rules)', () => {
    for (const [path, code] of [
      ['../x', 'traversal'],
      ['/abs', 'absolute'],
      ['a\\b', 'backslash'],
      ['C:/x', 'drive_letter'],
      ['a//b', 'empty_segment'],
      ['a\0b', 'nul'],
    ] as const) {
      assert.throws(() => fingerprintOf([file(path, 'x')]), (error: unknown) => {
        assert.ok(error instanceof SnapshotPathError);
        assert.equal(error.code, code);
        return true;
      });
    }
  });

  it('rejects duplicate paths', () => {
    assert.throws(() => fingerprintOf([file('a', '1'), file('a', '2')]), { code: 'duplicate' });
  });

  it('rejects content with a lone surrogate instead of hashing a lossy copy', () => {
    // Without this check both strings would be encoded with U+FFFD and look identical.
    for (const bad of ['\uD800', 'ok\uDC00', 'x\uD83D']) {
      assert.throws(() => fingerprintOf([file('f', bad)]), (error: unknown) => {
        assert.ok(error instanceof SnapshotContentError);
        assert.equal(error.code, 'invalid_unicode');
        assert.equal(error.path, 'f');
        return true;
      });
    }
  });

  it('accepts a real U+FFFD in content (it is valid text) and a valid surrogate pair', () => {
    assert.doesNotThrow(() => fingerprintOf([file('f', 'caf\uFFFD')]));
    assert.doesNotThrow(() => fingerprintOf([file('f', '\u{1F600}')]));
    assert.notEqual(fingerprintOf([file('f', '\uFFFD')]), fingerprintOf([file('f', '?')]));
  });

  it('rejects non-string content', () => {
    for (const bad of [undefined, null, 42, {}, Buffer.from('x')]) {
      assert.throws(
        () => fingerprintOf([{ path: 'f', content: bad } as unknown as StagedFile]),
        (error: unknown) => {
          assert.ok(error instanceof SnapshotContentError);
          assert.equal(error.code, 'not_string');
          return true;
        },
      );
    }
  });

  it('never puts file content in an error message', () => {
    try {
      fingerprintOf([file('secret.txt', 'TOP-SECRET\uD800')]);
      assert.fail('expected an error');
    } catch (error) {
      assert.ok(error instanceof SnapshotContentError);
      assert.ok(!error.message.includes('TOP-SECRET'));
      assert.ok(error.message.includes('secret.txt'));
    }
  });

  it('fails as a whole: one bad file means no manifest at all', () => {
    assert.throws(() => buildSnapshotManifest([file('ok.txt', 'fine'), file('bad.txt', '\uD800')]));
  });
});

// ---------------------------------------------------------------------------
// 9. Size and platform behaviour
// ---------------------------------------------------------------------------

describe('larger inputs', () => {
  it('handles a 2 MB file and reports its byte size', () => {
    const big = 'x'.repeat(2_000_000);
    const manifest = buildSnapshotManifest([file('big.txt', big)]);
    assert.equal(manifest.files[0]?.bytes, 2_000_000);
    assert.equal(manifest.fingerprint, referenceFingerprint([file('big.txt', big)]));
  });

  it('handles 2,000 small files and matches the reference implementation', () => {
    const files: StagedFile[] = [];
    for (let i = 0; i < 2000; i++) files.push(file(`d${i % 20}/f${i}.txt`, `n=${i}\n`));
    assert.equal(fingerprintOf(files), referenceFingerprint(files));
  });

  it('is identical regardless of the operating system (pure computation, no file access)', () => {
    // The pinned golden values above are the same literals on Windows and Linux.
    // This test only documents that nothing here depends on process.platform.
    const before = fingerprintOf([file('a', 'x')]);
    assert.equal(before, fingerprintOf([file('a', 'x')]));
  });
});
