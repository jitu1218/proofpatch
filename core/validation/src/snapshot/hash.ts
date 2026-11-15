/**
 * SHA-256 snapshot fingerprinting (Phase 2, Step 3).
 *
 * Turns a set of staged files into a SnapshotManifest: one SHA-256 digest per
 * file plus ONE fingerprint for the whole snapshot. Same files in -> same
 * fingerprint out, on every machine. Any change to a path, a file's content or
 * the set of files -> a different fingerprint.
 *
 * =============================================================================
 * EXACT HASH FORMAT, version "v1"   (PROVISIONAL until agreed with Member 4)
 * =============================================================================
 *
 * 1. File digest
 *      fileDigest = SHA-256( UTF-8 bytes of the file's text content )
 *    No newline conversion, no BOM stripping, no Unicode normalization.
 *    "\r\n" and "\n" are different bytes and give different digests.
 *
 * 2. Snapshot hash input (a byte stream, built in this exact order)
 *      lp("proofpatch-snapshot")        domain tag: this hash is for snapshots only
 *      lp("v1")                         format version
 *      u32(fileCount)                   number of files
 *      then, for each file in canonical order (UTF-8 byte order of the path):
 *        lp(path as UTF-8)              the path
 *        fileDigest (exactly 32 bytes)  raw digest bytes (not hex text)
 *
 *    where
 *      u32(n)  = n as an unsigned 32-bit BIG-endian integer (4 bytes)
 *      lp(b)   = u32(byte length of b) followed by the bytes of b
 *
 *    Every variable-length field is length-prefixed and the digest has a fixed
 *    width (32 bytes), so the stream can be read back in only one way. There is
 *    no separator character that a path could contain, and "path a + content
 *    bc" can never be confused with "path ab + content c".
 *
 * 3. Fingerprint
 *      fingerprint = "sha256:" + lowercase-hex( SHA-256( snapshot hash input ) )
 *
 * Why the file CONTENT is hashed separately and only its digest enters the
 * stream: the stream stays small and fixed-shape however big a file is, and a
 * file's content can never be mistaken for framing bytes.
 *
 * What is NOT part of the hash: timestamps, the temp folder location, the
 * machine, the order the files were given in, and anything about a file other
 * than its path and text content (deleted/renamed intent, file modes and
 * binary data are not modelled; see provisional.ts).
 *
 * An empty snapshot (zero files) is allowed and has a well-defined fingerprint.
 * =============================================================================
 */
import { createHash, type Hash } from 'node:crypto';

import type {
  FileDigest,
  FingerprintFormatVersion,
  Sha256Fingerprint,
  Sha256Hex,
  SnapshotManifest,
  StagedFile,
} from '../types/index.js';
import { assertSafeSnapshotPath, canonicalizeByPath } from './canonical.js';

/** Format version written into every manifest and into the hash input. */
export const FINGERPRINT_FORMAT_VERSION: FingerprintFormatVersion = 'v1';

/** Literal prefix of every fingerprint string. */
export const FINGERPRINT_PREFIX = 'sha256:';

/** Domain-separation tag: the first field of the hash input. */
const DOMAIN_TAG = 'proofpatch-snapshot';

/** Why a file's content could not be hashed. */
export type SnapshotContentProblem =
  | 'not_string' // content is not a JavaScript string
  | 'invalid_unicode'; // contains a lone surrogate, so it has no exact UTF-8 form

/**
 * Thrown when content cannot be hashed exactly. We refuse instead of hashing
 * a lossy version: UTF-8 encoding would silently turn each lone surrogate into
 * U+FFFD, so two different contents could get the same digest. The message
 * names only the path, never the content.
 */
export class SnapshotContentError extends Error {
  readonly code: SnapshotContentProblem;
  readonly path: string;

  constructor(code: SnapshotContentProblem, path: string) {
    const why =
      code === 'not_string'
        ? 'content is not a string'
        : 'content is not well-formed Unicode (lone surrogate)';
    super(`Cannot hash ${JSON.stringify(path)}: ${why}`);
    this.name = 'SnapshotContentError';
    this.code = code;
    this.path = path;
  }
}

// Same rule as in canonical.ts: a UTF-16 surrogate without its partner.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** SHA-256 of raw bytes as 64 lowercase hex characters. */
export function sha256Hex(bytes: Uint8Array): Sha256Hex {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Digest of one file: validates the path, encodes the content as UTF-8 exactly
 * as given (no normalization), and returns { path, sha256, bytes }.
 * The returned object is frozen.
 */
export function digestFile(file: StagedFile): FileDigest {
  assertSafeSnapshotPath(file.path);
  const content: unknown = file.content;
  if (typeof content !== 'string') {
    throw new SnapshotContentError('not_string', file.path);
  }
  if (LONE_SURROGATE.test(content)) {
    throw new SnapshotContentError('invalid_unicode', file.path);
  }
  const bytes = Buffer.from(content, 'utf8');
  return Object.freeze({ path: file.path, sha256: sha256Hex(bytes), bytes: bytes.length });
}

/** u32(n): unsigned 32-bit big-endian integer. */
function u32(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`Value ${value} does not fit in an unsigned 32-bit integer`);
  }
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

/** lp(b): u32(length) followed by the bytes. */
function updateLengthPrefixed(hash: Hash, bytes: Uint8Array): void {
  hash.update(u32(bytes.length));
  hash.update(bytes);
}

/** Builds the v1 hash input for already-canonical (sorted, unique) digests. */
function fingerprintOfDigests(digests: readonly FileDigest[]): Sha256Fingerprint {
  const hash = createHash('sha256');
  updateLengthPrefixed(hash, Buffer.from(DOMAIN_TAG, 'utf8'));
  updateLengthPrefixed(hash, Buffer.from(FINGERPRINT_FORMAT_VERSION, 'utf8'));
  hash.update(u32(digests.length));
  for (const digest of digests) {
    updateLengthPrefixed(hash, Buffer.from(digest.path, 'utf8'));
    hash.update(Buffer.from(digest.sha256, 'hex')); // exactly 32 raw bytes
  }
  return `${FINGERPRINT_PREFIX}${hash.digest('hex')}`;
}

/**
 * Builds the manifest ("receipt") for a snapshot:
 *  1. validates paths, rejects duplicates and sorts by byte order (Step 2);
 *  2. digests every file's content;
 *  3. derives the snapshot fingerprint from the sorted (path, digest) pairs.
 *
 * The order of `files` never matters. Throws (and returns nothing) if any path
 * is unsafe (SnapshotPathError) or any content cannot be hashed exactly
 * (SnapshotContentError). The input is not modified; the result is frozen.
 */
export function buildSnapshotManifest(files: readonly StagedFile[]): SnapshotManifest {
  const ordered = canonicalizeByPath(files);
  const digests = ordered.map(digestFile);
  return Object.freeze({
    formatVersion: FINGERPRINT_FORMAT_VERSION,
    algorithm: 'sha256',
    fingerprint: fingerprintOfDigests(digests),
    files: Object.freeze(digests),
  });
}
