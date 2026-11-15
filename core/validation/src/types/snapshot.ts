/**
 * Snapshot manifest types (Phase 2, Step 1).
 *
 * A manifest is the "receipt" for one staged snapshot: the list of files that
 * were hashed (path + SHA-256 + size) and the single fingerprint derived from
 * them. It is what a validation run is stamped with.
 *
 * TYPES ONLY. Nothing here computes a hash. Building a manifest is done in
 * later steps (canonicalization in Step 2, hashing in Step 3).
 *
 * INDEPENDENT of Member 4 EXCEPT the fingerprint format, which is PROVISIONAL:
 * `sha256:<hex>` with a "v1" format tag. It must be agreed with Member 4
 * before integration (see ./provisional.ts and ../../README.md).
 */
import type { SnapshotFingerprint } from './provisional.js';

/** Hash algorithm used for file digests and the snapshot fingerprint. */
export type HashAlgorithm = 'sha256';

/**
 * Version of the canonical form that was hashed (how paths are ordered and how
 * fields are framed). Stored so old evidence can be told apart if the format
 * ever changes. Only 'v1' exists.
 */
export type FingerprintFormatVersion = 'v1';

/**
 * A SHA-256 digest as 64 lowercase hexadecimal characters, with NO prefix
 * (e.g. "e3b0c442..."). The type is documentation only: TypeScript cannot
 * check the length or the characters. The hashing code (Step 3) guarantees it.
 */
export type Sha256Hex = string;

/**
 * The snapshot fingerprint in its provisional format: the literal prefix
 * "sha256:" followed by 64 lowercase hex characters.
 *
 * The compiler enforces the "sha256:" prefix; the hex part is guaranteed by
 * the hashing code. It is assignable to the plain `SnapshotFingerprint`
 * (a string) used by evidence and ledger types, so those need no change.
 *
 * PROVISIONAL until agreed with Member 4.
 */
export type Sha256Fingerprint = `sha256:${string}`;

/** Digest of one file in the snapshot. */
export interface FileDigest {
  /**
   * Validated, repo-relative path with "/" separators (rules are enforced in
   * Step 2). Never absolute, never contains "..".
   */
  readonly path: string;
  /** SHA-256 of the file's content bytes (UTF-8 encoding of the text). */
  readonly sha256: Sha256Hex;
  /** Size of the content in bytes (UTF-8), a non-negative integer. */
  readonly bytes: number;
}

/**
 * Receipt for one snapshot.
 *
 * Invariants that the code in later steps must guarantee (the compiler cannot
 * check them):
 *  - `files` is sorted by path in raw byte order and has no duplicate paths;
 *  - `fingerprint` depends only on `formatVersion`, `algorithm`-hashed
 *    contents and the sorted (path, digest) pairs, never on input order,
 *    temp folder locations or timestamps;
 *  - the same files always give the same manifest; any change to a path, a
 *    file's content, or the set of files gives a different `fingerprint`.
 */
export interface SnapshotManifest {
  readonly formatVersion: FingerprintFormatVersion;
  readonly algorithm: HashAlgorithm;
  /** Identity of the whole snapshot. Copied into every validation result. */
  readonly fingerprint: Sha256Fingerprint;
  /** One entry per file, sorted by path. */
  readonly files: readonly FileDigest[];
}
