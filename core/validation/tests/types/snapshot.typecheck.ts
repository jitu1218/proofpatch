/**
 * Compile-time tests for the snapshot manifest types. Nothing here runs:
 * `tsc` must accept every valid line and REJECT every line marked
 * @ts-expect-error. If a forbidden shape ever becomes valid, the
 * @ts-expect-error turns into an "unused directive" error and tsc fails.
 *
 * Checked by `npm run typecheck` and also by `npm test` (it compiles tests).
 */
import type {
  FileDigest,
  Sha256Fingerprint,
  SnapshotFingerprint,
  SnapshotManifest,
} from '../../src/index.js';

const hex = '0'.repeat(64);

// ---- Valid shapes ------------------------------------------------------------
export const digestOk: FileDigest = { path: 'src/app.py', sha256: hex, bytes: 12 };

export const manifestOk: SnapshotManifest = {
  formatVersion: 'v1',
  algorithm: 'sha256',
  fingerprint: `sha256:${hex}`,
  files: [digestOk],
};

export const manifestEmpty: SnapshotManifest = {
  formatVersion: 'v1',
  algorithm: 'sha256',
  fingerprint: `sha256:${hex}`,
  files: [],
};

// ---- FileDigest requires all three fields, with the right types ---------------
// @ts-expect-error missing "bytes"
export const digestNoBytes: FileDigest = { path: 'a.txt', sha256: hex };
// @ts-expect-error missing "sha256"
export const digestNoHash: FileDigest = { path: 'a.txt', bytes: 1 };
// @ts-expect-error missing "path"
export const digestNoPath: FileDigest = { sha256: hex, bytes: 1 };
// @ts-expect-error bytes must be a number
export const digestBytesString: FileDigest = { path: 'a.txt', sha256: hex, bytes: '1' };
// @ts-expect-error unknown extra field (e.g. file content must never be stored here)
export const digestWithContent: FileDigest = { path: 'a.txt', sha256: hex, bytes: 1, content: 'secret' };

// ---- Manifest: fixed algorithm and format version ------------------------------
export const manifestMd5: SnapshotManifest = {
  formatVersion: 'v1',
  // @ts-expect-error only sha256 is supported
  algorithm: 'md5',
  fingerprint: `sha256:${hex}`,
  files: [],
};
export const manifestV2: SnapshotManifest = {
  // @ts-expect-error only format version v1 exists
  formatVersion: 'v2',
  algorithm: 'sha256',
  fingerprint: `sha256:${hex}`,
  files: [],
};

// ---- Manifest: the fingerprint must carry the "sha256:" prefix -----------------
export const manifestNoPrefix: SnapshotManifest = {
  formatVersion: 'v1',
  algorithm: 'sha256',
  // @ts-expect-error a bare hex string is not a prefixed fingerprint
  fingerprint: hex,
  files: [],
};
export const manifestWrongPrefix: SnapshotManifest = {
  formatVersion: 'v1',
  algorithm: 'sha256',
  // @ts-expect-error wrong algorithm prefix
  fingerprint: `md5:${hex}`,
  files: [],
};

// ---- Manifest: all four fields are required ------------------------------------
// @ts-expect-error missing "files"
export const manifestNoFiles: SnapshotManifest = { formatVersion: 'v1', algorithm: 'sha256', fingerprint: `sha256:${hex}` };
// @ts-expect-error missing "fingerprint"
export const manifestNoFingerprint: SnapshotManifest = { formatVersion: 'v1', algorithm: 'sha256', files: [] };
// @ts-expect-error missing "formatVersion"
export const manifestNoVersion: SnapshotManifest = { algorithm: 'sha256', fingerprint: `sha256:${hex}`, files: [] };

// ---- Manifest is read-only after creation --------------------------------------
export function mutationAttempts(m: SnapshotManifest): void {
  // @ts-expect-error fingerprint is readonly
  m.fingerprint = `sha256:${hex}`;
  // @ts-expect-error files array is readonly
  m.files = [];
  // @ts-expect-error cannot push to a readonly array
  m.files.push(digestOk);
  // @ts-expect-error digest fields are readonly
  m.files[0]!.bytes = 0;
}

// ---- Compatibility with Phase 1 evidence/ledger types --------------------------
// A prefixed manifest fingerprint is usable as a SnapshotFingerprint...
export const asSnapshotFingerprint: SnapshotFingerprint = manifestOk.fingerprint;
// ...but an arbitrary string is NOT automatically a valid Sha256Fingerprint.
export function fromPlainString(s: SnapshotFingerprint): Sha256Fingerprint {
  // @ts-expect-error a plain string has not been checked for the "sha256:" prefix
  return s;
}
