/**
 * PROVISIONAL INTERFACES — depend on Member 4 (Safe Patch Engine).
 *
 * Nothing in this file describes Member 4's real WorkspaceView API. These are
 * the minimum shapes Member 5 NEEDS to consume a staged snapshot and are
 * written from the validation side only. They must be replaced or confirmed
 * once Member 4 shares the real interface.
 *
 * Open questions for Member 4 are listed in ../../README.md.
 */

/**
 * Identity of one exact staged snapshot.
 *
 * PROVISIONAL: the string format (e.g. lowercase hex SHA-256, with or without
 * an "sha256:" prefix) is NOT yet agreed with Member 4. Treat it as opaque and
 * never compare fingerprints produced under different formats.
 */
export type SnapshotFingerprint = string;

/**
 * One file in the staged snapshot (original files + accepted hunks applied).
 *
 * PROVISIONAL, and deliberately limited. This type models ONLY a present,
 * text file at a repo-relative POSIX path. It does NOT model:
 *
 *  - Deleted files: a deletion cannot be expressed. A snapshot that omits a
 *    file is ambiguous (deleted? or never staged?). Until Member 4 defines
 *    deletions, validation may run against files that should be gone, and a
 *    deletion-only change would not change any fingerprint.
 *  - Renamed files: a rename can only appear as "new path present", with the
 *    old path either left behind or silently missing. Rename intent is lost.
 *  - Binary files: `content` is a string. Binary data cannot be represented
 *    without lossy decoding, so binary files must not be passed through this
 *    type and would be excluded from hashing and validation.
 *  - File modes: the executable bit, symlinks and permissions are absent. A
 *    mode-only change (e.g. chmod +x on a script) is invisible, so it would not
 *    make evidence STALE, and a temp snapshot may not recreate the same modes.
 *  - Line endings / encoding: no encoding is declared; text is assumed UTF-8
 *    and any CRLF/LF difference is part of `content`.
 *
 * Whenever a limitation above matters for a result, the report must say the
 * check was run on an incomplete model of the staged change. Do not claim an
 * exact-snapshot validation for changes this type cannot express.
 *
 * Do not extend this interface to guess Member 4's design; wait for the real
 * WorkspaceView contract (see ../../README.md open questions).
 */
export interface StagedFile {
  /** Path relative to the workspace root, using "/" separators. */
  readonly path: string;
  readonly content: string;
}

/**
 * The exact staged content to validate.
 * PROVISIONAL.
 */
export interface StagedSnapshot {
  readonly files: readonly StagedFile[];
  /** Git base commit the proposal was made against, if Member 4 provides it. */
  readonly baseCommit?: string;
  /** Identity assigned by Member 4, if they define one. Not assumed to exist. */
  readonly externalIdentity?: string;
}

/**
 * What Member 5 requires from the patch engine side: a way to obtain the
 * current staged snapshot. A Member 4 adapter will implement this later.
 * PROVISIONAL.
 */
export interface StagedSnapshotSource {
  getStagedSnapshot(): Promise<StagedSnapshot>;
}

/**
 * A disk-conflict report coming from the patch engine (a file changed on disk
 * after the proposal was created). Member 5 only records it in the ledger.
 * PROVISIONAL: the real shape is owned by Member 4.
 */
export interface DiskConflictReport {
  readonly conflictingPaths: readonly string[];
}
