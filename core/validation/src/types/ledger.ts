/**
 * Validation Freshness Ledger types.
 * INDEPENDENT of other members, except snapshot fingerprints (provisional
 * format) and conflict paths (reported by Member 4's patch engine).
 */
import type {
  FailingRunResult,
  InconclusiveRunResult,
  PassedRunResult,
  ValidationRunResult,
} from './evidence.js';
import type { SnapshotFingerprint } from './provisional.js';

/**
 * The five freshness states. "NOT RUN" is written NOT_RUN in code; the UI
 * (Member 3) may render it with a space.
 */
export type FreshnessState = 'FRESH' | 'STALE' | 'FAILED' | 'CONFLICT' | 'NOT_RUN';

/** What changed after a validation run, making its evidence STALE. */
export type StaleReason =
  | 'staged_content_changed'
  | 'accepted_hunks_changed'
  | 'command_changed'
  | 'validation_inputs_changed';

/**
 * No conclusive evidence exists for the current snapshot.
 * `lastAttempt` may hold a cancelled / snapshot_changed run for display only;
 * it is inconclusive and never counts as a pass or a failure.
 */
export interface NotRunEntry {
  readonly state: 'NOT_RUN';
  readonly currentSnapshot: SnapshotFingerprint;
  readonly lastAttempt?: InconclusiveRunResult;
}

/**
 * A successful run matches the current snapshot and context.
 * `evidence` is PassedRunResult (status exactly 'passed', exitCode 0), so a
 * failed, timed-out, cancelled, spawn-error or snapshot-changed result cannot
 * be placed here. The compiler cannot check that
 * evidence.snapshotFingerprint === currentSnapshot; the Phase 3 ledger logic
 * must enforce it at runtime.
 */
export interface FreshEntry {
  readonly state: 'FRESH';
  readonly currentSnapshot: SnapshotFingerprint;
  readonly evidence: PassedRunResult;
}

/**
 * The check was attempted against the current snapshot and did not pass.
 * `evidence` can never be a 'passed' result (see FailingRunResult).
 */
export interface FailedEntry {
  readonly state: 'FAILED';
  readonly currentSnapshot: SnapshotFingerprint;
  readonly evidence: FailingRunResult;
}

/**
 * Evidence exists but no longer matches the current snapshot/context.
 * `evidence` is kept only as history; it must never be shown as current.
 * evidence.snapshotFingerprint !== currentSnapshot (or the context differs).
 * Any past result may become stale, so this keeps the general union.
 */
export interface StaleEntry {
  readonly state: 'STALE';
  readonly currentSnapshot: SnapshotFingerprint;
  readonly reason: StaleReason;
  readonly evidence: ValidationRunResult;
}

/** A file changed on disk since the proposal; Apply must stop. */
export interface ConflictEntry {
  readonly state: 'CONFLICT';
  readonly conflictingPaths: readonly string[];
}

/**
 * Discriminated union: each state carries exactly the data it needs, e.g.
 * FRESH cannot exist without evidence, so "FRESH with no run" is not
 * representable.
 */
export type LedgerEntry =
  | NotRunEntry
  | FreshEntry
  | FailedEntry
  | StaleEntry
  | ConflictEntry;

/** Ledger entry plus when it was last recomputed (ISO 8601 UTC). */
export interface LedgerRecord {
  readonly entry: LedgerEntry;
  readonly updatedAt: string;
}
