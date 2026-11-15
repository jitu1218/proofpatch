/**
 * Validation Freshness Ledger (Phase 3).
 *
 * Associates each validation result with its identity information and determines
 * whether that evidence is still trustworthy for the CURRENT snapshot and
 * execution context.
 *
 * FRESHNESS RULES (enforced at runtime; the type system enforces as many as it
 * can, but snapshot/context equality is a string comparison that only the
 * runtime can verify):
 *
 *  1. A successful result is FRESH only for the exact (snapshot, context) pair
 *     it validated.
 *  2. A failed result remains FAILED for the (snapshot, context) pair it
 *     validated.
 *  3. If the staged snapshot changes, previous results for that snapshot become
 *     STALE.
 *  4. If the execution context changes, affected results become STALE.
 *  5. A result is never reused as FRESH for a different snapshot.
 *  6. A result is never reused as FRESH for a different context.
 *  7. A conflict is represented as CONFLICT, not silently treated as success.
 *  8. A command that has not been executed is represented as NOT_RUN.
 *  9. Missing evidence never becomes a passing result.
 * 10. Aggregation distinguishes FRESH, STALE, FAILED, CONFLICT, and NOT_RUN.
 *
 * Mapping from ExecutionStatus to FreshnessState (confirmed in Phase 1 design):
 *   passed           -> FRESH   (only for matching snapshot + context)
 *   failed           -> FAILED
 *   timed_out        -> FAILED  (attempted and did not pass)
 *   spawn_error      -> FAILED  (attempted and did not pass)
 *   cancelled        -> NOT_RUN (inconclusive — stored only in lastAttempt)
 *   snapshot_changed -> NOT_RUN (inconclusive — stored only in lastAttempt)
 *
 * Any FRESH/FAILED entry whose snapshot or context no longer matches the
 * current values is demoted to STALE.
 */

import type {
  DiskConflictReport,
  FailingRunResult,
  FreshnessState,
  InconclusiveRunResult,
  LedgerEntry,
  LedgerRecord,
  PassedRunResult,
  SnapshotFingerprint,
  StaleReason,
  ValidationRunResult,
} from '../types/index.js';

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export type LedgerProblem =
  | 'missing_snapshot_fingerprint'
  | 'missing_context_fingerprint'
  | 'missing_run_result';

export class ValidationLedgerError extends Error {
  readonly code: LedgerProblem;

  constructor(code: LedgerProblem) {
    super(`Validation ledger error: ${code}`);
    this.name = 'ValidationLedgerError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

/** Narrow a ValidationRunResult to an InconclusiveRunResult if it qualifies. */
function isInconclusiveResult(result: ValidationRunResult): result is InconclusiveRunResult {
  return result.status === 'cancelled' || result.status === 'snapshot_changed';
}

function nowIso(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// LedgerEntry constructors
// ---------------------------------------------------------------------------

/**
 * Returns a NOT_RUN entry for a snapshot that has never been run.
 * Optionally stores an inconclusive past attempt for display.
 */
export function makeNotRunEntry(
  currentSnapshot: SnapshotFingerprint,
  lastAttempt?: InconclusiveRunResult,
): LedgerEntry {
  if (typeof currentSnapshot !== 'string' || currentSnapshot.length === 0) {
    throw new ValidationLedgerError('missing_snapshot_fingerprint');
  }
  if (lastAttempt !== undefined) {
    if (lastAttempt.snapshotFingerprint === currentSnapshot) {
      return Object.freeze({ state: 'NOT_RUN', currentSnapshot, lastAttempt });
    }
  }
  return Object.freeze({ state: 'NOT_RUN', currentSnapshot });
}

/**
 * Records a disk-conflict report as a CONFLICT entry.
 * CONFLICT entries carry no run evidence and no snapshot fingerprint —
 * conflicts are reported by Member 4 independently of a validation run.
 */
export function makeConflictEntry(conflictReport: DiskConflictReport): LedgerEntry {
  return Object.freeze({
    state: 'CONFLICT',
    conflictingPaths: Object.freeze([...conflictReport.conflictingPaths]),
  });
}

// ---------------------------------------------------------------------------
// Core ledger transition: recordResult
// ---------------------------------------------------------------------------

/**
 * Computes a new LedgerEntry from a completed ValidationRunResult, the current
 * snapshot fingerprint, and the expected context fingerprint.
 *
 * Rules:
 *  - If `result` is `passed` AND its snapshotFingerprint matches
 *    `currentSnapshot` AND its contextFingerprint matches
 *    `currentContextFingerprint`, the entry is FRESH.
 *  - If `result` is `passed` but snapshot or context do NOT match, the entry
 *    is STALE (evidence exists but no longer matches). This prevents a passed
 *    result from one snapshot being treated as FRESH for another.
 *  - If `result` is a failing result (`failed`, `timed_out`, `spawn_error`)
 *    AND its snapshotFingerprint matches `currentSnapshot`, the entry is FAILED.
 *  - If `result` is a failing result but its snapshot does NOT match, the
 *    entry is STALE.
 *  - If `result` is inconclusive (`cancelled`, `snapshot_changed`), the entry
 *    is NOT_RUN (with the inconclusive run as `lastAttempt`).
 *
 * @throws ValidationLedgerError if identity fields are missing or empty.
 */
export function recordResult(
  result: ValidationRunResult,
  currentSnapshot: SnapshotFingerprint,
  currentContextFingerprint: string,
): LedgerEntry {
  assertIdentityFields(currentSnapshot, currentContextFingerprint, result);

  if (isInconclusiveResult(result)) {
    const snapshotMatches = result.snapshotFingerprint === currentSnapshot;
    const contextMatches = result.contextFingerprint === currentContextFingerprint;

    if (snapshotMatches && contextMatches) {
      // Inconclusive attempt for current snapshot and context: store for display only.
      return Object.freeze({ state: 'NOT_RUN', currentSnapshot, lastAttempt: result });
    }

    // Inconclusive attempt for a different snapshot or context: preserve as stale history.
    const reason = deriveStaleReason(result, currentSnapshot, currentContextFingerprint);
    return Object.freeze({
      state: 'STALE',
      currentSnapshot,
      reason,
      evidence: result,
    });
  }

  if (result.status === 'passed') {
    const snapshotMatches = result.snapshotFingerprint === currentSnapshot;
    const contextMatches = result.contextFingerprint === currentContextFingerprint;

    if (snapshotMatches && contextMatches) {
      // The only path to FRESH: passed + matching identities.
      const entry: LedgerEntry = Object.freeze({
        state: 'FRESH',
        currentSnapshot,
        evidence: result as PassedRunResult,
      });
      return entry;
    }

    // Passed, but for a different snapshot or context — stale history.
    const reason = deriveStaleReason(result, currentSnapshot, currentContextFingerprint);
    return Object.freeze({
      state: 'STALE',
      currentSnapshot,
      reason,
      evidence: result,
    });
  }

  // Remainder: result is FailingRunResult ('failed' | 'timed_out' | 'spawn_error')
  const snapshotMatches = result.snapshotFingerprint === currentSnapshot;
  const contextMatches = result.contextFingerprint === currentContextFingerprint;

  if (snapshotMatches && contextMatches) {
    // Failed for this exact snapshot and context — a definitive FAILED.
    const entry: LedgerEntry = Object.freeze({
      state: 'FAILED',
      currentSnapshot,
      evidence: result,
    });
    return entry;
  }

  // Failed for a different snapshot or context — stale history.
  const reason = deriveStaleReason(result, currentSnapshot, currentContextFingerprint);
  return Object.freeze({
    state: 'STALE',
    currentSnapshot,
    reason,
    evidence: result,
  });
}

// ---------------------------------------------------------------------------
// Staleness transition: stalеEntry
// ---------------------------------------------------------------------------

/**
 * Demotes an existing FRESH or FAILED ledger entry to STALE when the snapshot
 * or context has changed, without re-running the command.
 *
 * Call this when:
 *  - The staged content changes (-> reason: 'staged_content_changed')
 *  - Accepted hunks change    (-> reason: 'accepted_hunks_changed')
 *  - The command changes      (-> reason: 'command_changed')
 *  - Other validation inputs change (-> reason: 'validation_inputs_changed')
 *
 * A STALE, NOT_RUN, or CONFLICT entry cannot be further demoted.
 * The historical evidence is preserved in the STALE entry for audit purposes.
 *
 * @throws ValidationLedgerError if `entry` has no evidence to preserve, or
 *   if `newSnapshot` is an empty string.
 */
export function staleEntry(
  entry: LedgerEntry,
  newSnapshot: SnapshotFingerprint,
  reason: StaleReason,
): LedgerEntry {
  if (typeof newSnapshot !== 'string' || newSnapshot.length === 0) {
    throw new ValidationLedgerError('missing_snapshot_fingerprint');
  }

  switch (entry.state) {
    case 'FRESH':
    case 'FAILED': {
      return Object.freeze({
        state: 'STALE',
        currentSnapshot: newSnapshot,
        reason,
        evidence: entry.evidence,
      });
    }
    case 'STALE': {
      // Update the snapshot and reason; keep the original historical evidence.
      return Object.freeze({
        state: 'STALE',
        currentSnapshot: newSnapshot,
        reason,
        evidence: entry.evidence,
      });
    }
    case 'NOT_RUN':
    case 'CONFLICT': {
      // These carry no conclusive evidence to demote. Return a fresh NOT_RUN.
      if (entry.state === 'NOT_RUN') {
        return Object.freeze({ state: 'NOT_RUN', currentSnapshot: newSnapshot });
      }
      // CONFLICT: return as-is (conflicts are owned by Member 4; we don't
      // override them here, but Phase 4 will drive conflict resolution).
      return entry;
    }
  }
}

// ---------------------------------------------------------------------------
// LedgerRecord wrapper
// ---------------------------------------------------------------------------

/**
 * Wraps a LedgerEntry in a LedgerRecord with the current wall-clock timestamp.
 * The timestamp is generated at call time; repeated calls produce different
 * timestamps (this is the only intentionally non-deterministic part).
 */
export function makeLedgerRecord(entry: LedgerEntry): LedgerRecord {
  return Object.freeze({ entry, updatedAt: nowIso() });
}

// ---------------------------------------------------------------------------
// Freshness query helpers
// ---------------------------------------------------------------------------

/** Returns true if the entry is currently FRESH (and counts as a pass). */
export function isFresh(entry: LedgerEntry): boolean {
  return entry.state === 'FRESH';
}

/** Returns true if the entry represents definitive failure for this snapshot. */
export function isFailed(entry: LedgerEntry): boolean {
  return entry.state === 'FAILED';
}

/** Returns true if the entry has stale (outdated) evidence. */
export function isStale(entry: LedgerEntry): boolean {
  return entry.state === 'STALE';
}

/** Returns true if the command has never been run for this snapshot. */
export function isNotRun(entry: LedgerEntry): boolean {
  return entry.state === 'NOT_RUN';
}

/** Returns true if a disk conflict blocks the check. */
export function isConflict(entry: LedgerEntry): boolean {
  return entry.state === 'CONFLICT';
}

/** Returns the FreshnessState of an entry. */
export function getFreshnessState(entry: LedgerEntry): FreshnessState {
  return entry.state;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function assertIdentityFields(
  currentSnapshot: SnapshotFingerprint,
  currentContextFingerprint: string,
  result: ValidationRunResult,
): void {
  if (typeof currentSnapshot !== 'string' || currentSnapshot.length === 0) {
    throw new ValidationLedgerError('missing_snapshot_fingerprint');
  }
  if (typeof currentContextFingerprint !== 'string' || currentContextFingerprint.length === 0) {
    throw new ValidationLedgerError('missing_context_fingerprint');
  }
  if (typeof result !== 'object' || result === null) {
    throw new ValidationLedgerError('missing_run_result');
  }
  if (typeof result.snapshotFingerprint !== 'string' || result.snapshotFingerprint.length === 0) {
    throw new ValidationLedgerError('missing_snapshot_fingerprint');
  }
  if (typeof result.contextFingerprint !== 'string' || result.contextFingerprint.length === 0) {
    throw new ValidationLedgerError('missing_context_fingerprint');
  }
}

function deriveStaleReason(
  result: ValidationRunResult,
  currentSnapshot: SnapshotFingerprint,
  currentContextFingerprint: string,
): StaleReason {
  if (result.snapshotFingerprint !== currentSnapshot) {
    return 'staged_content_changed';
  }
  if (result.contextFingerprint !== currentContextFingerprint) {
    return 'command_changed';
  }
  return 'staged_content_changed';
}

