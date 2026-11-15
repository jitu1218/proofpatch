/**
 * Deterministic validation result aggregation (Phase 3).
 *
 * Aggregates a collection of LedgerEntry values into a single overall
 * validation state for one staged snapshot.
 *
 * AGGREGATION CONTRACT:
 *
 *  1. The aggregate result is FRESH only if:
 *       - At least one FRESH entry exists, AND
 *       - No FAILED, STALE, CONFLICT, or NOT_RUN entries exist.
 *       (Any non-FRESH entry makes the overall result non-FRESH.)
 *
 *  2. The aggregate result is CONFLICT if any CONFLICT entry exists (and the
 *     result is not already blocked by a more severe state).
 *     Severity order (highest to lowest): FAILED > CONFLICT > STALE > NOT_RUN > FRESH
 *     This means: if any check FAILED, overall is FAILED; if any CONFLICT (and
 *     no failure), overall is CONFLICT; etc.
 *
 *  3. The aggregate result is FAILED if any FAILED entry exists.
 *
 *  4. The aggregate result is STALE if any STALE entry exists (and nothing
 *     worse).
 *
 *  5. The aggregate result is NOT_RUN if all entries are NOT_RUN (or the
 *     collection is empty).
 *
 *  6. Missing evidence never becomes success: an empty collection is NOT_RUN,
 *     not FRESH.
 *
 *  7. Aggregation is deterministic: the same set of entries always produces the
 *     same AggregationResult (same counts, same overall, same lists), regardless
 *     of insertion order.
 *
 *  8. Historical results are not discarded: STALE entries are counted and
 *     listed in `checksRequiringRerun`, so the caller knows which commands
 *     need re-execution.
 *
 *  9. All counts are independent: a single CONFLICT entry does not prevent
 *     FRESH entries from being counted (they are still in freshCount).
 *
 * 10. Snapshot consistency is enforced here, not assumed. Entries are plain
 *     values and can be built or combined outside `recordResult`, so:
 *       - A FRESH or FAILED entry whose evidence.snapshotFingerprint differs
 *         from its own currentSnapshot is counted as STALE.
 *       - If `expectedSnapshot` is given, a FRESH or FAILED entry whose
 *         currentSnapshot differs from it is counted as STALE.
 *       - If `expectedSnapshot` is omitted and the entries do not all agree on
 *         one currentSnapshot, no entry can be proven current, so every FRESH
 *         entry is counted as STALE (FAILED entries stay FAILED: a failure is
 *         never hidden). Callers should pass `expectedSnapshot`.
 *     Consequently the overall result is FRESH only for entries that all
 *     belong to one snapshot.
 */

import { Buffer } from 'node:buffer';

import type {
  CheckKind,
  FreshnessState,
  LedgerEntry,
  SnapshotFingerprint,
} from '../types/index.js';

import { ValidationLedgerError } from './ledger.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Identity of one check in the aggregation summary. Uses the fields already
 * present on LedgerEntry/RecordedCommand; no new identity fields are invented.
 */
export interface CheckIdentity {
  /** The kind of check (test, lint, build, typecheck, custom). */
  readonly kind: CheckKind | 'unknown';
  /**
   * Run ID from the evidence, if available. Lets the caller correlate
   * the aggregation summary back to individual run results.
   */
  readonly runId?: string;
}

/**
 * One entry in the aggregation result, pairing the state with its identity.
 */
export interface AggregatedCheck {
  readonly state: FreshnessState;
  readonly identity: CheckIdentity;
}

/**
 * Result of aggregating all LedgerEntry values for one snapshot.
 *
 * The `overall` field follows the severity order defined in the module comment.
 * Counts reflect the final entry states, not execution statuses.
 */
export interface AggregationResult {
  /** Overall freshness state for this set of checks. */
  readonly overall: FreshnessState;
  /** Number of entries that are FRESH (passed + matching identity). */
  readonly freshCount: number;
  /** Number of entries that are STALE (evidence exists but outdated). */
  readonly staleCount: number;
  /** Number of entries that are FAILED (definitive failure). */
  readonly failedCount: number;
  /** Number of entries that are CONFLICT. */
  readonly conflictCount: number;
  /** Number of entries that are NOT_RUN. */
  readonly notRunCount: number;
  /** Total number of entries aggregated. */
  readonly totalCount: number;
  /** Checks that must be re-executed before the snapshot can be FRESH. */
  readonly checksRequiringRerun: readonly AggregatedCheck[];
  /** All checks that are currently FRESH (for informational display). */
  readonly freshChecks: readonly AggregatedCheck[];
  /** Required check kinds absent from the supplied entries. */
  readonly missingRequiredKinds?: readonly CheckKind[];
}

// ---------------------------------------------------------------------------
// Identity extraction
// ---------------------------------------------------------------------------

/**
 * Extracts the check identity from a LedgerEntry. FRESH and FAILED entries
 * carry evidence with a kind and runId. STALE entries carry historical
 * evidence. NOT_RUN and CONFLICT carry no run evidence.
 */
function extractIdentity(entry: LedgerEntry): CheckIdentity {
  switch (entry.state) {
    case 'FRESH':
      return Object.freeze({ kind: entry.evidence.command.kind, runId: entry.evidence.runId });
    case 'FAILED':
      return Object.freeze({ kind: entry.evidence.command.kind, runId: entry.evidence.runId });
    case 'STALE':
      return Object.freeze({ kind: entry.evidence.command.kind, runId: entry.evidence.runId });
    case 'NOT_RUN':
      // May have a lastAttempt with a kind; use it if available.
      if (entry.lastAttempt !== undefined) {
        return Object.freeze({ kind: entry.lastAttempt.command.kind, runId: entry.lastAttempt.runId });
      }
      return Object.freeze({ kind: 'unknown' });
    case 'CONFLICT':
      return Object.freeze({ kind: 'unknown' });
  }
}

// ---------------------------------------------------------------------------
// Severity ranking (for overall state determination)
// ---------------------------------------------------------------------------

/** Higher number = higher severity. FRESH is "best" (lowest severity). */
const SEVERITY: Record<FreshnessState, number> = {
  FRESH: 0,
  NOT_RUN: 1,
  STALE: 2,
  CONFLICT: 3,
  FAILED: 4,
};

function highestSeverityState(states: readonly FreshnessState[]): FreshnessState {
  if (states.length === 0) return 'NOT_RUN';
  let result: FreshnessState = 'FRESH';
  for (const state of states) {
    if (SEVERITY[state] > SEVERITY[result]) {
      result = state;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Snapshot consistency
// ---------------------------------------------------------------------------

/** True if every snapshot-bearing entry names the same currentSnapshot. */
function snapshotsAgree(entries: readonly LedgerEntry[]): boolean {
  const seen = new Set<string>();
  for (const entry of entries) {
    // CONFLICT entries carry no snapshot fingerprint.
    if (entry.state !== 'CONFLICT') seen.add(entry.currentSnapshot);
  }
  return seen.size <= 1;
}

/**
 * The state an entry counts as in aggregation. Only FRESH and FAILED entries
 * can be demoted (to STALE); every other state is returned unchanged.
 */
function effectiveState(
  entry: LedgerEntry,
  expectedSnapshot: SnapshotFingerprint | undefined,
  entriesAgree: boolean,
): FreshnessState {
  if (entry.state !== 'FRESH' && entry.state !== 'FAILED') return entry.state;
  // Evidence must belong to the snapshot the entry claims to be current for.
  if (entry.evidence.snapshotFingerprint !== entry.currentSnapshot) return 'STALE';
  if (expectedSnapshot !== undefined) {
    return entry.currentSnapshot === expectedSnapshot ? entry.state : 'STALE';
  }
  // No expected snapshot: with disagreeing entries nothing can be proven
  // current, so FRESH is demoted. FAILED is kept so a failure is never hidden.
  if (!entriesAgree && entry.state === 'FRESH') return 'STALE';
  return entry.state;
}

// ---------------------------------------------------------------------------
// aggregateValidationResults
// ---------------------------------------------------------------------------

/**
 * Aggregates an array of LedgerEntry values into a single AggregationResult.
 *
 * The function is pure and deterministic: the same entries (regardless of
 * order) always produce the same AggregationResult. The only time-dependent
 * field in the broader system is LedgerRecord.updatedAt, which is not part
 * of aggregation.
 *
 * Empty input: returns overall NOT_RUN with all counts at zero (missing
 * evidence is never treated as success).
 *
 * `expectedSnapshot` is the snapshot the caller is aggregating for. See
 * contract item 10 for how entries that do not belong to it are counted.
 *
 * @throws ValidationLedgerError if `expectedSnapshot` is given but is not a
 *   non-empty string.
 */
export function aggregateValidationResults(
  entries: readonly LedgerEntry[],
  expectedSnapshot?: SnapshotFingerprint,
  requiredKinds?: readonly CheckKind[],
): AggregationResult {
  if (
    expectedSnapshot !== undefined &&
    (typeof expectedSnapshot !== 'string' || expectedSnapshot.length === 0)
  ) {
    throw new ValidationLedgerError('missing_snapshot_fingerprint');
  }
  const entriesAgree = snapshotsAgree(entries);
  let freshCount = 0;
  let staleCount = 0;
  let failedCount = 0;
  let conflictCount = 0;
  let notRunCount = 0;

  const checksRequiringRerun: AggregatedCheck[] = [];
  const freshChecks: AggregatedCheck[] = [];
  const allStates: FreshnessState[] = [];
  const presentKinds = new Set<CheckKind>();

  for (const entry of entries) {
    const state = effectiveState(entry, expectedSnapshot, entriesAgree);
    allStates.push(state);
    const identity = extractIdentity(entry);
    if (identity.kind !== 'unknown') presentKinds.add(identity.kind);

    switch (state) {
      case 'FRESH':
        freshCount += 1;
        freshChecks.push(Object.freeze({ state, identity }));
        break;
      case 'STALE':
        staleCount += 1;
        checksRequiringRerun.push(Object.freeze({ state, identity }));
        break;
      case 'FAILED':
        failedCount += 1;
        checksRequiringRerun.push(Object.freeze({ state, identity }));
        break;
      case 'CONFLICT':
        conflictCount += 1;
        checksRequiringRerun.push(Object.freeze({ state, identity }));
        break;
      case 'NOT_RUN':
        notRunCount += 1;
        checksRequiringRerun.push(Object.freeze({ state, identity }));
        break;
    }
  }

  const normalizedRequiredKinds = [...new Set(requiredKinds ?? [])].sort(compareBytes);
  const missingRequiredKinds = normalizedRequiredKinds.filter((kind) => !presentKinds.has(kind));

  // Overall state: the highest-severity state present.
  // Special rule: overall is FRESH only if EVERY entry is FRESH (i.e., no
  // entry has severity > 0). The severity approach naturally handles this:
  // highestSeverityState returns FRESH only when all states are FRESH.
  const highestState = highestSeverityState(allStates);
  const overall = missingRequiredKinds.length > 0 && highestState === 'FRESH'
    ? 'NOT_RUN'
    : highestState;

  // Sort checksRequiringRerun deterministically: by state severity desc, then
  // by kind asc, then by runId asc. This makes aggregation results comparable
  // across runs regardless of insertion order.
  checksRequiringRerun.sort(compareAggregatedCheck);
  freshChecks.sort(compareAggregatedCheck);

  return Object.freeze({
    overall,
    freshCount,
    staleCount,
    failedCount,
    conflictCount,
    notRunCount,
    totalCount: entries.length,
    checksRequiringRerun: Object.freeze(checksRequiringRerun),
    freshChecks: Object.freeze(freshChecks),
    missingRequiredKinds: Object.freeze(missingRequiredKinds),
  });
}

// ---------------------------------------------------------------------------
// Deterministic sort comparator
// ---------------------------------------------------------------------------

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function compareAggregatedCheck(a: AggregatedCheck, b: AggregatedCheck): number {
  // Sort by severity descending (highest first), then kind asc (UTF-8 byte order), then runId asc (UTF-8 byte order).
  const severityDiff = SEVERITY[b.state] - SEVERITY[a.state];
  if (severityDiff !== 0) return severityDiff;
  const kindDiff = compareBytes(a.identity.kind, b.identity.kind);
  if (kindDiff !== 0) return kindDiff;
  const aRunId = a.identity.runId ?? '';
  const bRunId = b.identity.runId ?? '';
  return compareBytes(aRunId, bRunId);
}

