/**
 * Validation report types.
 *
 * TWO DIFFERENT LEVELS OF STATUS — do not mix them up:
 *
 *  1. INDIVIDUAL CHECK STATUS (`ExecutionStatus`, see evidence.ts)
 *     How ONE command (e.g. `pytest`, `eslint`) ended:
 *     passed | failed | timed_out | spawn_error | cancelled | snapshot_changed.
 *
 *  2. OVERALL REPORT STATUS (`overall`, a `FreshnessState`)
 *     What can honestly be said about the WHOLE snapshot after all required
 *     checks are considered.
 *
 * Rule: a snapshot is reported FRESH only if every check that was run passed
 * and no REQUIRED check is missing. A required check that failed, timed out,
 * could not start, was cancelled, or was never performed means NOT fresh.
 *
 * The types enforce the shape; `buildValidationReport` (src/report/build.ts)
 * computes `overall` and checks at runtime that FRESH is backed only by passed
 * runs of the report's own snapshot.
 */
import type { CheckKind, PassedRunResult, ValidationRunResult } from './evidence.js';
import type { FreshnessState } from './ledger.js';
import type { SnapshotFingerprint } from './provisional.js';

/** Why a check was not performed. Used so reports never imply it ran. */
export type NotRunReason =
  | 'not_requested'
  | 'not_configured'
  | 'tool_unavailable'
  | 'blocked_by_conflict'
  | 'cancelled_before_start'
  | 'snapshot_changed_during_validation';

/** A check that did NOT execute for this snapshot. */
export interface NotRunCheck {
  readonly kind: CheckKind | 'security';
  readonly reason: NotRunReason;
  /** True if the overall result cannot be FRESH without this check. */
  readonly required: boolean;
  readonly detail?: string;
}

/** A not-performed check that does not block FRESH (it was optional). */
export type OptionalNotRunCheck = NotRunCheck & { readonly required: false };

/**
 * Overall FRESH report. Requires at least one run, every run 'passed', and
 * only OPTIONAL checks left unrun. Failed/cancelled/timed-out/spawn-error runs
 * or a missing required check do not type-check here.
 */
export interface FreshReport {
  readonly overall: 'FRESH';
  readonly snapshotFingerprint: SnapshotFingerprint;
  readonly checksRun: readonly [PassedRunResult, ...PassedRunResult[]];
  readonly checksNotRun: readonly OptionalNotRunCheck[];
}

/** Any overall result other than FRESH. May hold any runs and any unrun checks. */
export interface NonFreshReport {
  readonly overall: Exclude<FreshnessState, 'FRESH'>;
  readonly snapshotFingerprint: SnapshotFingerprint;
  readonly checksRun: readonly ValidationRunResult[];
  readonly checksNotRun: readonly NotRunCheck[];
}

/**
 * What was actually checked for one snapshot, and what was not.
 * `checksRun` holds real evidence only; anything absent must be in `checksNotRun`.
 */
export type ValidationReport = FreshReport | NonFreshReport;
