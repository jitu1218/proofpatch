/**
 * Compile-time tests. Nothing here runs: `tsc` must accept every valid line and
 * REJECT every line marked @ts-expect-error. If a "forbidden" state ever becomes
 * representable, the @ts-expect-error becomes unused and tsc fails.
 *
 * Run with: npm run typecheck
 */
import type {
  CancelledRunResult,
  FailedEntry,
  FailedRunResult,
  FreshEntry,
  NotRunEntry,
  PassedRunResult,
  SnapshotChangedRunResult,
  SpawnErrorRunResult,
  StaleEntry,
  TimedOutRunResult,
  ValidationRunResult,
} from '../../src/index.js';

declare const passed: PassedRunResult;
declare const failed: FailedRunResult;
declare const timedOut: TimedOutRunResult;
declare const spawnError: SpawnErrorRunResult;
declare const cancelled: CancelledRunResult;
declare const snapshotChanged: SnapshotChangedRunResult;
declare const anyResult: ValidationRunResult;
const fp = 'fp';

// ---- FRESH accepts only a passed result -----------------------------------
export const freshOk: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: passed };
// @ts-expect-error failed result cannot be FRESH
export const freshFailed: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: failed };
// @ts-expect-error timed-out result cannot be FRESH
export const freshTimedOut: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: timedOut };
// @ts-expect-error spawn error cannot be FRESH
export const freshSpawn: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: spawnError };
// @ts-expect-error cancelled result cannot be FRESH
export const freshCancelled: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: cancelled };
// @ts-expect-error snapshot-changed result cannot be FRESH
export const freshChanged: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: snapshotChanged };
// @ts-expect-error an unnarrowed ValidationRunResult cannot be FRESH
export const freshAny: FreshEntry = { state: 'FRESH', currentSnapshot: fp, evidence: anyResult };
// @ts-expect-error FRESH requires evidence
export const freshNoEvidence: FreshEntry = { state: 'FRESH', currentSnapshot: fp };

// ---- FAILED never holds a passed result -----------------------------------
export const failedOk: FailedEntry = { state: 'FAILED', currentSnapshot: fp, evidence: failed };
export const failedTimeout: FailedEntry = { state: 'FAILED', currentSnapshot: fp, evidence: timedOut };
export const failedSpawn: FailedEntry = { state: 'FAILED', currentSnapshot: fp, evidence: spawnError };
// @ts-expect-error passed result cannot be FAILED
export const failedPassed: FailedEntry = { state: 'FAILED', currentSnapshot: fp, evidence: passed };
// @ts-expect-error cancelled is inconclusive, not FAILED
export const failedCancelled: FailedEntry = { state: 'FAILED', currentSnapshot: fp, evidence: cancelled };

// ---- NOT_RUN may only remember an inconclusive attempt ---------------------
export const notRunPlain: NotRunEntry = { state: 'NOT_RUN', currentSnapshot: fp };
export const notRunCancelled: NotRunEntry = { state: 'NOT_RUN', currentSnapshot: fp, lastAttempt: cancelled };
export const notRunChanged: NotRunEntry = { state: 'NOT_RUN', currentSnapshot: fp, lastAttempt: snapshotChanged };
// @ts-expect-error a pass is not an inconclusive attempt
export const notRunPassed: NotRunEntry = { state: 'NOT_RUN', currentSnapshot: fp, lastAttempt: passed };
// @ts-expect-error a failure is not an inconclusive attempt
export const notRunFailed: NotRunEntry = { state: 'NOT_RUN', currentSnapshot: fp, lastAttempt: failed };

// ---- STALE keeps old evidence of any status as history ---------------------
export const staleOk: StaleEntry = {
  state: 'STALE',
  currentSnapshot: fp,
  reason: 'staged_content_changed',
  evidence: passed,
};

// ---- Status-specific shape rules -------------------------------------------
// @ts-expect-error a passed result must have exitCode 0
export const passedBadExit: PassedRunResult = { ...passed, exitCode: 1 };
// @ts-expect-error a spawn error never has an exit code
export const spawnBadExit: SpawnErrorRunResult = { ...spawnError, exitCode: 0 };

// ---- Overall report: FRESH only when everything required passed ------------
import type { FreshReport, NonFreshReport, NotRunCheck } from '../../src/index.js';

declare const optionalSkipped: NotRunCheck & { readonly required: false };
declare const requiredSkipped: NotRunCheck & { readonly required: true };

export const reportFresh: FreshReport = {
  overall: 'FRESH',
  snapshotFingerprint: fp,
  checksRun: [passed],
  checksNotRun: [optionalSkipped],
};
export const reportFreshWithFail: FreshReport = {
  overall: 'FRESH',
  snapshotFingerprint: fp,
  // @ts-expect-error a failed run cannot be in a FRESH report
  checksRun: [passed, failed],
  checksNotRun: [],
};
export const reportFreshWithCancel: FreshReport = {
  overall: 'FRESH',
  snapshotFingerprint: fp,
  // @ts-expect-error a cancelled run cannot be in a FRESH report
  checksRun: [passed, cancelled],
  checksNotRun: [],
};
export const reportFreshMissingRequired: FreshReport = {
  overall: 'FRESH',
  snapshotFingerprint: fp,
  checksRun: [passed],
  // @ts-expect-error a required check that was not performed blocks FRESH
  checksNotRun: [requiredSkipped],
};
export const reportFreshNoRuns: FreshReport = {
  overall: 'FRESH',
  snapshotFingerprint: fp,
  // @ts-expect-error FRESH needs at least one executed check
  checksRun: [],
  checksNotRun: [],
};
// @ts-expect-error the 'FRESH' overall status belongs to FreshReport only
export const nonFreshAsFresh: NonFreshReport = { overall: 'FRESH', snapshotFingerprint: fp, checksRun: [], checksNotRun: [] };
export const reportFailed: NonFreshReport = {
  overall: 'FAILED',
  snapshotFingerprint: fp,
  checksRun: [passed, failed],
  checksNotRun: [requiredSkipped],
};
