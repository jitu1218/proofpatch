/**
 * Phase 3 — Validation Freshness Ledger and Aggregation tests.
 *
 * Tests for:
 *  - recordResult transitions (FRESH, FAILED, STALE, NOT_RUN)
 *  - staleEntry transitions
 *  - makeConflictEntry / makeNotRunEntry constructors
 *  - aggregateValidationResults counts and overall state
 *  - Deterministic aggregation
 *  - Security and correctness edge cases
 *
 * No flaky timing, no network, no filesystem — pure logic tests.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  aggregateValidationResults,
  getFreshnessState,
  isConflict,
  isFailed,
  isFresh,
  isNotRun,
  isStale,
  makeConflictEntry,
  makeLedgerRecord,
  makeNotRunEntry,
  recordResult,
  staleEntry,
  ValidationLedgerError,
  type AggregationResult,
} from '../../src/index.js';

import type {
  CancelledRunResult,
  DiskConflictReport,
  FailedRunResult,
  LedgerEntry,
  PassedRunResult,
  SnapshotChangedRunResult,
  SpawnErrorRunResult,
  TimedOutRunResult,
  ValidationRunResult,
} from '../../src/index.js';

// ---------------------------------------------------------------------------
// Test fixture factories — no randomness, fully deterministic identities
// ---------------------------------------------------------------------------

const SNAP_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SNAP_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const CTX_1 = 'hmac-sha256:1111111111111111111111111111111111111111111111111111111111111111';
const CTX_2 = 'hmac-sha256:2222222222222222222222222222222222222222222222222222222222222222';

const baseFields = {
  runId: 'run-001',
  contextFingerprint: CTX_1,
  command: {
    kind: 'test' as const,
    executable: 'node',
    args: ['--test'],
    timeoutMs: 5000,
    envKeys: [],
  },
  outputSummary: {
    stdoutTail: '',
    stderrTail: '',
    stdoutTruncated: false,
    stderrTruncated: false,
    redactionApplied: false,
  },
  durationMs: 100,
  startedAt: '2026-11-12T10:00:00.000Z',
  finishedAt: '2026-11-12T10:00:00.100Z',
};

function passedResult(
  snapFingerprint = SNAP_A,
  ctxFingerprint = CTX_1,
  overrides: Partial<typeof baseFields> = {},
): PassedRunResult {
  return Object.freeze({
    ...baseFields,
    ...overrides,
    snapshotFingerprint: snapFingerprint,
    contextFingerprint: ctxFingerprint,
    status: 'passed',
    exitCode: 0 as const,
    signal: null,
  });
}

function passedResultOfKind(kind: PassedRunResult['command']['kind']): PassedRunResult {
  return Object.freeze({
    ...passedResult(),
    command: Object.freeze({ ...baseFields.command, kind }),
  });
}

function failedResult(
  snapFingerprint = SNAP_A,
  ctxFingerprint = CTX_1,
  overrides: Partial<typeof baseFields> = {},
): FailedRunResult {
  return Object.freeze({
    ...baseFields,
    ...overrides,
    snapshotFingerprint: snapFingerprint,
    contextFingerprint: ctxFingerprint,
    status: 'failed',
    exitCode: 1,
    signal: null,
  });
}

function timedOutResult(snapFingerprint = SNAP_A): TimedOutRunResult {
  return Object.freeze({
    ...baseFields,
    snapshotFingerprint: snapFingerprint,
    status: 'timed_out',
    exitCode: null,
    signal: null,
  });
}

function spawnErrorResult(snapFingerprint = SNAP_A): SpawnErrorRunResult {
  return Object.freeze({
    ...baseFields,
    snapshotFingerprint: snapFingerprint,
    status: 'spawn_error',
    exitCode: null,
    signal: null,
    errorMessage: 'Command not found',
  });
}

function cancelledResult(snapFingerprint = SNAP_A): CancelledRunResult {
  return Object.freeze({
    ...baseFields,
    snapshotFingerprint: snapFingerprint,
    status: 'cancelled',
    exitCode: null,
    signal: null,
  });
}

function snapshotChangedResult(snapFingerprint = SNAP_A): SnapshotChangedRunResult {
  return Object.freeze({
    ...baseFields,
    snapshotFingerprint: snapFingerprint,
    status: 'snapshot_changed',
    exitCode: null,
    signal: null,
    errorMessage: 'Snapshot changed during execution',
  });
}

const conflictReport: DiskConflictReport = {
  conflictingPaths: ['src/index.ts', 'lib/util.ts'],
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function assertLedgerError(fn: () => unknown, code: ValidationLedgerError['code']): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof ValidationLedgerError, `expected ValidationLedgerError, got ${String(err)}`);
    assert.equal(err.code, code);
    return true;
  });
}

// ---------------------------------------------------------------------------
// 1. Successful validation becomes FRESH
// ---------------------------------------------------------------------------

describe('recordResult — FRESH', () => {
  it('a passed result with matching snapshot and context fingerprints is FRESH', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    assert.equal(entry.state, 'FRESH');
    assert.ok(isFresh(entry));
    assert.ok(!isFailed(entry));
    assert.ok(!isStale(entry));
    assert.ok(!isNotRun(entry));
    assert.ok(!isConflict(entry));
  });

  it('FRESH entry carries the original PassedRunResult as evidence', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const entry = recordResult(result, SNAP_A, CTX_1);
    assert.equal(entry.state, 'FRESH');
    if (entry.state !== 'FRESH') return; // narrow
    assert.equal(entry.evidence.status, 'passed');
    assert.equal(entry.evidence.exitCode, 0);
    assert.equal(entry.evidence.snapshotFingerprint, SNAP_A);
    assert.equal(entry.evidence.contextFingerprint, CTX_1);
    assert.equal(entry.currentSnapshot, SNAP_A);
  });

  it('getFreshnessState returns FRESH for a FRESH entry', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    assert.equal(getFreshnessState(entry), 'FRESH');
  });
});

// ---------------------------------------------------------------------------
// 2. Failed validation remains FAILED
// ---------------------------------------------------------------------------

describe('recordResult — FAILED', () => {
  it('a failed result for the current snapshot is FAILED', () => {
    const entry = recordResult(failedResult(SNAP_A), SNAP_A, CTX_1);
    assert.equal(entry.state, 'FAILED');
    assert.ok(isFailed(entry));
    assert.ok(!isFresh(entry));
    assert.ok(!isStale(entry));
  });

  it('a timed_out result for the current snapshot is FAILED', () => {
    const entry = recordResult(timedOutResult(SNAP_A), SNAP_A, CTX_1);
    assert.equal(entry.state, 'FAILED');
  });

  it('a spawn_error result for the current snapshot is FAILED', () => {
    const entry = recordResult(spawnErrorResult(SNAP_A), SNAP_A, CTX_1);
    assert.equal(entry.state, 'FAILED');
  });

  it('FAILED entry preserves the FailingRunResult as evidence', () => {
    const result = failedResult(SNAP_A);
    const entry = recordResult(result, SNAP_A, CTX_1);
    if (entry.state !== 'FAILED') assert.fail('expected FAILED');
    assert.equal(entry.evidence.status, 'failed');
    assert.equal(entry.evidence.exitCode, 1);
    assert.equal(entry.currentSnapshot, SNAP_A);
  });
});

// ---------------------------------------------------------------------------
// 3. Snapshot changes invalidate old evidence
// ---------------------------------------------------------------------------

describe('recordResult — snapshot change makes evidence STALE', () => {
  it('a passed result for snapshot A is STALE when the current snapshot is B', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_B, CTX_1);
    assert.equal(entry.state, 'STALE');
    assert.ok(isStale(entry));
    assert.ok(!isFresh(entry));
  });

  it('a failed result for snapshot A is STALE when the current snapshot is B', () => {
    const entry = recordResult(failedResult(SNAP_A), SNAP_B, CTX_1);
    assert.equal(entry.state, 'STALE');
  });

  it('STALE entry has reason staged_content_changed when snapshots differ', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_B, CTX_1);
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'staged_content_changed');
  });

  it('STALE entry preserves historical evidence from the old snapshot', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const entry = recordResult(result, SNAP_B, CTX_1);
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.evidence.snapshotFingerprint, SNAP_A); // old evidence kept
    assert.equal(entry.currentSnapshot, SNAP_B); // current snapshot updated
  });
});

// ---------------------------------------------------------------------------
// 4. Context changes invalidate affected evidence
// ---------------------------------------------------------------------------

describe('recordResult — context change makes evidence STALE', () => {
  it('a passed result for context 1 is STALE when the current context is 2', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_2);
    assert.equal(entry.state, 'STALE');
  });

  it('STALE entry has reason command_changed when snapshot matches but context differs', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_2);
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'command_changed');
  });

  it('context change does not affect unrelated snapshots (each is independent)', () => {
    const entryA = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    const entryB = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_2);
    assert.equal(entryA.state, 'FRESH');  // same context: still fresh
    assert.equal(entryB.state, 'STALE'); // context changed: stale
  });

  it('a failed result for context 1 is STALE when the current context is 2', () => {
    const entry = recordResult(failedResult(SNAP_A, CTX_1), SNAP_A, CTX_2);
    assert.equal(entry.state, 'STALE');
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'command_changed');
    assert.equal(entry.evidence.status, 'failed');
  });

  it('a timed_out result for context 1 is STALE when the current context is 2', () => {
    const entry = recordResult(timedOutResult(SNAP_A), SNAP_A, CTX_2);
    assert.equal(entry.state, 'STALE');
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'command_changed');
    assert.equal(entry.evidence.status, 'timed_out');
  });

  it('a spawn_error result for context 1 is STALE when the current context is 2', () => {
    const entry = recordResult(spawnErrorResult(SNAP_A), SNAP_A, CTX_2);
    assert.equal(entry.state, 'STALE');
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'command_changed');
    assert.equal(entry.evidence.status, 'spawn_error');
  });

  it('a failed result is FAILED when both snapshot and context fingerprints match', () => {
    const entry = recordResult(failedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    assert.equal(entry.state, 'FAILED');
    if (entry.state !== 'FAILED') assert.fail('expected FAILED');
    assert.equal(entry.evidence.status, 'failed');
    assert.equal(entry.currentSnapshot, SNAP_A);
  });

  it('a failed result is never FAILED for a different context', () => {
    const entry = recordResult(failedResult(SNAP_A, CTX_1), SNAP_A, CTX_2);
    assert.notEqual(entry.state, 'FAILED');
    assert.equal(entry.state, 'STALE');
  });
});

// ---------------------------------------------------------------------------
// 5. Different snapshots cannot share fresh evidence
// ---------------------------------------------------------------------------

describe('snapshot isolation', () => {
  it('evidence from SNAP_A is never FRESH when current snapshot is SNAP_B', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const entryA = recordResult(result, SNAP_A, CTX_1);
    const entryB = recordResult(result, SNAP_B, CTX_1); // same result, different current snapshot
    assert.equal(entryA.state, 'FRESH');
    assert.equal(entryB.state, 'STALE');
  });

  it('two independent snapshots each require their own FRESH evidence', () => {
    const resultA = passedResult(SNAP_A, CTX_1, { runId: 'run-snap-a' });
    const resultB = passedResult(SNAP_B, CTX_1, { runId: 'run-snap-b' });
    const entryA = recordResult(resultA, SNAP_A, CTX_1);
    const entryB = recordResult(resultB, SNAP_B, CTX_1);
    // Attempting to use resultA for SNAP_B:
    const wrongEntry = recordResult(resultA, SNAP_B, CTX_1);
    assert.equal(entryA.state, 'FRESH');
    assert.equal(entryB.state, 'FRESH');
    assert.equal(wrongEntry.state, 'STALE');
  });
});

// ---------------------------------------------------------------------------
// 6. Different contexts cannot share fresh evidence
// ---------------------------------------------------------------------------

describe('context isolation', () => {
  it('evidence from CTX_1 is never FRESH when current context is CTX_2', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const freshEntry = recordResult(result, SNAP_A, CTX_1);
    const staleEntry_ = recordResult(result, SNAP_A, CTX_2);
    assert.equal(freshEntry.state, 'FRESH');
    assert.equal(staleEntry_.state, 'STALE');
  });

  it('two commands with different context fingerprints require separate evidence', () => {
    const resultCtx1 = passedResult(SNAP_A, CTX_1);
    const resultCtx2 = passedResult(SNAP_A, CTX_2);
    const entryCtx1 = recordResult(resultCtx1, SNAP_A, CTX_1);
    const entryCtx2 = recordResult(resultCtx2, SNAP_A, CTX_2);
    assert.equal(entryCtx1.state, 'FRESH');
    assert.equal(entryCtx2.state, 'FRESH');
    // Using ctx1 result for ctx2 slot:
    const wrongCtx = recordResult(resultCtx1, SNAP_A, CTX_2);
    assert.equal(wrongCtx.state, 'STALE');
  });
});

// ---------------------------------------------------------------------------
// 7. Conflicts are represented correctly
// ---------------------------------------------------------------------------

describe('makeConflictEntry', () => {
  it('creates a CONFLICT entry with the conflicting paths', () => {
    const entry = makeConflictEntry(conflictReport);
    assert.equal(entry.state, 'CONFLICT');
    assert.ok(isConflict(entry));
    assert.ok(!isFresh(entry));
  });

  it('preserves all conflicting paths', () => {
    const entry = makeConflictEntry(conflictReport);
    if (entry.state !== 'CONFLICT') assert.fail('expected CONFLICT');
    assert.deepEqual([...entry.conflictingPaths], ['src/index.ts', 'lib/util.ts']);
  });

  it('a CONFLICT entry is never treated as success', () => {
    const entry = makeConflictEntry(conflictReport);
    assert.ok(!isFresh(entry));
    assert.ok(!isFailed(entry));
    assert.ok(!isStale(entry));
    assert.ok(!isNotRun(entry));
    assert.ok(isConflict(entry));
  });

  it('CONFLICT with an empty conflicting paths list is representable', () => {
    const entry = makeConflictEntry({ conflictingPaths: [] });
    assert.equal(entry.state, 'CONFLICT');
    if (entry.state !== 'CONFLICT') return;
    assert.equal(entry.conflictingPaths.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 8. Unrun checks remain NOT_RUN
// ---------------------------------------------------------------------------

describe('makeNotRunEntry and NOT_RUN state', () => {
  it('makeNotRunEntry without a last attempt is NOT_RUN', () => {
    const entry = makeNotRunEntry(SNAP_A);
    assert.equal(entry.state, 'NOT_RUN');
    assert.ok(isNotRun(entry));
    assert.ok(!isFresh(entry));
    if (entry.state !== 'NOT_RUN') return;
    assert.equal(entry.lastAttempt, undefined);
  });

  it('makeNotRunEntry with a cancelled last attempt stores it', () => {
    const attempt = cancelledResult(SNAP_A);
    const entry = makeNotRunEntry(SNAP_A, attempt);
    assert.equal(entry.state, 'NOT_RUN');
    if (entry.state !== 'NOT_RUN') return;
    assert.ok(entry.lastAttempt !== undefined);
    assert.equal(entry.lastAttempt.status, 'cancelled');
  });

  it('makeNotRunEntry with a snapshot_changed last attempt stores it', () => {
    const attempt = snapshotChangedResult(SNAP_A);
    const entry = makeNotRunEntry(SNAP_A, attempt);
    if (entry.state !== 'NOT_RUN') assert.fail('expected NOT_RUN');
    assert.equal(entry.lastAttempt?.status, 'snapshot_changed');
  });

  it('a cancelled result becomes NOT_RUN when recorded', () => {
    const entry = recordResult(cancelledResult(SNAP_A), SNAP_A, CTX_1);
    assert.equal(entry.state, 'NOT_RUN');
    if (entry.state !== 'NOT_RUN') return;
    assert.equal(entry.lastAttempt?.status, 'cancelled');
  });

  it('a snapshot_changed result becomes NOT_RUN when recorded', () => {
    const entry = recordResult(snapshotChangedResult(SNAP_A), SNAP_A, CTX_1);
    assert.equal(entry.state, 'NOT_RUN');
    if (entry.state !== 'NOT_RUN') return;
    assert.equal(entry.lastAttempt?.status, 'snapshot_changed');
  });

  it('a cancelled result whose snapshot differs becomes STALE', () => {
    const entry = recordResult(cancelledResult(SNAP_A), SNAP_B, CTX_1);
    assert.equal(entry.state, 'STALE');
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'staged_content_changed');
    assert.equal(entry.evidence.status, 'cancelled');
    assert.equal(entry.evidence.snapshotFingerprint, SNAP_A);
    assert.equal(entry.currentSnapshot, SNAP_B);
  });

  it('a snapshot_changed result whose snapshot differs becomes STALE', () => {
    const entry = recordResult(snapshotChangedResult(SNAP_A), SNAP_B, CTX_1);
    assert.equal(entry.state, 'STALE');
    if (entry.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(entry.reason, 'staged_content_changed');
    assert.equal(entry.evidence.status, 'snapshot_changed');
    assert.equal(entry.evidence.snapshotFingerprint, SNAP_A);
    assert.equal(entry.currentSnapshot, SNAP_B);
  });

  it('makeNotRunEntry does not attach an attempt from a different snapshot', () => {
    const attempt = cancelledResult(SNAP_A);
    const entry = makeNotRunEntry(SNAP_B, attempt);
    assert.equal(entry.state, 'NOT_RUN');
    if (entry.state !== 'NOT_RUN') return;
    assert.equal(entry.lastAttempt, undefined);
  });

  it('makeNotRunEntry rejects empty snapshot identity', () => {
    assertLedgerError(() => makeNotRunEntry(''), 'missing_snapshot_fingerprint');
  });
});

// ---------------------------------------------------------------------------
// 9. Missing evidence never becomes success
// ---------------------------------------------------------------------------

describe('missing evidence never becomes success', () => {
  it('aggregating zero entries produces NOT_RUN, not FRESH', () => {
    const result = aggregateValidationResults([]);
    assert.equal(result.overall, 'NOT_RUN');
    assert.equal(result.freshCount, 0);
    assert.equal(result.totalCount, 0);
  });

  // ---------------------------------------------------------------------------
  // H2. Required check-set completeness
  // ---------------------------------------------------------------------------

  describe('aggregateValidationResults — required check completeness (H2)', () => {
    it('reports omitted required kinds and prevents FRESH', () => {
      const entries = [
        recordResult(passedResultOfKind('test'), SNAP_A, CTX_1),
      ];
      const result = aggregateValidationResults(entries, SNAP_A, ['test', 'lint', 'build']);
      assert.equal(result.overall, 'NOT_RUN');
      assert.deepEqual(result.missingRequiredKinds, ['build', 'lint']);
    });

    it('reports no missing kinds when every required kind is present and fresh', () => {
      const entries = [
        recordResult(passedResultOfKind('test'), SNAP_A, CTX_1),
        recordResult(passedResultOfKind('lint'), SNAP_A, CTX_1),
      ];
      const result = aggregateValidationResults(entries, SNAP_A, ['lint', 'test']);
      assert.equal(result.overall, 'FRESH');
      assert.deepEqual(result.missingRequiredKinds, []);
    });

    it('preserves the existing severity of a present required NOT_RUN kind', () => {
      const entries = [
        makeNotRunEntry(SNAP_A, cancelledResult(SNAP_A)),
      ];
      const result = aggregateValidationResults(entries, SNAP_A, ['test']);
      assert.equal(result.overall, 'NOT_RUN');
      assert.deepEqual(result.missingRequiredKinds, []);
      assert.equal(result.notRunCount, 1);
    });

    it('deduplicates and sorts required kinds deterministically', () => {
      const entry = recordResult(passedResultOfKind('test'), SNAP_A, CTX_1);
      const first = aggregateValidationResults([entry], SNAP_A, ['custom', 'lint', 'custom', 'build']);
      const second = aggregateValidationResults([entry], SNAP_A, ['build', 'custom', 'lint']);
      assert.deepEqual(first.missingRequiredKinds, ['build', 'custom', 'lint']);
      assert.deepEqual(first.missingRequiredKinds, second.missingRequiredKinds);
    });

    it('preserves behavior when requiredKinds is omitted', () => {
      const entries = [
        recordResult(passedResultOfKind('test'), SNAP_A, CTX_1),
      ];
      const result = aggregateValidationResults(entries, SNAP_A);
      assert.equal(result.overall, 'FRESH');
      assert.deepEqual(result.missingRequiredKinds, []);
    });
  });

  it('a NOT_RUN entry does not become FRESH when aggregated alone', () => {
    const entry = makeNotRunEntry(SNAP_A);
    const result = aggregateValidationResults([entry]);
    assert.equal(result.overall, 'NOT_RUN');
    assert.equal(result.freshCount, 0);
  });

  it('a STALE entry does not become FRESH when aggregated alone', () => {
    // Build a stale entry by passing a SNAP_A result against SNAP_B
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_B, CTX_1);
    const result = aggregateValidationResults([entry]);
    assert.equal(result.overall, 'STALE');
    assert.equal(result.freshCount, 0);
  });

  it('invalid or missing snapshot fingerprint fails safely (closed)', () => {
    assertLedgerError(
      () => recordResult(passedResult(SNAP_A, CTX_1), '', CTX_1),
      'missing_snapshot_fingerprint',
    );
  });

  it('invalid or missing context fingerprint fails safely (closed)', () => {
    assertLedgerError(
      () => recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, ''),
      'missing_context_fingerprint',
    );
  });

  it('a result with an empty snapshotFingerprint field fails safely', () => {
    const badResult = { ...passedResult(SNAP_A, CTX_1), snapshotFingerprint: '' } as ValidationRunResult;
    assertLedgerError(
      () => recordResult(badResult, SNAP_A, CTX_1),
      'missing_snapshot_fingerprint',
    );
  });

  it('a result with an empty contextFingerprint field fails safely', () => {
    const badResult = { ...passedResult(SNAP_A, CTX_1), contextFingerprint: '' } as ValidationRunResult;
    assertLedgerError(
      () => recordResult(badResult, SNAP_A, CTX_1),
      'missing_context_fingerprint',
    );
  });
});

// ---------------------------------------------------------------------------
// 10. Aggregation counts each status correctly
// ---------------------------------------------------------------------------

describe('aggregateValidationResults — counts', () => {
  it('counts FRESH, STALE, FAILED, CONFLICT, NOT_RUN independently', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),     // FRESH
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_B, CTX_1),     // STALE (snap mismatch)
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r3' }), SNAP_A, CTX_1),     // FAILED
      makeConflictEntry(conflictReport),                                               // CONFLICT
      makeNotRunEntry(SNAP_A),                                                         // NOT_RUN
    ];

    const result = aggregateValidationResults(entries, SNAP_A);
    assert.equal(result.freshCount, 1);
    assert.equal(result.staleCount, 1);
    assert.equal(result.failedCount, 1);
    assert.equal(result.conflictCount, 1);
    assert.equal(result.notRunCount, 1);
    assert.equal(result.totalCount, 5);
  });

  it('all FRESH: overall is FRESH', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_A, CTX_1),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'FRESH');
    assert.equal(result.freshCount, 2);
    assert.equal(result.checksRequiringRerun.length, 0);
  });

  it('all FAILED: overall is FAILED', () => {
    const entries: LedgerEntry[] = [
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      recordResult(timedOutResult(SNAP_A), SNAP_A, CTX_1),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'FAILED');
    assert.equal(result.failedCount, 2);
  });

  it('all NOT_RUN: overall is NOT_RUN', () => {
    const entries: LedgerEntry[] = [makeNotRunEntry(SNAP_A), makeNotRunEntry(SNAP_A)];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'NOT_RUN');
    assert.equal(result.notRunCount, 2);
  });

  it('all STALE: overall is STALE', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_B, CTX_1),
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_B, CTX_1),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'STALE');
    assert.equal(result.staleCount, 2);
  });
});

// ---------------------------------------------------------------------------
// 11. Mixed validation states produce a non-success overall result
// ---------------------------------------------------------------------------

describe('mixed validation states', () => {
  it('FRESH + FAILED = overall FAILED', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_A, CTX_1),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'FAILED');
    assert.equal(result.freshCount, 1);  // FRESH count preserved
    assert.equal(result.failedCount, 1);
  });

  it('FRESH + STALE = overall STALE', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_B, CTX_1), // stale
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'STALE');
  });

  it('FRESH + NOT_RUN = overall NOT_RUN', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      makeNotRunEntry(SNAP_A),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'NOT_RUN');
  });

  it('FRESH + CONFLICT = overall CONFLICT', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      makeConflictEntry(conflictReport),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.overall, 'CONFLICT');
  });

  it('FAILED > CONFLICT > STALE > NOT_RUN severity order is respected', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),     // FRESH
      makeNotRunEntry(SNAP_A),                                                         // NOT_RUN
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_B, CTX_1),     // STALE
      makeConflictEntry(conflictReport),                                               // CONFLICT
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r3' }), SNAP_A, CTX_1),     // FAILED
    ];
    const result = aggregateValidationResults(entries, SNAP_A);
    assert.equal(result.overall, 'FAILED'); // highest severity wins
    assert.equal(result.freshCount, 1);
    assert.equal(result.notRunCount, 1);
    assert.equal(result.staleCount, 1);
    assert.equal(result.conflictCount, 1);
    assert.equal(result.failedCount, 1);
    assert.equal(result.checksRequiringRerun.length, 4); // all non-fresh
  });

  it('checksRequiringRerun includes all non-FRESH entries', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),     // FRESH (excluded)
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_A, CTX_1),     // FAILED (included)
      makeNotRunEntry(SNAP_A),                                                         // NOT_RUN (included)
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.checksRequiringRerun.length, 2);
    assert.equal(result.freshChecks.length, 1);
  });
});

// ---------------------------------------------------------------------------
// 12. Deterministic aggregation
// ---------------------------------------------------------------------------

describe('deterministic aggregation', () => {
  it('the same entries produce the same AggregationResult regardless of insertion order', () => {
    const e1 = recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1);
    const e2 = recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_A, CTX_1);
    const e3 = makeNotRunEntry(SNAP_A);

    const result1 = aggregateValidationResults([e1, e2, e3]);
    const result2 = aggregateValidationResults([e3, e1, e2]);
    const result3 = aggregateValidationResults([e2, e3, e1]);

    for (const result of [result1, result2, result3]) {
      assert.equal(result.overall, 'FAILED');
      assert.equal(result.freshCount, 1);
      assert.equal(result.failedCount, 1);
      assert.equal(result.notRunCount, 1);
      assert.equal(result.checksRequiringRerun.length, 2);
    }

    // The sorted checksRequiringRerun list must be identical across all orderings.
    assert.deepEqual(result1.checksRequiringRerun, result2.checksRequiringRerun);
    assert.deepEqual(result2.checksRequiringRerun, result3.checksRequiringRerun);
  });

  it('sorts deterministically using raw UTF-8 byte order for case differences and non-ASCII', () => {
    // In UTF-8 bytes: 'A' (0x41) < 'Z' (0x5A) < 'a' (0x61) < 'z' (0x7A) < non-ASCII 'é' (0xC3 0xA9) < 'α' (0xCE 0xB1)
    const e1 = recordResult(failedResult(SNAP_A, CTX_1, { runId: 'run-a' }), SNAP_A, CTX_1);
    const e2 = recordResult(failedResult(SNAP_A, CTX_1, { runId: 'run-A' }), SNAP_A, CTX_1);
    const e3 = recordResult(failedResult(SNAP_A, CTX_1, { runId: 'run-é' }), SNAP_A, CTX_1);
    const e4 = recordResult(failedResult(SNAP_A, CTX_1, { runId: 'run-α' }), SNAP_A, CTX_1);

    const forward = aggregateValidationResults([e1, e2, e3, e4]);
    const reverse = aggregateValidationResults([e4, e3, e2, e1]);
    const shuffled = aggregateValidationResults([e3, e1, e4, e2]);

    assert.deepEqual(forward.checksRequiringRerun, reverse.checksRequiringRerun);
    assert.deepEqual(reverse.checksRequiringRerun, shuffled.checksRequiringRerun);

    // Verify the exact expected byte order: 'run-A' < 'run-a' < 'run-é' < 'run-α'
    const runIds = forward.checksRequiringRerun.map((c) => c.identity.runId);
    assert.deepEqual(runIds, ['run-A', 'run-a', 'run-é', 'run-α']);
  });

  it('identical inputs produce identical JSON-serializable output', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'r1' }), SNAP_A, CTX_1),
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'r2' }), SNAP_A, CTX_1),
    ];
    const r1 = aggregateValidationResults(entries);
    const r2 = aggregateValidationResults(entries);
    assert.equal(JSON.stringify(r1), JSON.stringify(r2));
  });
});

// ---------------------------------------------------------------------------
// 13. Historical results are not silently discarded
// ---------------------------------------------------------------------------

describe('historical results preserved', () => {
  it('staleEntry preserves the historical evidence from FRESH', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const freshE = recordResult(result, SNAP_A, CTX_1);
    assert.equal(freshE.state, 'FRESH');

    const staled = staleEntry(freshE, SNAP_B, 'staged_content_changed');
    assert.equal(staled.state, 'STALE');
    if (staled.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(staled.evidence.snapshotFingerprint, SNAP_A); // old snap preserved
    assert.equal(staled.currentSnapshot, SNAP_B); // updated
    assert.equal(staled.reason, 'staged_content_changed');
  });

  it('staleEntry preserves the historical evidence from FAILED', () => {
    const result = failedResult(SNAP_A);
    const failedE = recordResult(result, SNAP_A, CTX_1);
    const staled = staleEntry(failedE, SNAP_B, 'accepted_hunks_changed');
    assert.equal(staled.state, 'STALE');
    if (staled.state !== 'STALE') assert.fail('expected STALE');
    assert.equal(staled.evidence.status, 'failed');
  });

  it('staleEntry on a STALE entry updates snapshot/reason but keeps original evidence', () => {
    const result = passedResult(SNAP_A, CTX_1);
    const freshE = recordResult(result, SNAP_A, CTX_1);
    const staleE1 = staleEntry(freshE, SNAP_B, 'staged_content_changed');
    const SNAP_C = 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    const staleE2 = staleEntry(staleE1, SNAP_C, 'command_changed');
    assert.equal(staleE2.state, 'STALE');
    if (staleE2.state !== 'STALE') return;
    assert.equal(staleE2.evidence.snapshotFingerprint, SNAP_A); // original evidence unchanged
    assert.equal(staleE2.currentSnapshot, SNAP_C);
    assert.equal(staleE2.reason, 'command_changed');
  });

  it('staleEntry on NOT_RUN returns a NOT_RUN with updated snapshot', () => {
    const notRun = makeNotRunEntry(SNAP_A);
    const updated = staleEntry(notRun, SNAP_B, 'staged_content_changed');
    assert.equal(updated.state, 'NOT_RUN');
    if (updated.state !== 'NOT_RUN') return;
    assert.equal(updated.currentSnapshot, SNAP_B);
  });

  it('staleEntry rejects an empty new snapshot fingerprint', () => {
    const freshE = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    assertLedgerError(
      () => staleEntry(freshE, '', 'staged_content_changed'),
      'missing_snapshot_fingerprint',
    );
  });

  it('STALE entries appear in checksRequiringRerun (not silently dropped)', () => {
    const staleE = recordResult(passedResult(SNAP_A, CTX_1, { runId: 'old-run' }), SNAP_B, CTX_1);
    const result = aggregateValidationResults([staleE]);
    assert.equal(result.staleCount, 1);
    assert.equal(result.checksRequiringRerun.length, 1);
  });
});

// ---------------------------------------------------------------------------
// 14. Invalid / incomplete identity information fails safely
// ---------------------------------------------------------------------------

describe('invalid or incomplete identity fails closed', () => {
  it('empty current snapshot throws missing_snapshot_fingerprint', () => {
    assertLedgerError(
      () => recordResult(passedResult(SNAP_A, CTX_1), '', CTX_1),
      'missing_snapshot_fingerprint',
    );
  });

  it('empty current context fingerprint throws missing_context_fingerprint', () => {
    assertLedgerError(
      () => recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, ''),
      'missing_context_fingerprint',
    );
  });

  it('result with empty snapshotFingerprint throws missing_snapshot_fingerprint', () => {
    const bad = { ...passedResult(), snapshotFingerprint: '' };
    assertLedgerError(() => recordResult(bad, SNAP_A, CTX_1), 'missing_snapshot_fingerprint');
  });

  it('result with empty contextFingerprint throws missing_context_fingerprint', () => {
    const bad = { ...passedResult(), contextFingerprint: '' };
    assertLedgerError(() => recordResult(bad, SNAP_A, CTX_1), 'missing_context_fingerprint');
  });

  it('staleEntry with empty new snapshot throws missing_snapshot_fingerprint', () => {
    const entry = makeNotRunEntry(SNAP_A);
    assertLedgerError(
      () => staleEntry(entry, '', 'staged_content_changed'),
      'missing_snapshot_fingerprint',
    );
  });

  it('ValidationLedgerError carries the right name and code', () => {
    try {
      recordResult(passedResult(SNAP_A, CTX_1), '', CTX_1);
      assert.fail('should have thrown');
    } catch (err: unknown) {
      assert.ok(err instanceof ValidationLedgerError);
      assert.equal(err.name, 'ValidationLedgerError');
      assert.equal(err.code, 'missing_snapshot_fingerprint');
      assert.ok(err.message.includes('missing_snapshot_fingerprint'));
    }
  });
});

// ---------------------------------------------------------------------------
// 15. makeLedgerRecord wraps correctly
// ---------------------------------------------------------------------------

describe('makeLedgerRecord', () => {
  it('wraps any LedgerEntry with an ISO 8601 UTC updatedAt timestamp', () => {
    const entry = makeNotRunEntry(SNAP_A);
    const record = makeLedgerRecord(entry);
    assert.equal(record.entry, entry);
    assert.match(record.updatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it('wraps a FRESH entry', () => {
    const entry = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
    const record = makeLedgerRecord(entry);
    assert.equal(record.entry.state, 'FRESH');
  });
});

// ---------------------------------------------------------------------------
// 16. All StaleReason values can be recorded
// ---------------------------------------------------------------------------

describe('all StaleReason values', () => {
  for (const reason of ['staged_content_changed', 'accepted_hunks_changed', 'command_changed', 'validation_inputs_changed'] as const) {
    it(`staleEntry accepts reason "${reason}"`, () => {
      const freshE = recordResult(passedResult(SNAP_A, CTX_1), SNAP_A, CTX_1);
      const staled = staleEntry(freshE, SNAP_B, reason);
      assert.equal(staled.state, 'STALE');
      if (staled.state !== 'STALE') return;
      assert.equal(staled.reason, reason);
    });
  }
});

// ---------------------------------------------------------------------------
// 17. AggregationResult shape (not just counts)
// ---------------------------------------------------------------------------

describe('AggregationResult shape', () => {
  it('accepts legacy manually constructed results without missingRequiredKinds', () => {
    const legacy: AggregationResult = {
      overall: 'NOT_RUN',
      freshCount: 0,
      staleCount: 0,
      failedCount: 0,
      conflictCount: 0,
      notRunCount: 0,
      totalCount: 0,
      checksRequiringRerun: [],
      freshChecks: [],
    };
    assert.equal(legacy.missingRequiredKinds, undefined);
  });

  it('freshChecks lists only FRESH entries', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'fresh-1' }), SNAP_A, CTX_1),
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'fail-1' }), SNAP_A, CTX_1),
    ];
    const result: AggregationResult = aggregateValidationResults(entries);
    assert.equal(result.freshChecks.length, 1);
    assert.equal(result.freshChecks[0]?.state, 'FRESH');
    assert.equal(result.freshChecks[0]?.identity.kind, 'test');
    assert.equal(result.freshChecks[0]?.identity.runId, 'fresh-1');
  });

  it('checksRequiringRerun includes identity info for rerunning', () => {
    const entries: LedgerEntry[] = [
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'fail-run' }), SNAP_A, CTX_1),
    ];
    const result = aggregateValidationResults(entries);
    assert.equal(result.checksRequiringRerun.length, 1);
    assert.equal(result.checksRequiringRerun[0]?.identity.runId, 'fail-run');
    assert.equal(result.checksRequiringRerun[0]?.identity.kind, 'test');
  });

  it('CONFLICT entries appear in checksRequiringRerun with kind "unknown"', () => {
    const entries: LedgerEntry[] = [makeConflictEntry(conflictReport)];
    const result = aggregateValidationResults(entries);
    assert.equal(result.checksRequiringRerun.length, 1);
    assert.equal(result.checksRequiringRerun[0]?.identity.kind, 'unknown');
    assert.equal(result.checksRequiringRerun[0]?.state, 'CONFLICT');
  });

  it('NOT_RUN entry with a lastAttempt exposes its kind in aggregation', () => {
    const attempt = cancelledResult(SNAP_A);
    const entry = makeNotRunEntry(SNAP_A, attempt);
    const result = aggregateValidationResults([entry]);
    assert.equal(result.checksRequiringRerun[0]?.identity.kind, 'test');
  });

  it('deep-freezes nested identity objects in checksRequiringRerun and freshChecks', () => {
    const entries: LedgerEntry[] = [
      recordResult(passedResult(SNAP_A, CTX_1, { runId: 'fresh-1' }), SNAP_A, CTX_1),
      recordResult(failedResult(SNAP_A, CTX_1, { runId: 'fail-1' }), SNAP_A, CTX_1),
    ];
    const result = aggregateValidationResults(entries);

    // Verify outer result and array freezing
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.freshChecks));
    assert.ok(Object.isFrozen(result.checksRequiringRerun));

    // Verify each AggregatedCheck is frozen
    const freshCheck = result.freshChecks[0]!;
    const failedCheck = result.checksRequiringRerun[0]!;
    assert.ok(Object.isFrozen(freshCheck));
    assert.ok(Object.isFrozen(failedCheck));

    // Verify nested CheckIdentity is frozen
    assert.ok(Object.isFrozen(freshCheck.identity));
    assert.ok(Object.isFrozen(failedCheck.identity));

    // Attempting mutation in strict mode throws TypeError
    assert.throws(
      () => {
        // @ts-expect-error mutating readonly property
        freshCheck.identity.kind = 'custom';
      },
      (err: unknown) => err instanceof TypeError,
    );
    assert.throws(
      () => {
        // @ts-expect-error mutating readonly property
        failedCheck.identity.kind = 'custom';
      },
      (err: unknown) => err instanceof TypeError,
    );
    assert.equal(freshCheck.identity.kind, 'test');
    assert.equal(failedCheck.identity.kind, 'test');
  });
});

// ---------------------------------------------------------------------------
// H1. Aggregation enforces snapshot consistency
// ---------------------------------------------------------------------------

describe('aggregateValidationResults — snapshot consistency (H1)', () => {
  const freshA = (runId = 'fresh-a'): LedgerEntry =>
    recordResult(passedResult(SNAP_A, CTX_1, { runId }), SNAP_A, CTX_1);
  const freshB = (runId = 'fresh-b'): LedgerEntry =>
    recordResult(passedResult(SNAP_B, CTX_1, { runId }), SNAP_B, CTX_1);
  const failedA = (runId = 'failed-a'): LedgerEntry =>
    recordResult(failedResult(SNAP_A, CTX_1, { runId }), SNAP_A, CTX_1);
  const failedB = (runId = 'failed-b'): LedgerEntry =>
    recordResult(failedResult(SNAP_B, CTX_1, { runId }), SNAP_B, CTX_1);

  it('FRESH for snapshot A plus FRESH for snapshot B is not FRESH without an expected snapshot', () => {
    const result = aggregateValidationResults([freshA(), freshB()]);
    assert.notEqual(result.overall, 'FRESH');
    assert.equal(result.overall, 'STALE');
    assert.equal(result.freshCount, 0);
    assert.equal(result.staleCount, 2);
    assert.equal(result.freshChecks.length, 0);
    assert.equal(result.checksRequiringRerun.length, 2);
  });

  it('with an expected snapshot, only entries for that snapshot stay FRESH', () => {
    const result = aggregateValidationResults([freshA(), freshB()], SNAP_A);
    assert.equal(result.overall, 'STALE');
    assert.equal(result.freshCount, 1);
    assert.equal(result.staleCount, 1);
    assert.deepEqual(result.freshChecks.map((c) => c.identity.runId), ['fresh-a']);
    assert.deepEqual(result.checksRequiringRerun.map((c) => [c.state, c.identity.runId]), [
      ['STALE', 'fresh-b'],
    ]);
  });

  it('an expected snapshot that matches no entry never yields FRESH', () => {
    const result = aggregateValidationResults([freshA()], SNAP_B);
    assert.equal(result.overall, 'STALE');
    assert.equal(result.freshCount, 0);
  });

  it('entries that all agree are FRESH with or without a matching expected snapshot', () => {
    const entries = [freshA('r1'), freshA('r2')];
    assert.equal(aggregateValidationResults(entries).overall, 'FRESH');
    assert.equal(aggregateValidationResults(entries, SNAP_A).overall, 'FRESH');
    assert.equal(aggregateValidationResults(entries, SNAP_A).freshCount, 2);
  });

  it('a FRESH entry whose evidence is for a different snapshot is counted as STALE', () => {
    const forged: LedgerEntry = {
      state: 'FRESH',
      currentSnapshot: SNAP_B,
      evidence: passedResult(SNAP_A),
    };
    for (const result of [
      aggregateValidationResults([forged]),
      aggregateValidationResults([forged], SNAP_B),
    ]) {
      assert.equal(result.overall, 'STALE');
      assert.equal(result.freshCount, 0);
      assert.equal(result.staleCount, 1);
    }
  });

  it('a FAILED entry whose evidence is for a different snapshot is counted as STALE', () => {
    const forged: LedgerEntry = {
      state: 'FAILED',
      currentSnapshot: SNAP_B,
      evidence: failedResult(SNAP_A),
    };
    const result = aggregateValidationResults([forged]);
    assert.equal(result.overall, 'STALE');
    assert.equal(result.failedCount, 0);
    assert.equal(result.staleCount, 1);
  });

  it('a failure is never hidden when entries disagree and no snapshot is expected', () => {
    const result = aggregateValidationResults([freshB(), failedA()]);
    assert.equal(result.overall, 'FAILED');
    assert.equal(result.failedCount, 1);
    assert.equal(result.freshCount, 0);
    assert.equal(result.staleCount, 1);
  });

  it('with an expected snapshot, a FAILED entry for another snapshot is STALE, for the expected one stays FAILED', () => {
    const result = aggregateValidationResults([failedA(), failedB()], SNAP_A);
    assert.equal(result.overall, 'FAILED');
    assert.equal(result.failedCount, 1);
    assert.equal(result.staleCount, 1);
  });

  it('CONFLICT entries (no snapshot) do not count as disagreement', () => {
    const result = aggregateValidationResults([freshA(), makeConflictEntry(conflictReport)]);
    assert.equal(result.freshCount, 1);
    assert.equal(result.overall, 'CONFLICT');
  });

  it('STALE and NOT_RUN entries are not changed by consistency checks', () => {
    const stale = recordResult(passedResult(SNAP_A), SNAP_B, CTX_1);
    const notRun = makeNotRunEntry(SNAP_B);
    const result = aggregateValidationResults([stale, notRun], SNAP_A);
    assert.equal(result.staleCount, 1);
    assert.equal(result.notRunCount, 1);
    assert.equal(result.overall, 'STALE');
  });

  it('is deterministic for mixed-snapshot input regardless of order', () => {
    const entries = [freshA('r1'), freshB('r2'), failedB('r3'), makeNotRunEntry(SNAP_A)];
    const expected = JSON.stringify(aggregateValidationResults(entries));
    assert.equal(JSON.stringify(aggregateValidationResults([...entries].reverse())), expected);
    assert.equal(
      JSON.stringify(aggregateValidationResults([entries[2]!, entries[0]!, entries[3]!, entries[1]!])),
      expected,
    );
    const withExpected = JSON.stringify(aggregateValidationResults(entries, SNAP_A));
    assert.equal(JSON.stringify(aggregateValidationResults([...entries].reverse(), SNAP_A)), withExpected);
  });

  it('rejects an empty or non-string expected snapshot (fails closed)', () => {
    assertLedgerError(() => aggregateValidationResults([freshA()], ''), 'missing_snapshot_fingerprint');
    assertLedgerError(
      () => aggregateValidationResults([freshA()], 42 as unknown as string),
      'missing_snapshot_fingerprint',
    );
  });

  it('an empty collection is still NOT_RUN with or without an expected snapshot', () => {
    assert.equal(aggregateValidationResults([]).overall, 'NOT_RUN');
    assert.equal(aggregateValidationResults([], SNAP_A).overall, 'NOT_RUN');
  });
});
