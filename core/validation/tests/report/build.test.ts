import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildValidationReport,
  formatValidationReport,
  type LedgerEntry,
  type PassedRunResult,
} from '../../src/index.js';

const FP = 'sha256:aaa';
const run = (snapshotFingerprint = FP): PassedRunResult => ({
  runId: 'r1',
  snapshotFingerprint,
  contextFingerprint: 'ctx',
  command: { kind: 'test', executable: '/x', args: [], timeoutMs: 1, envKeys: [] },
  outputSummary: { stdoutTail: '', stderrTail: '', stdoutTruncated: false, stderrTruncated: false, redactionApplied: false },
  durationMs: 5,
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:00.005Z',
  status: 'passed',
  exitCode: 0,
  signal: null,
});
const fresh = (r = run()): LedgerEntry => ({ state: 'FRESH', currentSnapshot: FP, evidence: r });

test('FRESH only with passed runs of the same snapshot', () => {
  const report = buildValidationReport({ snapshotFingerprint: FP, entries: [fresh()], runs: [run()], requiredKinds: ['test'] });
  assert.equal(report.overall, 'FRESH');
});

test('a required check that was not run blocks FRESH', () => {
  const report = buildValidationReport({
    snapshotFingerprint: FP,
    entries: [fresh()],
    runs: [run()],
    requiredKinds: ['test', 'lint'],
  });
  assert.equal(report.overall, 'NOT_RUN');
  assert.ok(report.checksNotRun.some((c) => c.kind === 'lint' && c.required));
});

test('FRESH entries that the supplied runs do not back are not reported FRESH', () => {
  assert.notEqual(buildValidationReport({ snapshotFingerprint: FP, entries: [fresh()], runs: [] }).overall, 'FRESH');
  assert.notEqual(
    buildValidationReport({ snapshotFingerprint: FP, entries: [fresh()], runs: [run('sha256:other')] }).overall,
    'FRESH',
  );
});

test('empty input is NOT_RUN and formatting separates ran from not run', () => {
  const report = buildValidationReport({ snapshotFingerprint: FP, entries: [], runs: [] });
  assert.equal(report.overall, 'NOT_RUN');
  const text = formatValidationReport(report);
  assert.match(text, /Checks run:\n  \(none\)/);
  assert.match(text, /Checks NOT run:/);
});
