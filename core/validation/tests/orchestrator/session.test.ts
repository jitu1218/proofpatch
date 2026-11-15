import assert from 'node:assert/strict';
import { access, rm } from 'node:fs/promises';
import { test } from 'node:test';

import {
  formatValidationReport,
  LedgerStore,
  buildSnapshotManifest,
  ValidationSession,
  type StagedSnapshot,
  type StagedSnapshotSource,
} from '../../src/index.js';
import { dirFingerprint, makeRealWorkspace, nodeCommand, readDir, sessionOptions } from '../_helpers.js';

const snap = (content: string): StagedSnapshot => ({ files: [{ path: 'a.txt', content }] });
const pass = nodeCommand('process.exit(0)');

test('passing check gives FRESH with run evidence and lists unrun security checks', async () => {
  const session = new ValidationSession(sessionOptions());
  const outcome = await session.validate(snap('1'), [{ command: pass }]);
  assert.equal(outcome.report.overall, 'FRESH');
  assert.equal(outcome.runs.length, 1);
  assert.equal(outcome.runs[0]!.snapshotFingerprint, outcome.report.snapshotFingerprint);
  assert.ok(outcome.report.checksNotRun.some((c) => c.kind === 'security' && c.reason === 'not_requested'));
  assert.match(formatValidationReport(outcome.report), /Checks NOT run:/);
});

test('failed, timed-out and missing-executable checks are never FRESH', async () => {
  for (const command of [
    nodeCommand('process.exit(3)'),
    nodeCommand('setInterval(()=>{},1000)', { timeoutMs: 300 }),
    nodeCommand('', { executable: '/definitely/not/here/tool' }),
  ]) {
    const outcome = await new ValidationSession(sessionOptions()).validate(snap('1'), [{ command }]);
    assert.equal(outcome.report.overall, 'FAILED');
  }
});

test('changed snapshot makes old evidence STALE, revalidation restores FRESH', async () => {
  const session = new ValidationSession(sessionOptions());
  const first = await session.validate(snap('1'), [{ command: pass }]);
  assert.equal(first.report.overall, 'FRESH');
  const fpB = buildSnapshotManifest(snap('2').files).fingerprint;
  const view = session.store.entriesFor(fpB);
  assert.equal(view.length, 1);
  assert.equal(view[0]!.state, 'STALE');
  const second = await session.validate(snap('2'), [{ command: pass }]);
  assert.equal(second.report.overall, 'FRESH');
  assert.equal(second.report.snapshotFingerprint, fpB);
});

test('a failed revalidation after a FRESH run is FAILED, not FRESH', async () => {
  const session = new ValidationSession(sessionOptions());
  await session.validate(snap('1'), [{ command: pass }]);
  const bad = await session.validate(snap('2'), [{ command: pass }, { command: nodeCommand('process.exit(1)', { kind: 'lint' }) }]);
  assert.equal(bad.report.overall, 'FAILED');
});

test('changing only the timeout re-runs under the new context and ends FRESH', async () => {
  const session = new ValidationSession(sessionOptions());
  await session.validate(snap('1'), [{ command: pass }]);
  const changed = nodeCommand('process.exit(0)', { timeoutMs: 20_000 });
  const outcome = await session.validate(snap('1'), [{ command: changed }]);
  assert.equal(outcome.report.overall, 'FRESH');
});

test('cancellation mid-run: no FRESH, later checks not run, temp snapshot deleted', async () => {
  const session = new ValidationSession(sessionOptions());
  const controller = new AbortController();
  const slow = nodeCommand('console.log(process.cwd()); setInterval(()=>{},1000)', { timeoutMs: 20_000 });
  setTimeout(() => controller.abort(), 500);
  const outcome = await session.validate(snap('1'), [{ command: slow }, { command: nodeCommand('process.exit(0)', { kind: 'lint' }) }], {
    signal: controller.signal,
  });
  assert.equal(outcome.runs[0]!.status, 'cancelled');
  assert.notEqual(outcome.report.overall, 'FRESH');
  assert.ok(outcome.report.checksNotRun.some((c) => c.kind === 'lint' && c.reason === 'cancelled_before_start'));
  const cwd = outcome.runs[0]!.outputSummary.stdoutTail.trim();
  assert.ok(cwd.length > 0);
  await assert.rejects(access(cwd));
});

test('active disk conflict blocks validation and reports CONFLICT', async () => {
  const session = new ValidationSession(sessionOptions());
  session.reportConflict({ conflictingPaths: ['a.txt'] });
  const outcome = await session.validate(snap('1'), [{ command: pass }]);
  assert.equal(outcome.report.overall, 'CONFLICT');
  assert.equal(outcome.runs.length, 0);
  assert.ok(outcome.report.checksNotRun.every((c) => c.reason === 'blocked_by_conflict'));
  session.clearConflict();
  assert.equal((await session.validate(snap('1'), [{ command: pass }])).report.overall, 'FRESH');
});

test('snapshot moving during validation yields STALE and skips remaining checks', async () => {
  let calls = 0;
  const source: StagedSnapshotSource = {
    getStagedSnapshot: async () => snap(++calls <= 2 ? 'A' : 'B'),
  };
  const session = new ValidationSession(sessionOptions());
  const outcome = await session.validate(source, [{ command: pass }, { command: nodeCommand('process.exit(0)', { kind: 'lint' }) }]);
  assert.equal(outcome.report.overall, 'STALE');
  assert.equal(outcome.report.snapshotFingerprint, buildSnapshotManifest(snap('B').files).fingerprint);
  assert.ok(outcome.report.checksNotRun.some((c) => c.reason === 'snapshot_changed_during_validation'));
});

test('ledger store passed in keeps history across sessions', async () => {
  const store = new LedgerStore();
  await new ValidationSession({ ...sessionOptions(), store }).validate(snap('1'), [{ command: pass }]);
  assert.equal(store.ids().length, 1);
});

test('secret scan results are reported with redaction and do not fake a pass', async () => {
  const secret = 'ghp_123456789012345678901234567890';
  const outcome = await new ValidationSession(sessionOptions()).validate(snap(`token = "${secret}"`), [{ command: pass }], {
    security: { secrets: true },
  });
  assert.equal(outcome.security.secrets?.status, 'failed');
  assert.ok(!JSON.stringify(outcome).includes(secret));
});

test('real workspace is never modified or used as cwd (pass, fail, cancel, snapshot-write)', async () => {
  const real = await makeRealWorkspace({ 'a.txt': 'hello', 'src/b.txt': 'world' });
  try {
    const before = await dirFingerprint(real);
    const staged: StagedSnapshot = { files: await readDir(real) };
    const session = new ValidationSession(sessionOptions());

    const printCwd = nodeCommand('console.log(process.cwd())');
    const passed = await session.validate(staged, [{ command: printCwd }]);
    assert.equal(passed.report.overall, 'FRESH');
    assert.notEqual(passed.runs[0]!.outputSummary.stdoutTail.trim(), real);

    await session.validate(staged, [{ command: nodeCommand('process.exit(1)') }]);
    const writer = await session.validate(staged, [{ command: nodeCommand("require('fs').writeFileSync('polluted.txt','x')") }]);
    assert.notEqual(writer.report.overall, 'FRESH');

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 300);
    await session.validate(staged, [{ command: nodeCommand('setInterval(()=>{},1000)', { timeoutMs: 20_000 }) }], { signal: controller.signal });

    assert.equal(await dirFingerprint(real), before);
    await assert.rejects(access(`${real}/polluted.txt`));
  } finally {
    await rm(real, { recursive: true, force: true });
  }
});
