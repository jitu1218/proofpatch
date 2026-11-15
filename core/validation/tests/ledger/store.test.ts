import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  LedgerStore,
  LedgerStoreError,
  checkIdOf,
  loadLedgerStore,
  parseLedgerStore,
  saveLedgerStore,
  serializeLedgerStore,
  type PassedRunResult,
} from '../../src/index.js';

const passed = (fp: string): PassedRunResult => ({
  runId: 'r1',
  snapshotFingerprint: fp,
  contextFingerprint: 'ctx',
  command: { kind: 'test', executable: '/x', args: [], timeoutMs: 1, envKeys: [] },
  outputSummary: { stdoutTail: '', stderrTail: '', stdoutTruncated: false, stderrTruncated: false, redactionApplied: false },
  durationMs: 1,
  startedAt: 't',
  finishedAt: 't',
  status: 'passed',
  exitCode: 0,
  signal: null,
});

test('checkIdOf is stable and depends on identity fields only', () => {
  const a = checkIdOf({ kind: 'test', executable: '/x', args: ['a'] });
  assert.equal(a, checkIdOf({ kind: 'test', executable: '/x', args: ['a'] }));
  assert.notEqual(a, checkIdOf({ kind: 'test', executable: '/x', args: ['b'] }));
});

test('entriesFor demotes entries from another snapshot to STALE', () => {
  const store = new LedgerStore();
  store.set('c', { state: 'FRESH', currentSnapshot: 'sha256:1', evidence: passed('sha256:1') });
  assert.equal(store.entriesFor('sha256:1')[0]!.state, 'FRESH');
  assert.equal(store.entriesFor('sha256:2')[0]!.state, 'STALE');
  store.invalidateFor('sha256:2');
  assert.equal(store.get('c')!.entry.state, 'STALE');
});

test('JSON round trip keeps entries; save/load works and missing file is empty', async () => {
  const store = new LedgerStore();
  store.set('c', { state: 'FRESH', currentSnapshot: 'sha256:1', evidence: passed('sha256:1') });
  store.reportConflict({ conflictingPaths: ['a.txt'] });
  assert.equal(serializeLedgerStore(parseLedgerStore(serializeLedgerStore(store))), serializeLedgerStore(store));

  const dir = await mkdtemp(join(tmpdir(), 'pp-ledger-'));
  try {
    const file = join(dir, 'nested', 'ledger.json');
    assert.equal((await loadLedgerStore(file)).ids().length, 0);
    await saveLedgerStore(file, store);
    const loaded = await loadLedgerStore(file);
    assert.equal(loaded.get('c')!.entry.state, 'FRESH');
    assert.equal(loaded.conflict?.state, 'CONFLICT');
    assert.deepEqual(await readdir(join(dir, 'nested')), ['ledger.json']);
    await writeFile(file, '{not json');
    await assert.rejects(loadLedgerStore(file), LedgerStoreError);
    assert.ok((await readFile(file, 'utf8')).length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('tampered files cannot create FRESH without matching passed evidence', () => {
  const base = (entry: unknown) =>
    JSON.stringify({ version: 1, records: { c: { updatedAt: 't', entry } } });
  const failedRun = { ...passed('sha256:1'), status: 'failed', exitCode: 1 };
  assert.throws(() => parseLedgerStore(base({ state: 'FRESH', currentSnapshot: 'sha256:1', evidence: failedRun })), LedgerStoreError);
  assert.throws(
    () => parseLedgerStore(base({ state: 'FRESH', currentSnapshot: 'sha256:2', evidence: passed('sha256:1') })),
    LedgerStoreError,
  );
  assert.throws(() => parseLedgerStore(base({ state: 'MAYBE' })), LedgerStoreError);
  assert.throws(() => parseLedgerStore('{"version":2,"records":{}}'), LedgerStoreError);
});
