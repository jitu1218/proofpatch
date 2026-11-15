import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { delimiter } from 'node:path';
import { test } from 'node:test';

import {
  PYTHON_ENV_ALLOWLIST,
  buildPytestCommand,
  buildPythonImportGuardCommand,
  materializeSnapshot,
  pythonSnapshotEnv,
  runValidationCommand,
  type ValidationCommand,
} from '../../src/index.js';
import { sessionOptions } from '../_helpers.js';

const python = ['/usr/bin/python3', '/usr/local/bin/python3'].find((p) => existsSync(p));
const skip = python === undefined ? 'python3 not available' : false;

async function runGuard(files: { path: string; content: string }[], command: ValidationCommand) {
  const materialized = await materializeSnapshot({ files });
  return runValidationCommand(command, materialized, sessionOptions({ environmentAllowlist: PYTHON_ENV_ALLOWLIST }));
}

test('pythonSnapshotEnv uses stable relative paths', () => {
  assert.equal(pythonSnapshotEnv({}).PYTHONPATH, '.');
  assert.equal(pythonSnapshotEnv({ sourceRoots: ['src'], cwd: 'tests' }).PYTHONPATH, '../src');
  assert.equal(pythonSnapshotEnv({ sourceRoots: ['src', '.'] }).PYTHONPATH, ['src', '.'].join(delimiter));
  assert.throws(() => pythonSnapshotEnv({ sourceRoots: ['../x'] }), RangeError);
  assert.throws(() => pythonSnapshotEnv({ sourceRoots: ['/abs'] }), RangeError);
});

test('buildPytestCommand pins the snapshot and disables cache/bytecode writes', () => {
  const command = buildPytestCommand({ python: '/usr/bin/python3', timeoutMs: 1000 });
  assert.ok(command.args.includes('no:cacheprovider'));
  assert.equal(command.env?.PYTHONDONTWRITEBYTECODE, '1');
});

test('guard passes when the package is imported from the snapshot', { skip }, async () => {
  const command = buildPythonImportGuardCommand({ python: python!, packages: ['mypkg'], timeoutMs: 20_000 });
  const result = await runGuard([{ path: 'mypkg/__init__.py', content: 'X = 1\n' }], command);
  assert.equal(result.status, 'passed', result.outputSummary.stdoutTail);
  assert.match(result.outputSummary.stdoutTail, /mypkg OK/);
});

test('guard works with a src layout and a nested cwd', { skip }, async () => {
  const command = buildPythonImportGuardCommand({
    python: python!,
    packages: ['flaskish'],
    sourceRoots: ['src'],
    cwd: 'tests',
    timeoutMs: 20_000,
  });
  const result = await runGuard(
    [
      { path: 'src/flaskish/__init__.py', content: '' },
      { path: 'tests/test_x.py', content: '' },
    ],
    command,
  );
  assert.equal(result.status, 'passed', result.outputSummary.stdoutTail);
});

test('guard fails when the package is NOT in the snapshot (outside copy imported)', { skip }, async () => {
  // `json` exists only in the interpreter's own library, like a global install.
  const command = buildPythonImportGuardCommand({ python: python!, packages: ['json'], timeoutMs: 20_000 });
  const result = await runGuard([{ path: 'README.md', content: 'x' }], command);
  assert.equal(result.status, 'failed');
  assert.equal(result.exitCode, 3);
  assert.match(result.outputSummary.stdoutTail, /OUTSIDE THE SNAPSHOT/);
});

test('guard fails when the package cannot be imported at all', { skip }, async () => {
  const command = buildPythonImportGuardCommand({ python: python!, packages: ['nope_missing_pkg'], timeoutMs: 20_000 });
  const result = await runGuard([{ path: 'README.md', content: 'x' }], command);
  assert.equal(result.status, 'failed');
  assert.equal(result.exitCode, 4);
});

test('guard rejects invalid package names', () => {
  assert.throws(() => buildPythonImportGuardCommand({ python: '/p', packages: ['a;b'], timeoutMs: 1 }), RangeError);
});
