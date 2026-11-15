import assert from 'node:assert/strict';
import { access, readFile, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

import {
  MAX_VALIDATION_TIMEOUT_MS,
  materializeSnapshot,
  runValidationCommand,
  ValidationContextError,
  ValidationRunnerError,
  type MaterializedSnapshot,
  type StagedSnapshot,
  type ValidationCommand,
  type ValidationRunResult,
} from '../../src/index.js';

const key = Buffer.from('runner-test-private-key');

const snapshot = (files: StagedSnapshot['files']): StagedSnapshot => ({ files });

const command = (overrides: Partial<ValidationCommand> = {}): ValidationCommand => ({
  kind: 'test',
  executable: process.execPath,
  args: ['-e', 'process.exit(0)'],
  timeoutMs: 1_000,
  ...overrides,
});

const options = (overrides: Partial<Parameters<typeof runValidationCommand>[2]> = {}) => ({
  fingerprintKeyProvider: { getFingerprintKey: () => key },
  environmentAllowlist: [],
  ...overrides,
});

function expectStatus<S extends ValidationRunResult['status']>(
  result: ValidationRunResult,
  status: S,
): Extract<ValidationRunResult, { status: S }> {
  if (result.status !== status) assert.fail(`expected ${status}, got ${result.status}`);
  return result as Extract<ValidationRunResult, { status: S }>;
}

async function run(
  commandOverrides: Partial<ValidationCommand> = {},
  files: StagedSnapshot['files'] = [],
  optionOverrides: Partial<Parameters<typeof runValidationCommand>[2]> = {},
) {
  const materialized = await materializeSnapshot(snapshot(files));
  const result = await runValidationCommand(command(commandOverrides), materialized, options(optionOverrides));
  return { materialized, result };
}

test('returns passed for a successful command and cleans the snapshot', async () => {
  const { materialized, result } = await run();
  const passed = expectStatus(result, 'passed');
  assert.equal(passed.exitCode, 0);
  await assert.rejects(access(materialized.root));
});

test('accepts the maximum supported timeout without an immediate timeout', async () => {
  const { result } = await run({ timeoutMs: MAX_VALIDATION_TIMEOUT_MS });
  expectStatus(result, 'passed');
});

test('returns failed for a non-zero exit code', async () => {
  const { materialized, result } = await run({ args: ['-e', 'process.exit(7)'] });
  const failed = expectStatus(result, 'failed');
  assert.equal(failed.exitCode, 7);
  await assert.rejects(access(materialized.root));
});

test('rejects an invalid validation command and cleans the snapshot', async () => {
  const materialized = await materializeSnapshot(snapshot([]));
  await assert.rejects(
    runValidationCommand(command({ executable: 'node' }), materialized, options()),
    (error: unknown) => error instanceof ValidationContextError && error.code === 'relative_executable',
  );
  await assert.rejects(access(materialized.root));
});

test('returns spawn_error without exposing spawn details', async () => {
  const { result } = await run({ executable: `${process.execPath}.missing-proofpatch` });
  const spawnError = expectStatus(result, 'spawn_error');
  assert.equal(spawnError.exitCode, null);
  assert.equal(spawnError.errorMessage, 'Validation command could not be started.');
});

test('returns timed_out and terminates the child', async () => {
  const { result } = await run({
    args: ['-e', 'setTimeout(() => {}, 60_000)'],
    timeoutMs: 100,
  });
  expectStatus(result, 'timed_out');
});

function treeCommand(marker: string): Partial<ValidationCommand> {
  const grandchildScript =
    `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(marker)}, "grandchild-alive"), 300);` +
    'setTimeout(() => {}, 60000)';
  const parentScript =
    `require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(grandchildScript)}], {stdio: "inherit"});` +
    'setTimeout(() => {}, 60000)';
  return { args: ['-e', parentScript], timeoutMs: 100 };
}

test('terminates spawned grandchildren on timeout without waiting for inherited pipes', async () => {
  const marker = join(tmpdir(), `proofpatch-timeout-grandchild-${randomUUID()}`);
  const started = performance.now();
  try {
    const { result } = await run(treeCommand(marker), []);
    const elapsed = performance.now() - started;
    expectStatus(result, 'timed_out');
    assert.ok(elapsed < 2_000, `timeout runner took ${elapsed}ms`);
    await new Promise((resolve) => setTimeout(resolve, 450));
    await assert.rejects(readFile(marker));
  } finally {
    await rm(marker, { force: true });
  }
});

test('returns cancelled when cancellation is requested before execution', async () => {
  const controller = new AbortController();
  controller.abort();
  const { materialized, result } = await run({}, [], { signal: controller.signal });
  expectStatus(result, 'cancelled');
  await assert.rejects(access(materialized.root));
});

test('pre-aborted cancellation does not start a parent or leave descendants', async () => {
  const marker = join(tmpdir(), `proofpatch-pre-aborted-${randomUUID()}`);
  const controller = new AbortController();
  controller.abort();
  const started = performance.now();
  try {
    const { result } = await run(treeCommand(marker), [], { signal: controller.signal });
    assert.ok(performance.now() - started < 1_000);
    expectStatus(result, 'cancelled');
    await new Promise((resolve) => setTimeout(resolve, 450));
    await assert.rejects(readFile(marker));
  } finally {
    await rm(marker, { force: true });
  }
});

test('terminates spawned grandchildren on cancellation without waiting for inherited pipes', async () => {
  const marker = join(tmpdir(), `proofpatch-cancel-grandchild-${randomUUID()}`);
  const controller = new AbortController();
  const started = performance.now();
  try {
    const promise = run(treeCommand(marker), [], { signal: controller.signal });
    setTimeout(() => controller.abort(), 50);
    const { result } = await promise;
    const elapsed = performance.now() - started;
    expectStatus(result, 'cancelled');
    assert.ok(elapsed < 2_000, `cancelled runner took ${elapsed}ms`);
    await new Promise((resolve) => setTimeout(resolve, 450));
    await assert.rejects(readFile(marker));
  } finally {
    await rm(marker, { force: true });
  }
});

test('captures bounded stdout/stderr and redacts environment values', async () => {
  const secret = 'runner-secret-value';
  const { result } = await run(
    {
      env: { SECRET: secret },
      args: ['-e', 'console.log(process.env.SECRET); console.error("x".repeat(200))'],
    },
    [],
    { environmentAllowlist: ['SECRET'], outputLimitBytes: 32 },
  );
  expectStatus(result, 'passed');
  assert.ok(!result.outputSummary.stdoutTail.includes(secret));
  assert.equal(result.outputSummary.redactionApplied, true);
  assert.ok(Buffer.byteLength(result.outputSummary.stderrTail) <= 32);
  assert.equal(result.outputSummary.stderrTruncated, true);
});

test('redacts encoded environment values without redacting unrelated output', async () => {
  const secret = 'runner-secret-value';
  const encoded = Buffer.from(secret, 'utf8').toString('base64');
  const hex = Buffer.from(secret, 'utf8').toString('hex');
  const { result } = await run(
    {
      env: { SECRET: secret },
      args: ['-e', `console.log("public ${encoded} ${hex} public")`],
    },
    [],
    { environmentAllowlist: ['SECRET'] },
  );
  expectStatus(result, 'passed');
  assert.ok(!result.outputSummary.stdoutTail.includes(encoded));
  assert.ok(!result.outputSummary.stdoutTail.includes(hex));
  assert.ok(result.outputSummary.stdoutTail.includes('public'));
  assert.equal(result.outputSummary.redactionApplied, true);
});

test('passes only explicitly allowlisted environment variables', async () => {
  const { result } = await run(
    {
      env: { ALLOWED: 'yes' },
      args: ['-e', 'process.exit(process.env.ALLOWED === "yes" && process.env.NOT_INHERITED === undefined ? 0 : 1)'],
    },
    [],
    { environmentAllowlist: ['ALLOWED'] },
  );
  expectStatus(result, 'passed');
});

test('uses the configured working directory relative to the snapshot root', async () => {
  const { result } = await run(
    { cwd: 'nested', args: ['-e', 'process.exit(process.cwd().endsWith("nested") ? 0 : 1)'] },
    [{ path: 'nested/marker.txt', content: 'marker' }],
  );
  expectStatus(result, 'passed');
});

test('fails closed when the fingerprint key is missing or invalid', async () => {
  const missing = await materializeSnapshot(snapshot([]));
  await assert.rejects(
    runValidationCommand(command(), missing, {
      fingerprintKeyProvider: { getFingerprintKey: () => { throw new Error(key.toString()); } },
      environmentAllowlist: [],
    }),
    (error: unknown) => error instanceof ValidationRunnerError && error.code === 'missing_fingerprint_key',
  );
  await assert.rejects(access(missing.root));

  const invalid = await materializeSnapshot(snapshot([]));
  await assert.rejects(
    runValidationCommand(command(), invalid, {
      fingerprintKeyProvider: { getFingerprintKey: () => new Uint8Array() },
      environmentAllowlist: [],
    }),
    (error: unknown) => error instanceof ValidationRunnerError && error.code === 'invalid_fingerprint_key',
  );
  await assert.rejects(access(invalid.root));
});

test('reuses a stable key to produce the same context fingerprint', async () => {
  const first = await run({}, [{ path: 'a.txt', content: 'same' }]);
  const second = await run({}, [{ path: 'a.txt', content: 'same' }]);
  assert.equal(first.result.contextFingerprint, second.result.contextFingerprint);
});

test('reports snapshot modification before execution', async () => {
  const original = await materializeSnapshot(snapshot([{ path: 'a.txt', content: 'one' }]));
  const tampered: MaterializedSnapshot = {
    ...original,
    verify: async () => {
      await original.cleanup();
      throw new Error('tampered');
    },
  };
  const result = await runValidationCommand(command(), tampered, options());
  expectStatus(result, 'snapshot_changed');
});

test('reports snapshot modification after execution', async () => {
  const { result } = await run(
    {
      args: ['-e', 'require("node:fs").writeFileSync("a.txt", "changed")'],
    },
    [{ path: 'a.txt', content: 'original' }],
  );
  expectStatus(result, 'snapshot_changed');
});

test('does not expose the fingerprint key in results', async () => {
  const { result } = await run({ args: ['-e', 'console.log("done")'] });
  assert.ok(!JSON.stringify(result).includes(key.toString()));
  assert.ok(!JSON.stringify(result).includes('runner-test-private-key'));
});
