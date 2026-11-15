import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isAbsolute } from 'node:path';

import {
  CONTEXT_FINGERPRINT_FORMAT_VERSION,
  MAX_VALIDATION_TIMEOUT_MS,
  ValidationContextError,
  fingerprintValidationContext,
  type ValidationCommand,
} from '../../src/index.js';

const command = (overrides: Partial<ValidationCommand> = {}): ValidationCommand => ({
  kind: 'test',
  executable: process.execPath,
  args: ['--test', 'tests/a.test.js'],
  timeoutMs: 30_000,
  ...overrides,
});
const options = { environmentAllowlist: [], fingerprintKey: Buffer.from('test-only-private-key') };

describe('fingerprintValidationContext', () => {
  it('is deterministic and uses the documented prefix', () => {
    const result = fingerprintValidationContext(command(), options);
    assert.match(result, /^hmac-sha256:[0-9a-f]{64}$/);
    assert.equal(CONTEXT_FINGERPRINT_FORMAT_VERSION, 'v2');
    assert.equal(result, fingerprintValidationContext(command(), options));
  });

  it('does not depend on environment object or allowlist insertion order', () => {
    const first = fingerprintValidationContext(
      command({ env: { Z_MODE: 'fast', A_MODE: 'safe' } }),
      { environmentAllowlist: ['Z_MODE', 'A_MODE'], fingerprintKey: options.fingerprintKey },
    );
    const second = fingerprintValidationContext(
      command({ env: { A_MODE: 'safe', Z_MODE: 'fast' } }),
      { environmentAllowlist: ['A_MODE', 'Z_MODE'], fingerprintKey: options.fingerprintKey },
    );
    assert.equal(first, second);
  });

  it('distinguishes absent, empty, and changed allowlisted values', () => {
    const contextOptions = { environmentAllowlist: ['MODE'], fingerprintKey: options.fingerprintKey };
    const absent = fingerprintValidationContext(command(), contextOptions);
    const empty = fingerprintValidationContext(command({ env: { MODE: '' } }), contextOptions);
    const changed = fingerprintValidationContext(command({ env: { MODE: 'x' } }), contextOptions);
    assert.notEqual(absent, empty);
    assert.notEqual(empty, changed);
  });

  it('includes all execution fields and relative cwd', () => {
    const base = fingerprintValidationContext(command(), options);
    for (const changed of [
      command({ kind: 'lint' }),
      command({ executable: `${process.execPath}.alternate` }),
      command({ args: ['--test'] }),
      command({ cwd: 'packages/app' }),
      command({ timeoutMs: 30_001 }),
    ]) {
      assert.notEqual(base, fingerprintValidationContext(changed, options));
    }
  });

  it('rejects absolute or ambiguous working directories', () => {
    for (const cwd of ['C:\\repo', 'C:/repo', '/tmp/repo', '../repo', 'a/../b', 'a//b', 'a\\b']) {
      assert.throws(
        () => fingerprintValidationContext(command({ cwd }), options),
        (error: unknown) => error instanceof ValidationContextError,
      );
    }
    assert.doesNotThrow(() => fingerprintValidationContext(command({ cwd: '.' }), options));
  });

  it('rejects malformed command and environment values', () => {
    const cases: Array<ValidationCommand> = [
      command({ executable: '' }),
      command({ args: ['ok', '\0'] }),
      command({ timeoutMs: 0 }),
      command({ env: { SECRET: 'value' } }),
    ];
    for (const invalid of cases) {
      assert.throws(
        () => fingerprintValidationContext(invalid, options),
        ValidationContextError,
      );
    }
    assert.throws(() => fingerprintValidationContext(command({ executable: 'node' }), options), {
      code: 'relative_executable',
    });
    assert.throws(
      () => fingerprintValidationContext(
        command({ env: { MODE: 'x' } }),
        { environmentAllowlist: ['MODE', 'MODE'], fingerprintKey: options.fingerprintKey },
      ),
      { code: 'duplicate_environment_name' },
    );
    assert.throws(
      () => fingerprintValidationContext(command({ env: { MODE: 'x' } }), { environmentAllowlist: ['OTHER'], fingerprintKey: options.fingerprintKey }),
      { code: 'environment_not_allowlisted' },
    );
  });

  it('does not expose environment values in validation errors', () => {
    assert.throws(
      () => fingerprintValidationContext(command({ env: { SECRET: 'TOP-SECRET' } }), options),
      (error: unknown) => {
        assert.ok(error instanceof ValidationContextError);
        assert.ok(!error.message.includes('TOP-SECRET'));
        return true;
      },
    );
  });

  it('canonicalizes environment names and rejects case-colliding duplicates', () => {
    const path = fingerprintValidationContext(command({ env: { path: 'bin' } }), {
      environmentAllowlist: ['PATH'],
      fingerprintKey: options.fingerprintKey,
    });
    const upper = fingerprintValidationContext(command({ env: { PATH: 'bin' } }), {
      environmentAllowlist: ['path'],
      fingerprintKey: options.fingerprintKey,
    });
    assert.equal(path, upper);
    assert.throws(
      () => fingerprintValidationContext(command(), { environmentAllowlist: ['PATH', 'path'], fingerprintKey: options.fingerprintKey }),
      { code: 'duplicate_environment_name' },
    );
    assert.throws(
      () => fingerprintValidationContext(command({ env: { PATH: 'a', path: 'b' } }), {
        environmentAllowlist: ['PATH'],
        fingerprintKey: options.fingerprintKey,
      }),
      { code: 'duplicate_environment_name' },
    );
  });

  it('requires a private fingerprint key', () => {
    assert.throws(
      () => fingerprintValidationContext(command(), { environmentAllowlist: [] } as never),
      { code: 'invalid_fingerprint_key' },
    );
  });

  it('accepts the Node timer maximum and rejects larger timeouts', () => {
    assert.doesNotThrow(() =>
      fingerprintValidationContext(command({ timeoutMs: MAX_VALIDATION_TIMEOUT_MS }), options),
    );
    assert.throws(
      () => fingerprintValidationContext(command({ timeoutMs: MAX_VALIDATION_TIMEOUT_MS + 1 }), options),
      { code: 'invalid_timeout' },
    );
  });

  it('requires executable identity to be absolute and fingerprints distinct identities', () => {
    const first = fingerprintValidationContext(command({ executable: process.execPath }), options);
    const second = fingerprintValidationContext(command({ executable: `${process.execPath}.alternate` }), options);
    assert.equal(isAbsolute(process.execPath), true);
    assert.notEqual(first, second);
  });

  it('uses host-platform absolute path rules for executable paths', () => {
    assert.doesNotThrow(() => fingerprintValidationContext(command({ executable: process.execPath }), options));
    if (process.platform === 'win32') {
      assert.doesNotThrow(() =>
        fingerprintValidationContext(command({ executable: 'C:\\Windows\\System32\\node.exe' }), options),
      );
      assert.doesNotThrow(() =>
        fingerprintValidationContext(command({ executable: '\\\\server\\share\\node.exe' }), options),
      );
      assert.throws(
        () => fingerprintValidationContext(command({ executable: '\\relative.exe' }), options),
        { code: 'relative_executable' },
      );
      assert.throws(
        () => fingerprintValidationContext(command({ executable: 'C:relative\\node.exe' }), options),
        { code: 'relative_executable' },
      );
    } else {
      assert.doesNotThrow(() =>
        fingerprintValidationContext(command({ executable: '/usr/bin/node' }), options),
      );
      assert.throws(
        () => fingerprintValidationContext(command({ executable: 'C:\\absolute\\node.exe' }), options),
        { code: 'relative_executable' },
      );
      assert.throws(
        () => fingerprintValidationContext(command({ executable: '\\\\server\\share\\node' }), options),
        { code: 'relative_executable' },
      );
    }
  });
});
