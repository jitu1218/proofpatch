import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scanSecrets, type StagedSnapshot } from '../../src/index.js';

const snapshot = (files: StagedSnapshot['files']): StagedSnapshot => ({ files });

test('detects common credentials without exposing their values', () => {
  const secret = 'ghp_123456789012345678901234567890';
  const result = scanSecrets(
    snapshot([
      {
        path: 'config.txt',
        content: [
          `token = "${secret}"`,
          'aws = AKIA1234567890ABCDEF',
          '-----BEGIN RSA PRIVATE KEY-----',
          'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
        ].join('\n'),
      },
    ]),
  );

  assert.equal(result.status, 'failed');
  assert.ok(result.findings.length >= 4);
  assert.deepEqual(
    new Set(result.findings.map((finding) => finding.kind)),
    new Set(['generic_credential', 'github_token', 'aws_access_key', 'private_key', 'bearer_token']),
  );
  assert.ok(result.findings.every((finding) => finding.redactedMatch === '[REDACTED]'));
  assert.ok(!JSON.stringify(result).includes(secret));
});

test('does not report common credential placeholders', () => {
  const result = scanSecrets(
    snapshot([
      {
        path: 'example.env',
        content: [
          'API_KEY=changeme',
          'PASSWORD="your-secret-here"',
          'TOKEN=${TOKEN_FROM_ENV}',
        ].join('\n'),
      },
    ]),
  );

  assert.equal(result.status, 'passed');
  assert.deepEqual(result.findings, []);
});

test('secret results use the exact snapshot fingerprint', () => {
  const result = scanSecrets(snapshot([{ path: 'a.txt', content: 'safe' }]));
  assert.match(result.snapshotFingerprint, /^sha256:[0-9a-f]{64}$/u);
});
