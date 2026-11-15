import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { materializeSnapshot, parseSemgrepJson, runSemgrepScan } from '../../src/index.js';
import { sessionOptions } from '../_helpers.js';

const files = [{ path: 'app.py', content: 'print(1)\n' }];

test('semgrep missing -> not_run, never passed, snapshot cleaned', async () => {
  const materialized = await materializeSnapshot({ files });
  const result = await runSemgrepScan(materialized, {
    ...sessionOptions(),
    resolveExecutable: async () => undefined,
  });
  assert.equal(result.status, 'not_run');
  assert.equal(result.outcome, 'not_run');
  assert.equal(result.reason, 'tool_unavailable');
  await assert.rejects(materialized.verify());
});

test('parseSemgrepJson keeps rule, path, line and redacts messages', () => {
  const secret = 'ghp_123456789012345678901234567890';
  const json = JSON.stringify({
    results: [
      {
        check_id: 'python.lang.security.eval',
        path: './app.py',
        start: { line: 3, col: 5 },
        extra: { severity: 'ERROR', message: `bad token ${secret}`, lines: `x = "${secret}"` },
      },
    ],
    errors: [],
  });
  const parsed = parseSemgrepJson(json);
  assert.ok(parsed.ok);
  assert.deepEqual(
    parsed.ok && parsed.findings.map((f) => [f.ruleId, f.path, f.line, f.column, f.severity]),
    [['python.lang.security.eval', 'app.py', 3, 5, 'ERROR']],
  );
  assert.ok(!JSON.stringify(parsed).includes(secret));
});

test('parseSemgrepJson reports unusable output explicitly', () => {
  assert.deepEqual(parseSemgrepJson('not json'), { ok: false, reason: 'unparseable_output' });
  assert.deepEqual(parseSemgrepJson('{}'), { ok: false, reason: 'unparseable_output' });
  assert.deepEqual(parseSemgrepJson('{"results":[]}', true), { ok: false, reason: 'output_truncated' });
});

test('fake semgrep: findings are parsed even though it exits non-zero', { skip: process.platform === 'win32' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pp-fake-semgrep-'));
  try {
    const script = join(dir, 'semgrep');
    const payload = { results: [{ check_id: 'rule.one', path: 'app.py', start: { line: 1, col: 1 }, extra: { severity: 'WARNING', message: 'm' } }], errors: [] };
    await writeFile(script, `#!${process.execPath}\nconsole.log(${JSON.stringify(JSON.stringify(payload))});process.exit(1);\n`);
    await chmod(script, 0o755);
    const found = await runSemgrepScan(await materializeSnapshot({ files }), {
      ...sessionOptions(),
      resolveExecutable: async () => script,
    });
    assert.equal(found.outcome, 'findings');
    assert.equal(found.findings[0]?.ruleId, 'rule.one');

    await writeFile(script, `#!${process.execPath}\nconsole.log('{"results":[],"errors":[]}');\n`);
    const clean = await runSemgrepScan(await materializeSnapshot({ files }), { ...sessionOptions(), resolveExecutable: async () => script });
    assert.equal(clean.outcome, 'clean');

    await writeFile(script, `#!${process.execPath}\nconsole.log('garbage');\n`);
    const broken = await runSemgrepScan(await materializeSnapshot({ files }), { ...sessionOptions(), resolveExecutable: async () => script });
    assert.equal(broken.outcome, 'error');
    assert.equal(broken.parseProblem, 'unparseable_output');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
