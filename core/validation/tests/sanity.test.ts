/**
 * Step 0 sanity test: proves the test pipeline itself works
 * (TypeScript -> .test-build/ -> `node --test`). It tests no module logic.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

test('test infrastructure runs TypeScript-compiled tests on Node 22+', () => {
  const major = Number(process.versions.node.split('.')[0]);
  assert.ok(major >= 22, `Node 22+ required, found ${process.versions.node}`);
  assert.equal(1 + 1, 2);
});
