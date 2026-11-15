import assert from 'node:assert/strict';
import { access, mkdir, readFile, readlink, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, it } from 'node:test';

import {
  materializeSnapshot,
  SnapshotMaterializationError,
  type StagedSnapshot,
} from '../../src/index.js';

const snapshot = (files: StagedSnapshot['files']): StagedSnapshot => ({ files });

describe('materializeSnapshot', () => {
  it('writes exact UTF-8 bytes and verifies the manifest', async () => {
    const materialized = await materializeSnapshot(
      snapshot([
        { path: 'src/app.txt', content: 'café\r\n' },
        { path: 'empty', content: '' },
      ]),
    );
    try {
      assert.equal(await readFile(join(materialized.root, 'src', 'app.txt'), 'utf8'), 'café\r\n');
      await assert.doesNotReject(materialized.verify());
    } finally {
      await materialized.cleanup();
    }
    await assert.rejects(materialized.verify(), { code: 'missing_root' });
  });

  it('rejects Windows-unsafe names and platform collisions before writing', async () => {
    for (const path of ['CON.txt', 'folder/name. ', 'folder/name:']) {
      await assert.rejects(
        materializeSnapshot(snapshot([{ path, content: 'x' }])),
        SnapshotMaterializationError,
      );
    }
    await assert.rejects(
      materializeSnapshot(snapshot([{ path: 'README', content: 'x' }, { path: 'readme/file', content: 'y' }])),
      { code: 'path_collision' },
    );
  });

  it('rejects traversal and absolute paths without creating a directory', async () => {
    for (const path of ['../escape', '/absolute', 'C:/absolute', 'a\\b']) {
      await assert.rejects(
        materializeSnapshot(snapshot([{ path, content: 'x' }])),
        (error: unknown) => error instanceof Error,
      );
    }
  });

  it('detects modified, missing, and unexpected entries', async () => {
    const modified = await materializeSnapshot(snapshot([{ path: 'a.txt', content: 'one' }]));
    try {
      await writeFile(join(modified.root, 'a.txt'), 'two');
      await assert.rejects(modified.verify(), { code: 'modified_file' });
    } finally {
      await modified.cleanup();
    }

    const missing = await materializeSnapshot(snapshot([{ path: 'a.txt', content: 'one' }]));
    try {
      await rm(join(missing.root, 'a.txt'));
      await assert.rejects(missing.verify(), { code: 'missing_file' });
    } finally {
      await missing.cleanup();
    }

    const unexpected = await materializeSnapshot(snapshot([{ path: 'a.txt', content: 'one' }]));
    try {
      await writeFile(join(unexpected.root, 'extra.txt'), 'extra');
      await assert.rejects(unexpected.verify(), { code: 'unexpected_entry' });
    } finally {
      await unexpected.cleanup();
    }
  });

  it('detects unexpected directories and cleanup is idempotent', async () => {
    const materialized = await materializeSnapshot(snapshot([{ path: 'a.txt', content: 'one' }]));
    await mkdir(join(materialized.root, 'extra'));
    await assert.rejects(materialized.verify(), { code: 'unexpected_entry' });
    await materialized.cleanup();
    await materialized.cleanup();
    await assert.rejects(access(materialized.root));
  });

  it('rejects a replaced parent symlink without modifying its outside target', async () => {
    if (process.platform === 'win32') return;
    const outside = join(tmpdir(), `proofpatch-outside-${Date.now()}`);
    const materialized = await materializeSnapshot(snapshot([{ path: 'nested/file.txt', content: 'one' }]));
    try {
      await rm(join(materialized.root, 'nested'), { recursive: true });
      await writeFile(join(outside), 'outside');
      await symlink(tmpdir(), join(materialized.root, 'nested'));
      // The racer may be caught mid-swap (directory gone) or after the symlink
      // exists. Either way verification must fail closed with a typed error.
      await assert.rejects(
        materialized.verify(),
        (error: unknown) =>
          error instanceof SnapshotMaterializationError &&
          ['unexpected_entry', 'missing_file', 'modified_file'].includes(error.code),
      );
      assert.equal(await readFile(outside, 'utf8'), 'outside');
      assert.equal(await readlink(join(materialized.root, 'nested')), tmpdir());
    } finally {
      await rm(outside, { force: true });
      await materialized.cleanup();
    }
  });

  it('rejects a replaced Windows junction without modifying its outside target', async () => {
    if (process.platform !== 'win32') return;
    const outside = join(tmpdir(), `proofpatch-junction-outside-${Date.now()}`);
    const materialized = await materializeSnapshot(snapshot([{ path: 'nested/file.txt', content: 'one' }]));
    try {
      await mkdir(outside);
      await writeFile(join(outside, 'sentinel.txt'), 'outside');
      await rm(join(materialized.root, 'nested'), { recursive: true });
      try {
        await symlink(outside, join(materialized.root, 'nested'), 'junction');
      } catch {
        return;
      }
      // The racer may be caught mid-swap (directory gone) or after the symlink
      // exists. Either way verification must fail closed with a typed error.
      await assert.rejects(
        materialized.verify(),
        (error: unknown) =>
          error instanceof SnapshotMaterializationError &&
          ['unexpected_entry', 'missing_file', 'modified_file'].includes(error.code),
      );
      assert.equal(await readFile(join(outside, 'sentinel.txt'), 'utf8'), 'outside');
    } finally {
      await rm(outside, { recursive: true, force: true });
      await materialized.cleanup();
    }
  });

  it('keeps concurrent POSIX parent replacement from writing outside the root', async () => {
    if (process.platform !== 'linux') return;
    const outside = join(tmpdir(), `proofpatch-concurrent-outside-${Date.now()}`);
    const files = Array.from({ length: 32 }, (_, index) => ({
      path: `nested/file-${index}.txt`,
      content: 'x'.repeat(1024 * 1024),
    }));
    const existingRoots = new Set(await readdir(tmpdir()));
    let swaps = 0;
    const racer = setInterval(async () => {
      const roots = (await readdir(tmpdir())).filter(
        (entry) => entry.startsWith('proofpatch-snapshot-') && !existingRoots.has(entry),
      );
      for (const rootName of roots) {
        const nested = join(tmpdir(), rootName, 'nested');
        try {
          await rm(nested, { recursive: true });
          await symlink(outside, nested);
          swaps += 1;
        } catch {
          // The materializer may have completed or cleaned up this root.
        }
      }
    }, 1);
    try {
      await mkdir(outside);
      await writeFile(join(outside, 'sentinel.txt'), 'outside');
      try {
        const materialized = await materializeSnapshot(snapshot(files));
        await materialized.cleanup();
      } catch {
        // A concurrent replacement may legitimately make materialization fail closed.
      }
      assert.equal(await readFile(join(outside, 'sentinel.txt'), 'utf8'), 'outside');
      assert.deepEqual(await readdir(outside), ['sentinel.txt']);
      assert.ok(swaps > 0, 'the concurrent replacement did not run');
    } finally {
      clearInterval(racer);
      await rm(outside, { recursive: true, force: true });
    }
  });

  it('rejects concurrent POSIX parent replacement during verification', async () => {
    if (process.platform !== 'linux') return;
    const outside = join(tmpdir(), `proofpatch-verify-outside-${Date.now()}`);
    const materialized = await materializeSnapshot(
      snapshot([{ path: 'nested/file.txt', content: 'x'.repeat(1024 * 1024) }]),
    );
    await mkdir(outside);
    await writeFile(join(outside, 'sentinel.txt'), 'outside');
    let swaps = 0;
    const racer = setInterval(async () => {
      try {
        await rm(join(materialized.root, 'nested'), { recursive: true });
        await symlink(outside, join(materialized.root, 'nested'));
        swaps += 1;
      } catch {
        // Verification may have completed or cleanup may have removed the root.
      }
    }, 1);
    try {
      await new Promise((resolve) => setTimeout(resolve, 10));
      // The racer may be caught mid-swap (directory gone) or after the symlink
      // exists. Either way verification must fail closed with a typed error.
      await assert.rejects(
        materialized.verify(),
        (error: unknown) =>
          error instanceof SnapshotMaterializationError &&
          ['unexpected_entry', 'missing_file', 'modified_file'].includes(error.code),
      );
      assert.equal(await readFile(join(outside, 'sentinel.txt'), 'utf8'), 'outside');
      assert.deepEqual(await readdir(outside), ['sentinel.txt']);
      assert.ok(swaps > 0, 'the concurrent replacement did not run');
    } finally {
      clearInterval(racer);
      await materialized.cleanup();
      await rm(outside, { recursive: true, force: true });
    }
  });
});
