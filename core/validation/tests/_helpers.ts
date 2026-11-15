import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildSnapshotManifest, type StagedFile, type ValidationCommand } from '../src/index.js';

export const key = Buffer.from('test-private-key');

export const sessionOptions = (extra: { environmentAllowlist?: readonly string[] } = {}) => ({
  fingerprintKeyProvider: { getFingerprintKey: () => key },
  environmentAllowlist: extra.environmentAllowlist ?? [],
});

export const nodeCommand = (script: string, overrides: Partial<ValidationCommand> = {}): ValidationCommand => ({
  kind: 'test',
  executable: process.execPath,
  args: ['-e', script],
  timeoutMs: 10_000,
  ...overrides,
});

export async function makeRealWorkspace(files: Record<string, string>): Promise<string> {
  const { mkdir, writeFile } = await import('node:fs/promises');
  const root = await mkdtemp(join(tmpdir(), 'pp-real-'));
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path);
    await mkdir(join(target, '..'), { recursive: true });
    await writeFile(target, content, 'utf8');
  }
  return root;
}

export async function readDir(root: string, prefix = ''): Promise<StagedFile[]> {
  const out: StagedFile[] = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) out.push(...(await readDir(root, rel)));
    else out.push({ path: rel, content: await readFile(join(root, rel), 'utf8') });
  }
  return out;
}

/** Fingerprint of everything under a real directory (names + contents). */
export async function dirFingerprint(root: string): Promise<string> {
  return buildSnapshotManifest(await readDir(root)).fingerprint;
}
