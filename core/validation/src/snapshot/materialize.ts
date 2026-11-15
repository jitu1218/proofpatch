/**
 * Safe temporary materialization and verification (Phase 2, Step 5).
 *
 * This consumes only the provisional StagedSnapshot model. It therefore
 * materializes present UTF-8 text files, not deletions, renames, binaries,
 * symlinks, modes, or declared encoding/line-ending metadata.
 */
import { constants } from 'node:fs';
import {
  mkdtemp,
  mkdir,
  open,
  readdir,
  rm,
  lstat,
  realpath,
  type FileHandle,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep, resolve } from 'node:path';

import type { SnapshotManifest, StagedSnapshot } from '../types/index.js';
import { assertSafeSnapshotPath } from './canonical.js';
import { buildSnapshotManifest, sha256Hex } from './hash.js';

const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const WINDOWS_INVALID_CHARACTER = /[\u0001-\u001f<>:"|?*]/;
const TEMP_PREFIX = 'proofpatch-snapshot-';

export type MaterializationProblem =
  | 'unsafe_platform_path'
  | 'path_collision'
  | 'missing_root'
  | 'unexpected_entry'
  | 'missing_file'
  | 'modified_file'
  | 'cleanup_failed';

export class SnapshotMaterializationError extends Error {
  readonly code: MaterializationProblem;
  readonly path: string;

  constructor(code: MaterializationProblem, path: string, cause?: unknown) {
    super(`Snapshot materialization ${code} at ${JSON.stringify(path)}`, { cause });
    this.name = 'SnapshotMaterializationError';
    this.code = code;
    this.path = path;
  }
}

export interface MaterializedSnapshot {
  readonly root: string;
  readonly manifest: SnapshotManifest;
  readonly verify: () => Promise<void>;
  readonly cleanup: () => Promise<void>;
}

function platformPathKey(path: string): string {
  return path
    .split('/')
    .map((segment) => segment.replace(/[. ]+$/g, '').toLowerCase())
    .join('/');
}

function assertSafeMaterializationPath(path: string): void {
  assertSafeSnapshotPath(path);
  for (const segment of path.split('/')) {
    if (
      WINDOWS_INVALID_CHARACTER.test(segment) ||
      segment.endsWith('.') ||
      segment.endsWith(' ') ||
      WINDOWS_RESERVED_NAME.test(segment)
    ) {
      throw new SnapshotMaterializationError('unsafe_platform_path', path);
    }
  }
}

function assertNoPlatformCollisions(paths: readonly string[]): void {
  const keys = paths.map(platformPathKey).sort();
  for (let index = 0; index < keys.length; index += 1) {
    const current = keys[index]!;
    const previous = keys[index - 1];
    if (previous === current || (previous !== undefined && current.startsWith(`${previous}/`))) {
      throw new SnapshotMaterializationError('path_collision', paths[index]!);
    }
  }
}

function toSnapshotPath(path: string): string {
  return path.split(sep).join('/');
}

async function listEntries(root: string): Promise<{ files: string[]; directories: string[] }> {
  const files: string[] = [];
  const directories: string[] = [];
  if (process.platform === 'linux') {
    const rootHandle = await open(root, directoryOpenFlags());
    try {
      await visitLinux(rootHandle, '', files, directories);
    } finally {
      await rootHandle.close();
    }
    return { files, directories };
  }
  const resolvedRoot = process.platform === 'win32' ? resolve(root).toLowerCase() : '';
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      const snapshotPath = toSnapshotPath(relative(root, absolute));
      const stats = await lstat(absolute);
      if (stats.isSymbolicLink() || (!stats.isFile() && !stats.isDirectory())) {
        throw new SnapshotMaterializationError('unexpected_entry', snapshotPath);
      }
      if (process.platform === 'win32') {
        const resolvedEntry = (await realpath(absolute)).toLowerCase();
        if (resolvedEntry !== resolve(absolute).toLowerCase() ||
          (resolvedEntry !== resolvedRoot && !resolvedEntry.startsWith(`${resolvedRoot}\\`))) {
          throw new SnapshotMaterializationError('unexpected_entry', snapshotPath);
        }
      }
      if (stats.isDirectory()) {
        directories.push(snapshotPath);
        await visit(absolute);
      } else {
        files.push(snapshotPath);
      }
    }
  }
  await visit(root);
  return { files, directories };
}

/**
 * An entry that vanishes, turns into a symlink or stops being a directory
 * while we walk the tree means the private root was changed under us. That is
 * reported as a typed 'unexpected_entry' (fail closed), not a raw fs error.
 */
function traversalRace(error: unknown, snapshotPath: string): unknown {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (code === 'ENOENT' || code === 'ELOOP' || code === 'ENOTDIR') {
    return new SnapshotMaterializationError('unexpected_entry', snapshotPath, error);
  }
  return error;
}

async function visitLinux(
  directory: FileHandle,
  prefix: string,
  files: string[],
  directories: string[],
): Promise<void> {
  for (const entry of await readdir(`/proc/self/fd/${directory.fd}`, { withFileTypes: true })) {
    const childPath = `/proc/self/fd/${directory.fd}/${entry.name}`;
    const snapshotPath = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    let stats: Awaited<ReturnType<typeof lstat>>;
    try {
      stats = await lstat(childPath);
    } catch (error) {
      throw traversalRace(error, snapshotPath);
    }
    if (stats.isSymbolicLink() || (!stats.isFile() && !stats.isDirectory())) {
      throw new SnapshotMaterializationError('unexpected_entry', snapshotPath);
    }
    if (stats.isDirectory()) {
      directories.push(snapshotPath);
      let child: FileHandle;
      try {
        child = await open(childPath, directoryOpenFlags());
      } catch (error) {
        throw traversalRace(error, snapshotPath);
      }
      try {
        await visitLinux(child, snapshotPath, files, directories);
      } finally {
        await child.close();
      }
    } else {
      files.push(snapshotPath);
    }
  }
}

async function verify(root: string, manifest: SnapshotManifest): Promise<void> {
  let rootStats: Awaited<ReturnType<typeof lstat>>;
  try {
    rootStats = await lstat(root);
  } catch (error) {
    throw new SnapshotMaterializationError('missing_root', root, error);
  }
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw new SnapshotMaterializationError('missing_root', root);
  }

  const entries = await listEntries(root);
  const expectedFiles = new Map(manifest.files.map((file) => [file.path, file]));
  const expectedDirectories = new Set<string>();
  for (const path of expectedFiles.keys()) {
    let parent = dirname(path).replace(/\\/g, '/');
    while (parent !== '.' && parent !== '') {
      expectedDirectories.add(parent);
      parent = dirname(parent).replace(/\\/g, '/');
    }
  }
  for (const path of entries.directories) {
    if (!expectedDirectories.has(path)) {
      throw new SnapshotMaterializationError('unexpected_entry', path);
    }
  }
  for (const path of entries.files) {
    const expected = expectedFiles.get(path);
    if (expected === undefined) throw new SnapshotMaterializationError('unexpected_entry', path);
    const bytes = await readMaterializedFile(root, path);
    if (bytes.length !== expected.bytes || sha256Hex(bytes) !== expected.sha256) {
      throw new SnapshotMaterializationError('modified_file', path);
    }
    expectedFiles.delete(path);
  }
  const missingPath = [...expectedFiles.keys()][0];
  if (missingPath !== undefined) throw new SnapshotMaterializationError('missing_file', missingPath);
}

async function readMaterializedFile(root: string, path: string): Promise<Buffer> {
  if (process.platform === 'linux') {
    const segments = path.split('/');
    const filename = segments.pop()!;
    let directory = await open(root, directoryOpenFlags());
    try {
      for (const segment of segments) {
        const next = await open(`/proc/self/fd/${directory.fd}/${segment}`, directoryOpenFlags());
        await directory.close();
        directory = next;
      }
      const handle = await open(`/proc/self/fd/${directory.fd}/${filename}`, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const stats = await handle.stat();
        if (!stats.isFile()) throw new SnapshotMaterializationError('unexpected_entry', path);
        return await handle.readFile();
      } finally {
        await handle.close();
      }
    } finally {
      await directory.close();
    }
  }
  const filename = join(root, ...path.split('/'));
  const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(filename, flags);
    const stats = await handle.stat();
    if (!stats.isFile()) throw new SnapshotMaterializationError('unexpected_entry', path);
    return await handle.readFile();
  } finally {
    await handle?.close();
  }
}

async function removeTemporaryRoot(root: string): Promise<void> {
  try {
    await rm(root, { recursive: true, force: true });
  } catch (error) {
    throw new SnapshotMaterializationError('cleanup_failed', root, error);
  }
}

interface SafeParentDirectory {
  readonly path: string;
  readonly handle?: FileHandle;
}

function directoryOpenFlags(): number {
  return constants.O_RDONLY |
    (process.platform === 'linux' ? constants.O_DIRECTORY | constants.O_NOFOLLOW : 0);
}

async function ensureSafeParent(root: string, path: string): Promise<SafeParentDirectory> {
  const segments = path.split('/');
  segments.pop();
  let directory = root;
  let handle: FileHandle | undefined;
  try {
    if (process.platform === 'linux') handle = await open(root, directoryOpenFlags());
    for (const segment of segments) {
      const nextPath = handle === undefined
        ? join(directory, segment)
        : `/proc/self/fd/${handle.fd}/${segment}`;
      try {
        await mkdir(nextPath);
      } catch (error: unknown) {
        if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
      }
      const stats = await lstat(nextPath);
      if (stats.isSymbolicLink() || !stats.isDirectory()) {
        throw new SnapshotMaterializationError('unexpected_entry', segment);
      }
      directory = join(directory, segment);
      if (process.platform === 'linux') {
        const nextHandle = await open(nextPath, directoryOpenFlags());
        await handle?.close();
        handle = nextHandle;
      }
    }
    return handle === undefined ? { path: directory } : { path: directory, handle };
  } catch (error: unknown) {
    await handle?.close();
    throw error;
  }
}

async function writeMaterializedFile(root: string, path: string, content: string): Promise<void> {
  const parent = await ensureSafeParent(root, path);
  const filename = parent.handle === undefined
    ? join(parent.path, path.split('/').pop()!)
    : `/proc/self/fd/${parent.handle.fd}/${path.split('/').pop()!}`;
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
    (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
  let handle: FileHandle | undefined;
  try {
    handle = await open(filename, flags);
    await handle.writeFile(Buffer.from(content, 'utf8'));
  } finally {
    await handle?.close();
    await parent.handle?.close();
  }
}

/**
 * Creates a private temporary directory, writes exact UTF-8 bytes, and
 * returns explicit verification and cleanup operations. Any write failure
 * removes the partial directory before rethrowing (or reports both failures).
 */
export async function materializeSnapshot(snapshot: StagedSnapshot): Promise<MaterializedSnapshot> {
  const manifest = buildSnapshotManifest(snapshot.files);
  for (const file of manifest.files) assertSafeMaterializationPath(file.path);
  assertNoPlatformCollisions(manifest.files.map((file) => file.path));

  const root = await mkdtemp(join(tmpdir(), TEMP_PREFIX));
  try {
    for (const file of snapshot.files) {
      await writeMaterializedFile(root, file.path, file.content);
    }
    await verify(root, manifest);
  } catch (error) {
    try {
      await removeTemporaryRoot(root);
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Snapshot materialization failed and cleanup failed');
    }
    throw error;
  }

  let cleaned = false;
  const cleanup = async (): Promise<void> => {
    if (cleaned) return;
    await removeTemporaryRoot(root);
    cleaned = true;
  };
  const result: MaterializedSnapshot = {
    root,
    manifest,
    verify: () => {
      if (cleaned) return Promise.reject(new SnapshotMaterializationError('missing_root', root));
      return verify(root, manifest);
    },
    cleanup,
  };
  return Object.freeze(result);
}

export const verifyMaterializedSnapshot = (
  materialized: MaterializedSnapshot,
): Promise<void> => materialized.verify();
