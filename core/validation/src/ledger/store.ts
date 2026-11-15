/**
 * In-memory ledger store with optional JSON persistence.
 *
 * One record per check. The check id is derived from what the check IS
 * (kind, executable, args, cwd), not from its snapshot, so a changed
 * snapshot is visible as STALE history of the same check.
 *
 * Persisted data holds evidence only (env var names, no values, bounded and
 * redacted output). Loading validates the file strictly: a hand-edited file
 * can never create a FRESH entry that its own evidence does not back.
 */
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type {
  DiskConflictReport,
  LedgerEntry,
  LedgerRecord,
  SnapshotFingerprint,
  StaleReason,
  ValidationCommand,
} from '../types/index.js';
import { makeConflictEntry, makeLedgerRecord, staleEntry } from './ledger.js';

export const CONFLICT_KEY = '__conflict__';
const STORE_VERSION = 1;
const STATES = ['FRESH', 'STALE', 'FAILED', 'CONFLICT', 'NOT_RUN'];
const FAILING = ['failed', 'timed_out', 'spawn_error'];
const REASONS = ['staged_content_changed', 'accepted_hunks_changed', 'command_changed', 'validation_inputs_changed'];

export class LedgerStoreError extends Error {
  readonly code: 'invalid_format' | 'invalid_record';
  constructor(code: 'invalid_format' | 'invalid_record', detail: string) {
    super(`Ledger store ${code}: ${detail}`);
    this.name = 'LedgerStoreError';
    this.code = code;
  }
}

/** Stable identity of a check, independent of snapshot and timeout/env. */
export function checkIdOf(command: Pick<ValidationCommand, 'kind' | 'executable' | 'args' | 'cwd'>): string {
  const text = JSON.stringify([command.kind, command.executable, command.args, command.cwd ?? null]);
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Returns the entry as it must be shown for `snapshot`: FRESH/FAILED evidence
 * from another snapshot is demoted to STALE, never shown as current.
 */
export function entryForSnapshot(
  entry: LedgerEntry,
  snapshot: SnapshotFingerprint,
  reason: StaleReason = 'staged_content_changed',
): LedgerEntry {
  switch (entry.state) {
    case 'CONFLICT':
      return entry;
    case 'STALE':
      return entry.currentSnapshot === snapshot ? entry : staleEntry(entry, snapshot, entry.reason);
    default:
      return entry.currentSnapshot === snapshot ? entry : staleEntry(entry, snapshot, reason);
  }
}

export class LedgerStore {
  private readonly records = new Map<string, LedgerRecord>();

  get(id: string): LedgerRecord | undefined {
    return this.records.get(id);
  }

  set(id: string, entry: LedgerEntry): LedgerRecord {
    const record = makeLedgerRecord(entry);
    this.records.set(id, record);
    return record;
  }

  delete(id: string): boolean {
    return this.records.delete(id);
  }

  /** Check ids currently stored (the conflict marker excluded). */
  ids(): string[] {
    return [...this.records.keys()].filter((id) => id !== CONFLICT_KEY).sort();
  }

  /** Entries as they must be shown for `snapshot` (see entryForSnapshot). */
  entriesFor(snapshot: SnapshotFingerprint, ids?: readonly string[]): LedgerEntry[] {
    const wanted = ids ?? this.ids();
    const result: LedgerEntry[] = [];
    for (const id of wanted) {
      const record = this.records.get(id);
      if (record !== undefined) result.push(entryForSnapshot(record.entry, snapshot));
    }
    return result;
  }

  /** Demotes every stored entry that does not belong to `snapshot`. */
  invalidateFor(snapshot: SnapshotFingerprint, reason: StaleReason = 'staged_content_changed'): void {
    for (const id of this.ids()) {
      const record = this.records.get(id)!;
      const next = entryForSnapshot(record.entry, snapshot, reason);
      if (next !== record.entry) this.set(id, next);
    }
  }

  reportConflict(report: DiskConflictReport): void {
    this.set(CONFLICT_KEY, makeConflictEntry(report));
  }

  clearConflict(): void {
    this.records.delete(CONFLICT_KEY);
  }

  get conflict(): LedgerEntry | undefined {
    return this.records.get(CONFLICT_KEY)?.entry;
  }

  toJSON(): { version: number; records: Record<string, LedgerRecord> } {
    const records: Record<string, LedgerRecord> = {};
    for (const id of [...this.records.keys()].sort()) records[id] = this.records.get(id)!;
    return { version: STORE_VERSION, records };
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function validateEntry(id: string, entry: unknown): LedgerEntry {
  const bad = (why: string): never => {
    throw new LedgerStoreError('invalid_record', `${id}: ${why}`);
  };
  if (!isObject(entry) || typeof entry['state'] !== 'string' || !STATES.includes(entry['state'])) {
    return bad('unknown state');
  }
  const state = entry['state'];
  if (state === 'CONFLICT') {
    const paths = entry['conflictingPaths'];
    if (!Array.isArray(paths) || !paths.every((p) => typeof p === 'string')) return bad('conflictingPaths');
    return entry as unknown as LedgerEntry;
  }
  const current = entry['currentSnapshot'];
  if (typeof current !== 'string' || current.length === 0) return bad('currentSnapshot');
  if (state === 'NOT_RUN') return entry as unknown as LedgerEntry;

  const evidence = entry['evidence'];
  if (!isObject(evidence) || typeof evidence['status'] !== 'string') return bad('evidence');
  if (state === 'FRESH') {
    if (evidence['status'] !== 'passed' || evidence['exitCode'] !== 0) return bad('FRESH needs a passed run');
    if (evidence['snapshotFingerprint'] !== current) return bad('FRESH evidence is for another snapshot');
  } else if (state === 'FAILED') {
    if (!FAILING.includes(evidence['status'])) return bad('FAILED needs a failing run');
    if (evidence['snapshotFingerprint'] !== current) return bad('FAILED evidence is for another snapshot');
  } else if (typeof entry['reason'] !== 'string' || !REASONS.includes(entry['reason'])) {
    return bad('stale reason');
  }
  return entry as unknown as LedgerEntry;
}

export function serializeLedgerStore(store: LedgerStore): string {
  return `${JSON.stringify(store.toJSON(), null, 2)}\n`;
}

export function parseLedgerStore(text: string): LedgerStore {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new LedgerStoreError('invalid_format', 'not valid JSON');
  }
  if (!isObject(data) || data['version'] !== STORE_VERSION || !isObject(data['records'])) {
    throw new LedgerStoreError('invalid_format', 'unsupported version or shape');
  }
  const store = new LedgerStore();
  for (const [id, record] of Object.entries(data['records'])) {
    if (!isObject(record) || typeof record['updatedAt'] !== 'string') {
      throw new LedgerStoreError('invalid_record', `${id}: updatedAt`);
    }
    const entry = validateEntry(id, record['entry']);
    // Keep the stored timestamp: re-create the record without touching it.
    (store as unknown as { records: Map<string, LedgerRecord> }).records.set(
      id,
      Object.freeze({ entry, updatedAt: record['updatedAt'] }),
    );
  }
  return store;
}

/** Atomic save: write a temp file next to the target, then rename. */
export async function saveLedgerStore(path: string, store: LedgerStore): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temp, serializeLedgerStore(store), { encoding: 'utf8', mode: 0o600 });
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

/** Loads a store; a missing file is an empty store. */
export async function loadLedgerStore(path: string): Promise<LedgerStore> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new LedgerStore();
    throw error;
  }
  return parseLedgerStore(text);
}
