/**
 * Controlled validation command runner (Phase 2, Step 6).
 *
 * A runner owns one invocation against an already-materialized snapshot. It
 * never uses a shell and never inherits process.env. The caller supplies the
 * stable HMAC key provider used by context fingerprinting.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isAbsolute, join, relative, sep } from 'node:path';

import {
  fingerprintValidationContext,
  MAX_VALIDATION_TIMEOUT_MS,
  ValidationContextError,
} from '../context/index.js';
import type {
  CancelledRunResult,
  FailedRunResult,
  OutputSummary,
  PassedRunResult,
  RecordedCommand,
  SnapshotChangedRunResult,
  SpawnErrorRunResult,
  TimedOutRunResult,
  ValidationCommand,
  ValidationRunResult,
} from '../types/index.js';
import type { MaterializedSnapshot } from '../snapshot/index.js';

const DEFAULT_OUTPUT_LIMIT_BYTES = 64 * 1024;
const PROCESS_TERMINATION_GRACE_MS = 500;
const PROCESS_TERMINATION_TIMEOUT_MS = 5_000;
const PROCESS_PID_WAIT_TIMEOUT_MS = 1_000;
const EMPTY_OUTPUT: OutputSummary = Object.freeze({
  stdoutTail: '',
  stderrTail: '',
  stdoutTruncated: false,
  stderrTruncated: false,
  redactionApplied: false,
});

export interface FingerprintKeyProvider {
  /** Returns the stable private key for this installation/project scope. */
  getFingerprintKey(): Uint8Array | Promise<Uint8Array>;
}

export interface ValidationRunnerOptions {
  readonly fingerprintKeyProvider: FingerprintKeyProvider;
  /** Only these names may be placed in the child environment. */
  readonly environmentAllowlist: readonly string[];
  readonly outputLimitBytes?: number;
  readonly signal?: AbortSignal;
  readonly runId?: string;
}

export type ValidationRunnerProblem =
  | 'missing_fingerprint_key'
  | 'invalid_fingerprint_key'
  | 'invalid_output_limit'
  | 'invalid_working_directory'
  | 'cleanup_failed';

export class ValidationRunnerError extends Error {
  readonly code: ValidationRunnerProblem;

  constructor(code: ValidationRunnerProblem) {
    super(`Validation runner ${code}`);
    this.name = 'ValidationRunnerError';
    this.code = code;
  }
}

interface ProcessOutcome {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  spawnError: boolean;
  timedOut: boolean;
  cancelled: boolean;
  terminationError: string | null;
  stdout: OutputCollector;
  stderr: OutputCollector;
}

class OutputCollector {
  private chunks: Buffer[] = [];
  private size = 0;
  private truncated = false;

  public constructor(private readonly limit: number) {}

  public append(chunk: Buffer): void {
    if (chunk.length >= this.limit) {
      this.chunks = [chunk.subarray(chunk.length - this.limit)];
      this.size = this.limit;
      this.truncated = true;
      return;
    }
    this.chunks.push(chunk);
    this.size += chunk.length;
    if (this.size > this.limit) {
      const combined = Buffer.concat(this.chunks);
      this.chunks = [combined.subarray(combined.length - this.limit)];
      this.size = this.limit;
      this.truncated = true;
    }
  }

  public toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }

  public wasTruncated(): boolean {
    return this.truncated;
  }
}

function assertOutputLimit(value: number | undefined): number {
  const limit = value ?? DEFAULT_OUTPUT_LIMIT_BYTES;
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new ValidationRunnerError('invalid_output_limit');
  }
  return limit;
}

function normalizeWorkingDirectory(root: string, cwd: string | undefined): string {
  if (cwd === undefined || cwd === '') return root;
  if (cwd === '.') return root;
  if (isAbsolute(cwd) || cwd.includes('\\')) {
    throw new ValidationRunnerError('invalid_working_directory');
  }
  const segments = cwd.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new ValidationRunnerError('invalid_working_directory');
  }
  const target = join(root, ...segments);
  const relativeTarget = relative(root, target);
  if (relativeTarget === '..' || relativeTarget.startsWith(`..${sep}`) || isAbsolute(relativeTarget)) {
    throw new ValidationRunnerError('invalid_working_directory');
  }
  return target;
}

function sortedEnvironmentKeys(command: ValidationCommand): readonly string[] {
  return Object.keys(command.env ?? {}).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function recordedCommand(command: ValidationCommand, envKeys: readonly string[]): RecordedCommand {
  return Object.freeze({
    kind: command.kind,
    executable: command.executable,
    args: Object.freeze([...command.args]),
    ...(command.cwd === undefined ? {} : { cwd: command.cwd }),
    timeoutMs: command.timeoutMs,
    envKeys: Object.freeze([...envKeys]),
  });
}

function redact(text: string, values: readonly string[]): { text: string; applied: boolean } {
  let result = text;
  let applied = false;
  const candidates = new Set<string>();
  for (const value of values) {
    if (value.length === 0) continue;
    candidates.add(value);
    if (value.length >= 8) {
      candidates.add(Buffer.from(value, 'utf8').toString('base64'));
      candidates.add(Buffer.from(value, 'utf8').toString('hex'));
    }
  }
  for (const value of candidates) {
    if (value.length === 0 || !result.includes(value)) continue;
    result = result.split(value).join('[REDACTED]');
    applied = true;
  }
  return { text: result, applied };
}

function tailSummary(
  collector: OutputCollector,
  secretValues: readonly string[],
  limit: number,
): { text: string; applied: boolean } {
  const redacted = redact(collector.toBuffer().toString('utf8'), secretValues);
  const bytes = Buffer.from(redacted.text, 'utf8');
  return {
    text: bytes.length > limit ? bytes.subarray(bytes.length - limit).toString('utf8') : redacted.text,
    applied: redacted.applied,
  };
}

function outputSummary(
  outcome: ProcessOutcome,
  secretValues: readonly string[],
  limit: number,
): OutputSummary {
  const stdout = tailSummary(outcome.stdout, secretValues, limit);
  const stderr = tailSummary(outcome.stderr, secretValues, limit);
  return Object.freeze({
    stdoutTail: stdout.text,
    stderrTail: stderr.text,
    stdoutTruncated: outcome.stdout.wasTruncated(),
    stderrTruncated: outcome.stderr.wasTruncated(),
    redactionApplied: stdout.applied || stderr.applied,
  });
}

function emptyOutcome(limit: number): ProcessOutcome {
  return {
    exitCode: null,
    signal: null,
    spawnError: false,
    timedOut: false,
    cancelled: false,
    terminationError: null,
    stdout: new OutputCollector(limit),
    stderr: new OutputCollector(limit),
  };
}

interface TerminationResult {
  readonly succeeded: boolean;
  readonly errorMessage: string | null;
}

function directKill(child: ChildProcess): boolean {
  try {
    return child.kill('SIGKILL');
  } catch {
    return false;
  }
}

function terminateProcessTree(child: ChildProcess): Promise<TerminationResult> {
  const pid = child.pid;
  if (pid === undefined) {
    return Promise.resolve({
      succeeded: directKill(child),
      errorMessage: 'The validation process had no process identifier.',
    });
  }

  if (process.platform === 'win32') {
    return new Promise((resolve) => {
      let settled = false;
      let taskkill: ChildProcess;
      let timer: NodeJS.Timeout | undefined;
      let killWaitTimer: NodeJS.Timeout | undefined;
      const finish = (succeeded: boolean, errorMessage: string | null): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        if (killWaitTimer !== undefined) clearTimeout(killWaitTimer);
        resolve({ succeeded, errorMessage });
      };
      try {
        taskkill = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], {
          shell: false,
          windowsHide: true,
          stdio: 'ignore',
        });
      } catch {
        finish(false, 'The Windows process-tree termination command could not start.');
        return;
      }
      taskkill.once('error', () => {
        directKill(child);
        finish(false, 'The Windows process-tree termination command failed to start.');
      });
      taskkill.once('close', (code) => {
        if (code === 0) {
          finish(true, null);
          return;
        }
        directKill(child);
        finish(false, 'The Windows process-tree termination command failed.');
      });
      timer = setTimeout(() => {
        taskkill.kill('SIGKILL');
        directKill(child);
        killWaitTimer = setTimeout(() => {
          finish(false, 'The Windows process-tree termination command did not exit.');
        }, PROCESS_TERMINATION_GRACE_MS);
      }, PROCESS_TERMINATION_TIMEOUT_MS);
    });
  }

  try {
    process.kill(-pid, 'SIGKILL');
    return Promise.resolve({ succeeded: true, errorMessage: null });
  } catch (error: unknown) {
    if (error instanceof Error && 'code' in error && error.code === 'ESRCH') {
      return Promise.resolve({ succeeded: true, errorMessage: null });
    }
    directKill(child);
    return Promise.resolve({
      succeeded: false,
      errorMessage: 'The POSIX process-group termination command failed.',
    });
  }
}

function baseResult(
  command: ValidationCommand,
  materialized: MaterializedSnapshot,
  contextFingerprint: string,
  runId: string,
  startedAt: string,
  startedMs: number,
  summary: OutputSummary,
): {
  runId: string;
  snapshotFingerprint: string;
  contextFingerprint: string;
  command: RecordedCommand;
  outputSummary: OutputSummary;
  durationMs: number;
  startedAt: string;
  finishedAt: string;
} {
  const finishedAt = new Date().toISOString();
  return {
    runId,
    snapshotFingerprint: materialized.manifest.fingerprint,
    contextFingerprint,
    command: recordedCommand(command, sortedEnvironmentKeys(command)),
    outputSummary: summary,
    durationMs: Math.max(0, Math.round(performance.now() - startedMs)),
    startedAt,
    finishedAt,
  };
}

function snapshotChanged(
  base: ReturnType<typeof baseResult>,
  message: string,
): SnapshotChangedRunResult {
  return Object.freeze({ ...base, status: 'snapshot_changed', exitCode: null, signal: null, errorMessage: message });
}

async function execute(
  command: ValidationCommand,
  cwd: string,
  environment: Readonly<Record<string, string>>,
  timeoutMs: number,
  outputLimit: number,
  signal: AbortSignal | undefined,
): Promise<ProcessOutcome> {
  const outcome = emptyOutcome(outputLimit);
  if (signal?.aborted) {
    return { ...outcome, cancelled: true };
  }

  await new Promise<void>((resolve) => {
    let settled = false;
    let started = false;
    let ended = false;
    let timer: NodeJS.Timeout | undefined;
    let terminationTimer: NodeJS.Timeout | undefined;
    let pidWaitTimer: NodeJS.Timeout | undefined;
    let child: ChildProcess | undefined;
    let terminationComplete = true;
    let terminationStarted = false;

    const finish = (): void => {
      if (settled || !ended || !terminationComplete) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (terminationTimer !== undefined) clearTimeout(terminationTimer);
      if (pidWaitTimer !== undefined) clearTimeout(pidWaitTimer);
      signal?.removeEventListener('abort', onAbort);
      resolve();
    };
    const beginTermination = (): void => {
      if (terminationStarted || child === undefined) return;
      terminationStarted = true;
      const targetChild = child;
      terminationComplete = false;
      void terminateProcessTree(targetChild).then((terminationResult) => {
        terminationComplete = true;
        if (!terminationResult.succeeded) {
          outcome.terminationError = terminationResult.errorMessage;
        }
        terminationTimer = setTimeout(() => {
          targetChild.stdout?.destroy();
          targetChild.stderr?.destroy();
          directKill(targetChild);
          ended = true;
          finish();
        }, PROCESS_TERMINATION_GRACE_MS);
        finish();
      });
    };
    const stop = (kind: 'timeout' | 'cancel'): void => {
      if (outcome.timedOut || outcome.cancelled) return;
      if (kind === 'timeout') outcome.timedOut = true;
      else outcome.cancelled = true;
      if (child === undefined) {
        ended = true;
        finish();
        return;
      }
      if (child.pid !== undefined) {
        beginTermination();
        return;
      }
      pidWaitTimer = setTimeout(() => {
        if (terminationStarted || ended) return;
        terminationStarted = true;
        terminationComplete = false;
        directKill(child!);
        terminationComplete = true;
        ended = true;
        finish();
      }, PROCESS_PID_WAIT_TIMEOUT_MS);
      if (started) beginTermination();
    };
    const onAbort = (): void => stop('cancel');

    try {
      child = spawn(command.executable, [...command.args], {
        cwd,
        env: { ...environment },
        shell: false,
        detached: process.platform !== 'win32',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
      child.stdout?.on('data', (chunk: Buffer) => outcome.stdout.append(Buffer.from(chunk)));
      child.stderr?.on('data', (chunk: Buffer) => outcome.stderr.append(Buffer.from(chunk)));
      child.once('error', () => {
        outcome.spawnError = !started;
      });
      child.once('spawn', () => {
        started = true;
        if (outcome.cancelled || outcome.timedOut) {
          if (pidWaitTimer !== undefined) clearTimeout(pidWaitTimer);
          beginTermination();
        } else {
          timer = setTimeout(() => stop('timeout'), Math.min(timeoutMs, MAX_VALIDATION_TIMEOUT_MS));
        }
      });
      child.once('close', (code, childSignal) => {
        outcome.exitCode = code;
        outcome.signal = childSignal;
        ended = true;
        finish();
      });
    } catch {
      outcome.spawnError = true;
      finish();
    }
  });
  return outcome;
}

/**
 * Runs one command against an existing materialized snapshot. The snapshot is
 * verified before and after execution and is always cleaned up by this call.
 */
export async function runValidationCommand(
  command: ValidationCommand,
  materialized: MaterializedSnapshot,
  options: ValidationRunnerOptions,
): Promise<ValidationRunResult> {
  const runId = options.runId ?? randomUUID();
  const startedAt = new Date().toISOString();
  const startedMs = performance.now();
  try {
    const outputLimit = assertOutputLimit(options.outputLimitBytes);
    let key: Uint8Array;
    try {
      key = await options.fingerprintKeyProvider.getFingerprintKey();
    } catch {
      throw new ValidationRunnerError('missing_fingerprint_key');
    }
    if (!(key instanceof Uint8Array) || key.length === 0) {
      throw new ValidationRunnerError('invalid_fingerprint_key');
    }

    let contextFingerprint: string;
    try {
      contextFingerprint = fingerprintValidationContext(command, {
        environmentAllowlist: options.environmentAllowlist,
        fingerprintKey: key,
      });
    } catch (error) {
      if (error instanceof ValidationContextError && error.code === 'invalid_fingerprint_key') {
        throw new ValidationRunnerError('invalid_fingerprint_key');
      }
      throw error;
    }

    const commandKeys = sortedEnvironmentKeys(command);
    const environment = command.env ?? {};
    const secrets = commandKeys.map((name) => environment[name]!).filter((value) => value.length > 0);
    try {
      await materialized.verify();
    } catch {
      const base = baseResult(
        command,
        materialized,
        contextFingerprint,
        runId,
        startedAt,
        startedMs,
        EMPTY_OUTPUT,
      );
      return snapshotChanged(base, 'Snapshot integrity verification failed before execution.');
    }

    const cwd = normalizeWorkingDirectory(materialized.root, command.cwd);
    const outcome = await execute(command, cwd, environment, command.timeoutMs, outputLimit, options.signal);
    const output = outputSummary(outcome, secrets, outputLimit);
    const base = baseResult(command, materialized, contextFingerprint, runId, startedAt, startedMs, output);
    let result: ValidationRunResult;

    const terminationError = outcome.terminationError ?? undefined;
    if (outcome.cancelled) {
      result = Object.freeze({
        ...base,
        status: 'cancelled',
        exitCode: outcome.exitCode,
        signal: outcome.signal,
        ...(terminationError === undefined ? {} : { errorMessage: terminationError }),
      });
    } else if (outcome.timedOut) {
      result = Object.freeze({
        ...base,
        status: 'timed_out',
        exitCode: outcome.exitCode,
        signal: outcome.signal,
        ...(terminationError === undefined ? {} : { errorMessage: terminationError }),
      });
    } else if (outcome.spawnError) {
      result = Object.freeze({
        ...base,
        status: 'spawn_error',
        exitCode: null,
        signal: null,
        errorMessage: 'Validation command could not be started.',
      });
    } else if (outcome.exitCode === 0 && outcome.signal === null) {
      result = Object.freeze({ ...base, status: 'passed', exitCode: 0, signal: null });
    } else {
      result = Object.freeze({ ...base, status: 'failed', exitCode: outcome.exitCode, signal: outcome.signal });
    }

    try {
      await materialized.verify();
    } catch {
      result = snapshotChanged(base, 'Snapshot integrity verification failed after execution.');
    }
    return result;
  } finally {
    try {
      await materialized.cleanup();
    } catch {
      throw new ValidationRunnerError('cleanup_failed');
    }
  }
}
