import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isAbsolute } from 'node:path';

import type { MaterializedSnapshot } from '../snapshot/index.js';
import {
  runValidationCommand,
  type FingerprintKeyProvider,
} from '../runner/index.js';
import type { ValidationRunResult } from '../types/index.js';
import { parseSemgrepJson, type SemgrepFinding } from './semgrep-parse.js';

const execFileAsync = promisify(execFile);

export interface SemgrepOptions {
  readonly fingerprintKeyProvider: FingerprintKeyProvider;
  readonly environmentAllowlist: readonly string[];
  readonly config?: string;
  readonly timeoutMs?: number;
  readonly outputLimitBytes?: number;
  readonly signal?: AbortSignal;
  /** Test/integration hook: how to find the executable. Must return an absolute path. */
  readonly resolveExecutable?: () => Promise<string | undefined>;
}

/** Output cap for Semgrep JSON, which is larger than ordinary test output. */
const SEMGREP_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024;

export type SemgrepOutcome = 'not_run' | 'clean' | 'findings' | 'error';

export interface SemgrepScanResult {
  readonly kind: 'semgrep';
  readonly status: ValidationRunResult['status'] | 'not_run';
  readonly snapshotFingerprint: string;
  readonly run?: ValidationRunResult;
  readonly reason?: 'tool_unavailable';
  /**
   * not_run: Semgrep did not execute (missing, cancelled, snapshot changed).
   * clean: ran, parsed, zero findings and zero scanner errors.
   * findings: ran and reported findings (Semgrep exits non-zero with --error).
   * error: ran but the result is unusable (timeout, crash, unparseable/truncated JSON, scanner errors).
   */
  readonly outcome: SemgrepOutcome;
  readonly findings: readonly SemgrepFinding[];
  readonly parseProblem?: 'unparseable_output' | 'output_truncated';
}

async function findSemgrep(): Promise<string | undefined> {
  const locator = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const { stdout } = await execFileAsync(locator, ['semgrep'], {
      shell: false,
      windowsHide: true,
      timeout: 5_000,
      maxBuffer: 16 * 1024,
    });
    const candidate = String(stdout).split(/\r?\n/u).map((line) => line.trim()).find(Boolean);
    return candidate !== undefined && isAbsolute(candidate) ? candidate : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Runs Semgrep when installed. Unavailable tooling is explicitly NOT RUN;
 * it is never represented as a successful validation.
 *
 * The supplied materialized snapshot is owned by this function and is
 * cleaned by the existing runner on every execution path.
 */
export async function runSemgrepScan(
  materialized: MaterializedSnapshot,
  options: SemgrepOptions,
): Promise<SemgrepScanResult> {
  const executable = await (options.resolveExecutable ?? findSemgrep)();
  if (executable === undefined) {
    await materialized.cleanup();
    return Object.freeze({
      kind: 'semgrep',
      status: 'not_run',
      snapshotFingerprint: materialized.manifest.fingerprint,
      reason: 'tool_unavailable',
      outcome: 'not_run',
      findings: Object.freeze([]),
    });
  }

  const run = await runValidationCommand(
    {
      kind: 'custom',
      executable,
      args: ['scan', '--config', options.config ?? 'auto', '--error', '--json', '--metrics=off', '.'],
      timeoutMs: options.timeoutMs ?? 120_000,
    },
    materialized,
    {
      fingerprintKeyProvider: options.fingerprintKeyProvider,
      environmentAllowlist: options.environmentAllowlist,
      outputLimitBytes: options.outputLimitBytes ?? SEMGREP_OUTPUT_LIMIT_BYTES,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    },
  );
  const base = { kind: 'semgrep', status: run.status, snapshotFingerprint: run.snapshotFingerprint, run } as const;
  if (run.status === 'cancelled' || run.status === 'snapshot_changed') {
    return Object.freeze({ ...base, outcome: 'not_run', findings: Object.freeze([]) });
  }
  if (run.status !== 'passed' && run.status !== 'failed') {
    return Object.freeze({ ...base, outcome: 'error', findings: Object.freeze([]) });
  }
  const parsed = parseSemgrepJson(run.outputSummary.stdoutTail, run.outputSummary.stdoutTruncated);
  if (!parsed.ok) {
    return Object.freeze({ ...base, outcome: 'error', findings: Object.freeze([]), parseProblem: parsed.reason });
  }
  const outcome: SemgrepOutcome =
    parsed.findings.length > 0 ? 'findings' : run.status === 'passed' && parsed.scannerErrorCount === 0 ? 'clean' : 'error';
  return Object.freeze({ ...base, outcome, findings: parsed.findings });
}
