/**
 * Validation runner and evidence types.
 * INDEPENDENT of other members, except `snapshotFingerprint`, whose string
 * format is provisional (see ./provisional.ts).
 */
import type { SnapshotFingerprint } from './provisional.js';

/** Kind of check. Includes built-in checks plus caller-defined custom commands. */
export type CheckKind = 'test' | 'lint' | 'build' | 'typecheck' | 'custom';

/**
 * A command to run. Executable + args array (no shell string) so nothing is
 * interpreted by a shell and quoting/injection issues are avoided.
 */
export interface ValidationCommand {
  readonly kind: CheckKind;
  readonly executable: string;
  readonly args: readonly string[];
  /** Working directory relative to the snapshot root. Defaults to the root. */
  readonly cwd?: string;
  readonly timeoutMs: number;
  /** Extra environment variables (e.g. PYTHONPATH). Values are never recorded. */
  readonly env?: Readonly<Record<string, string>>;
}

/**
 * The command as stored in evidence. Environment values are dropped on
 * purpose (they may contain secrets); only variable names are kept.
 */
export interface RecordedCommand {
  readonly kind: CheckKind;
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly timeoutMs: number;
  readonly envKeys: readonly string[];
}

/** Bounded, summarised process output. Never the full log. */
export interface OutputSummary {
  readonly stdoutTail: string;
  readonly stderrTail: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  /** True if secret-like values were masked in the text above. */
  readonly redactionApplied: boolean;
}

/** Fields shared by every run result, whatever its status. */
interface RunResultBase {
  /** Unique per run. */
  readonly runId: string;
  /** Exact staged snapshot this run was executed against. */
  readonly snapshotFingerprint: SnapshotFingerprint;
  /**
   * Fingerprint of the validation context (command, relevant config inputs).
   * Lets the ledger detect "command changed" separately from "content changed".
   * Format/derivation is defined in the hashing phase.
   */
  readonly contextFingerprint: string;
  readonly command: RecordedCommand;
  readonly outputSummary: OutputSummary;
  readonly durationMs: number;
  /** ISO 8601 UTC timestamps. */
  readonly startedAt: string;
  readonly finishedAt: string;
  /** Human-readable detail for spawn_error / cancelled / snapshot_changed. */
  readonly errorMessage?: string;
}

/**
 * INDIVIDUAL CHECK STATUS — how ONE command execution ended.
 *
 * Each status is its own type below so the compiler can tell them apart.
 * Only PassedRunResult can ever be the evidence of a FRESH ledger entry.
 */

/** Process ran and exited with code 0. The ONLY status that can support FRESH. */
export interface PassedRunResult extends RunResultBase {
  readonly status: 'passed';
  readonly exitCode: 0;
  readonly signal: null;
}

/** Process ran and exited non-zero (or was killed by a signal it did not get from us). */
export interface FailedRunResult extends RunResultBase {
  readonly status: 'failed';
  readonly exitCode: number | null;
  readonly signal: string | null;
}

/** Process was killed because it exceeded timeoutMs. */
export interface TimedOutRunResult extends RunResultBase {
  readonly status: 'timed_out';
  readonly exitCode: number | null;
  readonly signal: string | null;
}

/** Process never started (missing executable, invalid command, bad cwd). */
export interface SpawnErrorRunResult extends RunResultBase {
  readonly status: 'spawn_error';
  readonly exitCode: null;
  readonly signal: null;
  readonly errorMessage: string;
}

/** Process was stopped because the caller cancelled. Result is incomplete. */
export interface CancelledRunResult extends RunResultBase {
  readonly status: 'cancelled';
  readonly exitCode: number | null;
  readonly signal: string | null;
}

/** Staged content changed while the process ran; the result is not usable. */
export interface SnapshotChangedRunResult extends RunResultBase {
  readonly status: 'snapshot_changed';
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly errorMessage: string;
}

/** Machine-readable evidence for one validation run (one command). */
export type ValidationRunResult =
  | PassedRunResult
  | FailedRunResult
  | TimedOutRunResult
  | SpawnErrorRunResult
  | CancelledRunResult
  | SnapshotChangedRunResult;

/** How one execution ended. Derived from the union so the two cannot drift. */
export type ExecutionStatus = ValidationRunResult['status'];

/** Any result that is not a clean pass. */
export type NotPassedRunResult = Exclude<ValidationRunResult, PassedRunResult>;

/**
 * Results that may back a FAILED ledger entry: the check was attempted and did
 * not succeed (non-zero exit, timeout, or it could not even be started).
 * DESIGN DECISION (confirm in review): spawn_error and timed_out are treated as
 * FAILED because they are never a pass and hiding them as NOT_RUN would be
 * misleading.
 */
export type FailingRunResult =
  | FailedRunResult
  | TimedOutRunResult
  | SpawnErrorRunResult;

/**
 * Results with no conclusion about the code (user stopped it, or the snapshot
 * moved under it). These never make a ledger entry FRESH or FAILED; the
 * ledger stays NOT_RUN and may keep one as `lastAttempt` for display.
 */
export type InconclusiveRunResult =
  | CancelledRunResult
  | SnapshotChangedRunResult;
