/**
 * End-to-end validation orchestration.
 *
 * snapshot -> (per check) fresh temp copy -> run -> ledger -> report.
 *
 * The caller (Member 3 UI / Member 4 patch engine) uses ONE entry point:
 * `ValidationSession.validate`. The user's real workspace is never touched:
 * commands only ever run inside temp copies that the runner deletes.
 */
import type {
  CheckKind,
  DiskConflictReport,
  NotRunCheck,
  StagedSnapshot,
  StagedSnapshotSource,
  ValidationCommand,
  ValidationReport,
  ValidationRunResult,
} from '../types/index.js';
import { fingerprintValidationContext } from '../context/index.js';
import { recordResult } from '../ledger/ledger.js';
import { checkIdOf, LedgerStore } from '../ledger/store.js';
import { buildValidationReport } from '../report/build.js';
import { runValidationCommand, ValidationRunnerError, type FingerprintKeyProvider } from '../runner/index.js';
import { runSemgrepScan, scanSecrets, type SemgrepOptions, type SemgrepScanResult, type SecretScanResult } from '../security/index.js';
import { buildSnapshotManifest, materializeSnapshot } from '../snapshot/index.js';

export interface CheckSpec {
  readonly command: ValidationCommand;
  /** Required checks must pass for FRESH. Default true. */
  readonly required?: boolean;
}

export interface SessionOptions {
  readonly fingerprintKeyProvider: FingerprintKeyProvider;
  readonly environmentAllowlist: readonly string[];
  /** Supply a store (e.g. loaded from JSON) to keep ledger history. */
  readonly store?: LedgerStore;
  readonly outputLimitBytes?: number;
}

export interface ValidateOptions {
  readonly signal?: AbortSignal;
  readonly security?: {
    /** Run the built-in secret scan. */
    readonly secrets?: boolean;
    /** Run Semgrep if installed; omit to skip. */
    readonly semgrep?: Omit<SemgrepOptions, 'fingerprintKeyProvider' | 'environmentAllowlist' | 'signal'>;
  };
}

export interface ValidationOutcome {
  readonly report: ValidationReport;
  /** Runs that really executed, in order. */
  readonly runs: readonly ValidationRunResult[];
  /**
   * Security results are reported next to, not inside, the freshness state:
   * a finding is not a failed test, and a missing scanner is not a pass.
   */
  readonly security: {
    readonly secrets?: SecretScanResult;
    readonly semgrep?: SemgrepScanResult;
  };
}

const isSource = (value: StagedSnapshot | StagedSnapshotSource): value is StagedSnapshotSource =>
  typeof (value as StagedSnapshotSource).getStagedSnapshot === 'function';

export class ValidationSession {
  readonly store: LedgerStore;

  constructor(private readonly options: SessionOptions) {
    this.store = options.store ?? new LedgerStore();
  }

  /** Patch engine reports a disk conflict: validation stops until cleared. */
  reportConflict(report: DiskConflictReport): void {
    this.store.reportConflict(report);
  }

  clearConflict(): void {
    this.store.clearConflict();
  }

  /**
   * Validates the exact given snapshot. When a `StagedSnapshotSource` is given,
   * the snapshot is re-read around every check; if it moved, the evidence is
   * demoted to STALE and the remaining checks are reported as not run.
   */
  async validate(
    input: StagedSnapshot | StagedSnapshotSource,
    checks: readonly CheckSpec[],
    validateOptions: ValidateOptions = {},
  ): Promise<ValidationOutcome> {
    const source = isSource(input) ? input : undefined;
    const snapshot = source === undefined ? (input as StagedSnapshot) : await source.getStagedSnapshot();
    let fingerprint = buildSnapshotManifest(snapshot.files).fingerprint;
    const ids = checks.map((spec) => checkIdOf(spec.command));
    const requiredKinds: CheckKind[] = checks.filter((s) => s.required !== false).map((s) => s.command.kind);
    const notRun: NotRunCheck[] = [];
    const runs: ValidationRunResult[] = [];
    const security: { secrets?: SecretScanResult; semgrep?: SemgrepScanResult } = {};

    const conflict = this.store.conflict;
    if (conflict !== undefined) {
      for (const spec of checks) {
        notRun.push({ kind: spec.command.kind, reason: 'blocked_by_conflict', required: spec.required !== false });
      }
      return Object.freeze({
        report: buildValidationReport({ snapshotFingerprint: fingerprint, entries: [conflict], runs, notRun, requiredKinds }),
        runs,
        security,
      });
    }

    const key = await this.options.fingerprintKeyProvider.getFingerprintKey();
    const skipRest = (from: number, reason: NotRunCheck['reason']): void => {
      for (const spec of checks.slice(from)) {
        notRun.push({ kind: spec.command.kind, reason, required: spec.required !== false });
      }
    };

    // The runner's own options never include a per-run id here: each run gets a fresh one.
    for (let index = 0; index < checks.length; index += 1) {
      const spec = checks[index]!;
      if (validateOptions.signal?.aborted === true) {
        skipRest(index, 'cancelled_before_start');
        break;
      }
      const latest = source === undefined ? undefined : buildSnapshotManifest((await source.getStagedSnapshot()).files).fingerprint;
      if (latest !== undefined && latest !== fingerprint) {
        fingerprint = latest;
        skipRest(index, 'snapshot_changed_during_validation');
        break;
      }

      const materialized = await materializeSnapshot(snapshot);
      let result: ValidationRunResult;
      try {
        result = await runValidationCommand(spec.command, materialized, {
          fingerprintKeyProvider: this.options.fingerprintKeyProvider,
          environmentAllowlist: this.options.environmentAllowlist,
          ...(this.options.outputLimitBytes === undefined ? {} : { outputLimitBytes: this.options.outputLimitBytes }),
          ...(validateOptions.signal === undefined ? {} : { signal: validateOptions.signal }),
        });
      } catch (error) {
        if (error instanceof ValidationRunnerError) throw error;
        await materialized.cleanup();
        throw error;
      }
      runs.push(result);
      const context = fingerprintValidationContext(spec.command, {
        environmentAllowlist: this.options.environmentAllowlist,
        fingerprintKey: key,
      });
      this.store.set(ids[index]!, recordResult(result, materialized.manifest.fingerprint, context));

      if (source !== undefined) {
        const after = buildSnapshotManifest((await source.getStagedSnapshot()).files).fingerprint;
        if (after !== fingerprint) {
          fingerprint = after;
          skipRest(index + 1, 'snapshot_changed_during_validation');
          break;
        }
      }
    }

    const finished = notRun.length === 0 && validateOptions.signal?.aborted !== true;
    if (finished) await this.runSecurity(snapshot, validateOptions, security, notRun);
    else notRun.push({ kind: 'security', reason: 'cancelled_before_start', required: false, detail: 'Security checks were skipped.' });

    // Demote anything that does not belong to the snapshot we ended up with.
    this.store.invalidateFor(fingerprint);
    const entries = this.store.entriesFor(fingerprint, ids);
    return Object.freeze({
      report: buildValidationReport({ snapshotFingerprint: fingerprint, entries, runs, notRun, requiredKinds }),
      runs,
      security,
    });
  }

  private async runSecurity(
    snapshot: StagedSnapshot,
    validateOptions: ValidateOptions,
    security: { secrets?: SecretScanResult; semgrep?: SemgrepScanResult },
    notRun: NotRunCheck[],
  ): Promise<void> {
    const wanted = validateOptions.security;
    if (wanted?.secrets === true) security.secrets = scanSecrets(snapshot);
    else notRun.push({ kind: 'security', reason: 'not_requested', required: false, detail: 'Secret scan was not requested.' });

    if (wanted?.semgrep === undefined) {
      notRun.push({ kind: 'security', reason: 'not_requested', required: false, detail: 'Semgrep was not requested.' });
      return;
    }
    const materialized = await materializeSnapshot(snapshot);
    const semgrep = await runSemgrepScan(materialized, {
      ...wanted.semgrep,
      fingerprintKeyProvider: this.options.fingerprintKeyProvider,
      environmentAllowlist: this.options.environmentAllowlist,
      ...(validateOptions.signal === undefined ? {} : { signal: validateOptions.signal }),
    });
    security.semgrep = semgrep;
    if (semgrep.outcome === 'not_run') {
      notRun.push({ kind: 'security', reason: semgrep.reason ?? 'cancelled_before_start', required: false, detail: 'Semgrep did not run.' });
    }
  }
}
