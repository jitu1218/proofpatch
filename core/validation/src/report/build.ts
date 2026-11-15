/**
 * Validation report builder.
 *
 * Turns ledger entries plus the runs that actually executed into one
 * `ValidationReport`, and lists every check that did NOT run so a reader can
 * never mistake "not tested" for "passed".
 */
import { aggregateValidationResults } from '../ledger/aggregate.js';
import type {
  CheckKind,
  FreshnessState,
  LedgerEntry,
  NotRunCheck,
  OptionalNotRunCheck,
  PassedRunResult,
  SnapshotFingerprint,
  ValidationReport,
  ValidationRunResult,
} from '../types/index.js';

export interface BuildReportInput {
  readonly snapshotFingerprint: SnapshotFingerprint;
  /** Current ledger entries (already compared with the current snapshot). */
  readonly entries: readonly LedgerEntry[];
  /** Runs that really executed. Nothing else may be listed here. */
  readonly runs: readonly ValidationRunResult[];
  /** Checks that were not performed, with the reason. */
  readonly notRun?: readonly NotRunCheck[];
  /** Kinds that must pass before the snapshot may be reported FRESH. */
  readonly requiredKinds?: readonly CheckKind[];
}

const isOptional = (check: NotRunCheck): check is OptionalNotRunCheck => !check.required;
const isPassed = (run: ValidationRunResult): run is PassedRunResult => run.status === 'passed';

export function buildValidationReport(input: BuildReportInput): ValidationReport {
  const { snapshotFingerprint, entries, runs } = input;
  const aggregation = aggregateValidationResults(entries, snapshotFingerprint, input.requiredKinds);

  const notRun: NotRunCheck[] = [...(input.notRun ?? [])];
  for (const kind of aggregation.missingRequiredKinds ?? []) {
    if (notRun.some((check) => check.kind === kind)) continue;
    notRun.push({ kind, reason: 'not_configured', required: true, detail: 'Required check has no evidence.' });
  }

  let overall: FreshnessState = aggregation.overall;
  if (overall === 'FRESH' && notRun.some((check) => check.required)) overall = 'NOT_RUN';

  if (overall === 'FRESH') {
    const passedRuns = runs.filter(isPassed);
    const consistent =
      runs.length > 0 &&
      passedRuns.length === runs.length &&
      passedRuns.every((run) => run.snapshotFingerprint === snapshotFingerprint);
    const [first, ...rest] = passedRuns;
    if (consistent && first !== undefined) {
      return Object.freeze({
        overall: 'FRESH',
        snapshotFingerprint,
        checksRun: Object.freeze([first, ...rest]) as readonly [PassedRunResult, ...PassedRunResult[]],
        checksNotRun: Object.freeze(notRun.filter(isOptional)),
      });
    }
    // FRESH entries that the supplied runs do not back: never claim FRESH.
    overall = 'NOT_RUN';
  }

  return Object.freeze({
    overall: overall as Exclude<FreshnessState, 'FRESH'>,
    snapshotFingerprint,
    checksRun: Object.freeze([...runs]),
    checksNotRun: Object.freeze(notRun),
  });
}

/** Plain-text summary that keeps "ran" and "not run" visibly apart. */
export function formatValidationReport(report: ValidationReport): string {
  const lines = [`Overall: ${report.overall}`, `Snapshot: ${report.snapshotFingerprint}`, 'Checks run:'];
  if (report.checksRun.length === 0) lines.push('  (none)');
  for (const run of report.checksRun) {
    const matches = run.snapshotFingerprint === report.snapshotFingerprint ? '' : ' [different snapshot: outdated]';
    lines.push(`  - ${run.command.kind} ${run.status} (exit ${run.exitCode ?? 'n/a'}, ${run.durationMs} ms)${matches}`);
  }
  lines.push('Checks NOT run:');
  if (report.checksNotRun.length === 0) lines.push('  (none)');
  for (const check of report.checksNotRun) {
    const detail = check.detail === undefined ? '' : `: ${check.detail}`;
    lines.push(`  - ${check.kind} (${check.reason}${check.required ? ', required' : ''})${detail}`);
  }
  return lines.join('\n');
}
