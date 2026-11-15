/**
 * Normalizes Semgrep `--json` output into findings.
 *
 * Only rule id, location, severity and a redacted message are kept. Semgrep's
 * `extra.lines` (matched source text) is deliberately dropped because it can
 * contain secret values.
 */
import { redactSecretLikeText } from './secret-scan.js';

export interface SemgrepFinding {
  readonly ruleId: string;
  readonly path: string;
  readonly line: number;
  readonly column: number;
  readonly severity: string;
  readonly message: string;
}

export type SemgrepParseResult =
  | { readonly ok: true; readonly findings: readonly SemgrepFinding[]; readonly scannerErrorCount: number }
  | { readonly ok: false; readonly reason: 'unparseable_output' | 'output_truncated' };

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const cmp = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));

export function parseSemgrepJson(stdout: string, outputTruncated = false): SemgrepParseResult {
  if (outputTruncated) return { ok: false, reason: 'output_truncated' };
  let data: unknown;
  try {
    data = JSON.parse(stdout);
  } catch {
    return { ok: false, reason: 'unparseable_output' };
  }
  if (!isObject(data) || !Array.isArray(data['results'])) return { ok: false, reason: 'unparseable_output' };

  const findings: SemgrepFinding[] = [];
  for (const item of data['results']) {
    if (!isObject(item)) return { ok: false, reason: 'unparseable_output' };
    const start = item['start'];
    const extra = isObject(item['extra']) ? item['extra'] : {};
    if (
      typeof item['check_id'] !== 'string' ||
      typeof item['path'] !== 'string' ||
      !isObject(start) ||
      typeof start['line'] !== 'number'
    ) {
      return { ok: false, reason: 'unparseable_output' };
    }
    findings.push(
      Object.freeze({
        ruleId: item['check_id'],
        path: item['path'].replace(/^\.\//u, ''),
        line: start['line'],
        column: typeof start['col'] === 'number' ? start['col'] : 1,
        severity: typeof extra['severity'] === 'string' ? extra['severity'] : 'UNKNOWN',
        message: redactSecretLikeText(typeof extra['message'] === 'string' ? extra['message'] : ''),
      }),
    );
  }
  findings.sort((a, b) => cmp(a.path, b.path) || a.line - b.line || a.column - b.column || cmp(a.ruleId, b.ruleId));
  const errors = Array.isArray(data['errors']) ? data['errors'].length : 0;
  return { ok: true, findings: Object.freeze(findings), scannerErrorCount: errors };
}
