import type { SnapshotFingerprint, StagedSnapshot } from '../types/index.js';
import { buildSnapshotManifest } from '../snapshot/hash.js';

export type SecretFindingKind =
  | 'private_key'
  | 'aws_access_key'
  | 'github_token'
  | 'generic_credential'
  | 'bearer_token';

export interface SecretFinding {
  readonly kind: SecretFindingKind;
  readonly path: string;
  readonly line: number;
  readonly column: number;
  readonly redactedMatch: '[REDACTED]';
}

export interface SecretScanResult {
  readonly kind: 'secrets';
  readonly status: 'passed' | 'failed';
  readonly snapshotFingerprint: SnapshotFingerprint;
  readonly findings: readonly SecretFinding[];
}

interface SecretPattern {
  readonly kind: SecretFindingKind;
  readonly expression: RegExp;
}

const PATTERNS: readonly SecretPattern[] = [
  { kind: 'private_key', expression: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g },
  { kind: 'aws_access_key', expression: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: 'github_token', expression: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g },
  { kind: 'bearer_token', expression: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/gi },
  {
    kind: 'generic_credential',
    expression:
      /\b(?:api[_-]?key|secret(?:[_-]?key)?|token|password|passwd|authorization)\b\s*[:=]\s*(['"]?)([A-Za-z0-9_./+=-]{12,})\1/gi,
  },
];

function isPlaceholder(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized === 'changeme' ||
    normalized === 'change-me' ||
    normalized === 'example' ||
    normalized === 'placeholder' ||
    normalized === 'your-secret-here' ||
    normalized.includes('<') ||
    normalized.includes('${')
  );
}

/** Masks secret-like substrings in free text (e.g. scanner messages). */
export function redactSecretLikeText(text: string): string {
  let result = text;
  for (const pattern of PATTERNS) {
    result = result.replace(new RegExp(pattern.expression.source, pattern.expression.flags), '[REDACTED]');
  }
  return result;
}

function scanLine(path: string, line: string, lineNumber: number): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const pattern of PATTERNS) {
    pattern.expression.lastIndex = 0;
    for (const match of line.matchAll(pattern.expression)) {
      const value = pattern.kind === 'generic_credential' ? match[2] : match[0];
      if (value === undefined || isPlaceholder(value)) continue;
      findings.push({
        kind: pattern.kind,
        path,
        line: lineNumber,
        column: (match.index ?? 0) + 1,
        redactedMatch: '[REDACTED]',
      });
    }
  }
  return findings;
}

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * Scans the provisional staged snapshot for common credential patterns.
 *
 * Findings contain only location, category, and a fixed redaction marker.
 * This is a conservative detector, not a guarantee that every secret is
 * found. The snapshot fingerprint is computed from the exact scanned model.
 */
export function scanSecrets(snapshot: StagedSnapshot): SecretScanResult {
  const manifest = buildSnapshotManifest(snapshot.files);
  const contentByPath = new Map(snapshot.files.map((file) => [file.path, file.content]));
  const findings: SecretFinding[] = [];
  for (const file of manifest.files) {
    const content = contentByPath.get(file.path);
    if (content === undefined) continue;
    const lines = content.split(/\r\n|\n|\r/u);
    for (let index = 0; index < lines.length; index += 1) {
      findings.push(...scanLine(file.path, lines[index]!, index + 1));
    }
  }
  findings.sort((a, b) =>
    compareBytes(a.path, b.path) ||
    a.line - b.line ||
    a.column - b.column ||
    compareBytes(a.kind, b.kind),
  );
  const frozenFindings = Object.freeze(findings.map((finding) => Object.freeze(finding)));
  return Object.freeze({
    kind: 'secrets',
    status: frozenFindings.length === 0 ? 'passed' : 'failed',
    snapshotFingerprint: manifest.fingerprint,
    findings: frozenFindings,
  });
}
