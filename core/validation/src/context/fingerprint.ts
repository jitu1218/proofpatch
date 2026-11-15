/**
 * Deterministic validation-context fingerprinting (Phase 2, Step 4).
 *
 * The input is a deliberately small, controlled execution description. It
 * does not inspect process.env: callers must provide the exact environment
 * they will give the child process and an explicit allowlist for the values
 * that are allowed to affect validation.
 *
 * v2 encoding:
 *   lp("proofpatch-validation-context"), lp("v1")
 *   lp(kind), lp(executable), u32(argumentCount), lp(each argument)
 *   lp(relativeWorkingDirectory)
 *   u32(allowlistedEnvironmentCount)
 *   for each allowlisted name in UTF-8 byte order:
 *     lp(name), byte(present), lp(value only when present)
 *   u64(timeoutMs)
 *
 * All variable-length values are length-prefixed. The field order is fixed,
 * independent of JavaScript object property insertion order.
 */
import { createHmac, type Hmac } from 'node:crypto';
import { isAbsolute, win32 } from 'node:path';

import type { CheckKind, ValidationCommand } from '../types/index.js';

export const CONTEXT_FINGERPRINT_FORMAT_VERSION = 'v2' as const;
export const CONTEXT_FINGERPRINT_PREFIX = 'hmac-sha256:';
/** Maximum delay supported by Node.js timers without overflow. */
export const MAX_VALIDATION_TIMEOUT_MS = 2_147_483_647;

const DOMAIN_TAG = 'proofpatch-validation-context';
const CHECK_KINDS: readonly CheckKind[] = ['build', 'custom', 'lint', 'test', 'typecheck'];
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export type ContextInputProblem =
  | 'invalid_string'
  | 'empty'
  | 'nul'
  | 'invalid_unicode'
  | 'invalid_kind'
  | 'relative_executable'
  | 'invalid_timeout'
  | 'absolute_working_directory'
  | 'unsafe_working_directory'
  | 'invalid_environment_name'
  | 'duplicate_environment_name'
  | 'environment_not_allowlisted'
  | 'invalid_fingerprint_key';

export class ValidationContextError extends Error {
  readonly code: ContextInputProblem;
  readonly field: string;

  constructor(code: ContextInputProblem, field: string) {
    super(`Invalid validation context field ${JSON.stringify(field)}: ${code}`);
    this.name = 'ValidationContextError';
    this.code = code;
    this.field = field;
  }
}

export interface ContextFingerprintOptions {
  /**
   * Names explicitly permitted to influence the child environment. The
   * allowlist is configuration-only: do not include credentials or secrets.
   */
  readonly environmentAllowlist: readonly string[];
  /**
   * Private, stable key held by the validation service. It is never recorded
   * in evidence or included in the encoded input.
   */
  readonly fingerprintKey: Uint8Array;
}

function assertText(value: unknown, field: string, allowEmpty = false): asserts value is string {
  if (typeof value !== 'string') throw new ValidationContextError('invalid_string', field);
  if (!allowEmpty && value.length === 0) throw new ValidationContextError('empty', field);
  if (value.includes('\0')) throw new ValidationContextError('nul', field);
  if (LONE_SURROGATE.test(value)) throw new ValidationContextError('invalid_unicode', field);
}

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function environmentNameKey(name: string): string {
  return name.toLowerCase();
}

function validateEnvironmentName(name: unknown, field: string): asserts name is string {
  assertText(name, field);
  if (name.includes('=')) throw new ValidationContextError('invalid_environment_name', field);
}

function validateWorkingDirectory(cwd: unknown): string {
  if (cwd === undefined) return '';
  assertText(cwd, 'cwd', true);
  if (cwd === '.') return '';
  if (cwd.startsWith('/') || /^[A-Za-z]:/.test(cwd)) {
    throw new ValidationContextError('absolute_working_directory', 'cwd');
  }

  if (cwd.includes('\\')) throw new ValidationContextError('unsafe_working_directory', 'cwd');
  const segments = cwd.split('/');
  if (segments.some((segment) => segment === '' || segment === '..' || segment === '.')) {
    throw new ValidationContextError('unsafe_working_directory', 'cwd');
  }
  return cwd;
}

function assertAbsoluteExecutable(executable: string): void {
  const absolute = process.platform === 'win32'
    ? win32.isAbsolute(executable) &&
      (/^[A-Za-z]:[\\/]/.test(executable) || executable.startsWith('\\\\'))
    : isAbsolute(executable);
  if (!absolute) {
    throw new ValidationContextError('relative_executable', 'executable');
  }
}

function u32(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('Context field does not fit in an unsigned 32-bit integer');
  }
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value, 0);
  return result;
}

function u64(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ValidationContextError('invalid_timeout', 'timeoutMs');
  }
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(BigInt(value), 0);
  return result;
}

function lp(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([u32(bytes.length), bytes]);
}

function updateLp(hash: Hmac, value: string): void {
  hash.update(lp(value));
}

/**
 * Computes an HMAC-SHA-256 fingerprint of a validated command context.
 *
 * `command.env` is an explicit child environment overlay, not inherited
 * process state. Every supplied name must be in `environmentAllowlist`;
 * non-allowlisted values are rejected rather than silently omitted.
 */
export function fingerprintValidationContext(
  command: ValidationCommand,
  options: ContextFingerprintOptions,
): string {
  if (typeof command !== 'object' || command === null) {
    throw new ValidationContextError('invalid_string', 'command');
  }
  if (typeof options !== 'object' || options === null) {
    throw new ValidationContextError('invalid_environment_name', 'options');
  }
  if (!(options.fingerprintKey instanceof Uint8Array) || options.fingerprintKey.length === 0) {
    throw new ValidationContextError('invalid_fingerprint_key', 'fingerprintKey');
  }
  if (!CHECK_KINDS.includes(command.kind)) {
    throw new ValidationContextError('invalid_kind', 'kind');
  }
  assertText(command.executable, 'executable');
  assertAbsoluteExecutable(command.executable);
  if (!Array.isArray(command.args)) throw new ValidationContextError('invalid_string', 'args');
  for (let index = 0; index < command.args.length; index += 1) {
    assertText(command.args[index], `args[${index}]`, true);
  }
  const cwd = validateWorkingDirectory(command.cwd);
  if (
    !Number.isSafeInteger(command.timeoutMs) ||
    command.timeoutMs <= 0 ||
    command.timeoutMs > MAX_VALIDATION_TIMEOUT_MS
  ) {
    throw new ValidationContextError('invalid_timeout', 'timeoutMs');
  }
  if (!Array.isArray(options.environmentAllowlist)) {
    throw new ValidationContextError('invalid_environment_name', 'environmentAllowlist');
  }

  const allowlist = [...options.environmentAllowlist];
  const names = new Set<string>();
  for (let index = 0; index < allowlist.length; index += 1) {
    const name = allowlist[index];
    validateEnvironmentName(name, `environmentAllowlist[${index}]`);
    const key = environmentNameKey(name);
    if (names.has(key)) throw new ValidationContextError('duplicate_environment_name', name);
    names.add(key);
  }
  allowlist.sort((a, b) => compareBytes(environmentNameKey(a), environmentNameKey(b)));

  const environment = command.env ?? {};
  if (typeof environment !== 'object' || Array.isArray(environment)) {
    throw new ValidationContextError('invalid_environment_name', 'env');
  }
  const suppliedNames = Object.keys(environment);
  const suppliedKeys = new Set<string>();
  for (const name of suppliedNames) {
    validateEnvironmentName(name, `env.${name}`);
    const key = environmentNameKey(name);
    if (!names.has(key)) throw new ValidationContextError('environment_not_allowlisted', name);
    if (suppliedKeys.has(key)) throw new ValidationContextError('duplicate_environment_name', name);
    suppliedKeys.add(key);
    assertText(environment[name], `env.${name}`, true);
  }

  const hash = createHmac('sha256', options.fingerprintKey);
  updateLp(hash, DOMAIN_TAG);
  updateLp(hash, CONTEXT_FINGERPRINT_FORMAT_VERSION);
  updateLp(hash, command.kind);
  updateLp(hash, command.executable);
  hash.update(u32(command.args.length));
  for (const argument of command.args) updateLp(hash, argument);
  updateLp(hash, cwd);
  hash.update(u32(allowlist.length));
  for (const name of allowlist) {
    const canonicalName = environmentNameKey(name);
    updateLp(hash, canonicalName);
    const suppliedName = suppliedNames.find((candidate) => environmentNameKey(candidate) === canonicalName);
    const present = suppliedName !== undefined;
    hash.update(Buffer.from([present ? 1 : 0]));
    if (present) updateLp(hash, environment[suppliedName]!);
  }
  hash.update(u64(command.timeoutMs));
  return `${CONTEXT_FINGERPRINT_PREFIX}${hash.digest('hex')}`;
}
