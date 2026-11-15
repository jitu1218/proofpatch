/**
 * Python/Flask helpers: make sure Python imports the SNAPSHOT, not an
 * editable install, a user-site package or a globally installed copy.
 *
 * Two parts:
 *  1. `pythonSnapshotEnv` puts the snapshot's source roots first on
 *     PYTHONPATH using RELATIVE entries. Relative entries resolve against the
 *     command's cwd, which is the temp snapshot, so the value is identical on
 *     every run and the context fingerprint stays stable (an absolute temp
 *     path would change every run and make FRESH impossible).
 *  2. `buildPythonImportGuardCommand` returns a command that imports the
 *     named packages and fails unless every module file lives under one of
 *     those roots. Run it BEFORE pytest; if it does not pass, pytest results
 *     must not be trusted.
 */
import { delimiter, posix } from 'node:path';

import type { ValidationCommand } from '../types/index.js';

/** Environment variable names the helpers set. Add these to environmentAllowlist. */
export const PYTHON_ENV_ALLOWLIST: readonly string[] = Object.freeze([
  'PYTHONPATH',
  'PYTHONNOUSERSITE',
  'PYTHONDONTWRITEBYTECODE',
]);

export interface PythonSnapshotOptions {
  /** Absolute path of the Python interpreter (callers resolve PATH names). */
  readonly python: string;
  /** Snapshot-relative source roots, e.g. ['src'] for the Flask repo. Default ['.']. */
  readonly sourceRoots?: readonly string[];
  /** Snapshot-relative working directory. Default: snapshot root. */
  readonly cwd?: string;
  readonly timeoutMs: number;
}

function assertRelativeSafe(path: string, label: string): void {
  if (path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/u.test(path) || path.split('/').includes('..')) {
    throw new RangeError(`${label} must be a snapshot-relative POSIX path without "..": ${path}`);
  }
}

export function pythonSnapshotEnv(options: Pick<PythonSnapshotOptions, 'sourceRoots' | 'cwd'>): Record<string, string> {
  const cwd = options.cwd === undefined || options.cwd === '' ? '.' : options.cwd;
  assertRelativeSafe(cwd, 'cwd');
  const entries = (options.sourceRoots ?? ['.']).map((root) => {
    assertRelativeSafe(root, 'sourceRoot');
    return posix.relative(cwd, root) || '.';
  });
  return {
    PYTHONPATH: entries.join(delimiter),
    PYTHONNOUSERSITE: '1',
    PYTHONDONTWRITEBYTECODE: '1',
  };
}

const GUARD_SCRIPT = [
  'import importlib, os, sys',
  'roots = [os.path.realpath(p) for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]',
  'if not roots:',
  '    print("GUARD: PYTHONPATH is empty"); sys.exit(2)',
  'bad = 0',
  'for name in sys.argv[1:]:',
  '    try:',
  '        mod = importlib.import_module(name)',
  '    except Exception as exc:',
  '        print("GUARD: cannot import " + name + ": " + type(exc).__name__); bad = 4; continue',
  '    files = [getattr(mod, "__file__", None)] + list(getattr(mod, "__path__", []))',
  '    files = [os.path.realpath(f) for f in files if f]',
  '    ok = bool(files) and all(any(f == r or f.startswith(r + os.sep) for r in roots) for f in files)',
  '    print("GUARD: " + name + (" OK" if ok else " IMPORTED FROM OUTSIDE THE SNAPSHOT"))',
  '    if not ok: bad = bad or 3',
  'sys.exit(bad)',
].join('\n');

/**
 * Command that fails (exit 2/3/4) unless every package is imported from the
 * snapshot's source roots. Output names packages only, never file paths.
 */
export function buildPythonImportGuardCommand(
  options: PythonSnapshotOptions & { readonly packages: readonly string[] },
): ValidationCommand {
  if (options.packages.length === 0 || !options.packages.every((p) => /^[A-Za-z_][A-Za-z0-9_.]*$/u.test(p))) {
    throw new RangeError('packages must be non-empty valid Python module names');
  }
  return {
    kind: 'custom',
    executable: options.python,
    args: ['-c', GUARD_SCRIPT, ...options.packages],
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    timeoutMs: options.timeoutMs,
    env: pythonSnapshotEnv(options),
  };
}

/** `python -m pytest` pinned to the snapshot via PYTHONPATH. */
export function buildPytestCommand(
  options: PythonSnapshotOptions & { readonly extraArgs?: readonly string[] },
): ValidationCommand {
  return {
    kind: 'test',
    executable: options.python,
    args: ['-m', 'pytest', '-p', 'no:cacheprovider', ...(options.extraArgs ?? [])],
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    timeoutMs: options.timeoutMs,
    env: pythonSnapshotEnv(options),
  };
}
