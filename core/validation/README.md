# core/validation — ProofPatch Validation, Security & Quality (Member 5)

Proves **which checks actually ran against which exact staged snapshot**.

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Module structure + TypeScript types (+ review corrections) | done |
| 2 | Temp snapshot, SHA-256 hashing, runner | done |
| 3 | Freshness ledger, aggregation, JSON store | done |
| 4 | Member 4 integration | **blocked** on the real WorkspaceView contract (provisional adapter in use) |
| 5 | Cancellation, failures, conflicts | done (runner, ledger, `ValidationSession`) |
| 6 | Semgrep (parsed findings) + secret checks | done; Semgrep is optional and reported `not_run` when missing |

Entry point for Member 3/4: `ValidationSession.validate(...)` (see below).
Member 4 integration remains blocked on the real WorkspaceView contract.

## Layout

```
src/
  types/      Type definitions (Phase 1)
  runner/     Controlled test/lint/build/custom execution
  context/    Keyed validation command context fingerprint
  snapshot/   Canonicalization, SHA-256 fingerprint, safe temp materialization
  ledger/     Freshness transitions, aggregation, JSON-persistable store
  report/     ValidationReport builder (ran vs not run)
  orchestrator/ ValidationSession: snapshot -> run -> ledger -> report
  python/     Flask/pytest helpers + import-from-snapshot guard
  security/   Optional Semgrep adapter + secret scanner
tests/        Unit + integration/runtime tests
```

## Interface status

**Independent (owned by Member 5):**
`CheckKind`, `ExecutionStatus`, `ValidationCommand`, `RecordedCommand`,
`OutputSummary`, `ValidationRunResult` (one type per status: `PassedRunResult`,
`FailedRunResult`, `TimedOutRunResult`, `SpawnErrorRunResult`, `CancelledRunResult`,
`SnapshotChangedRunResult`), `NotRunCheck`, `FreshReport` / `NonFreshReport`
(`ValidationReport`), `FreshnessState`, `StaleReason`, `LedgerEntry` (+ its five
variants), `LedgerRecord`.

**PROVISIONAL (depend on Member 4, `src/types/provisional.ts`):**
`StagedFile`, `StagedSnapshot`, `StagedSnapshotSource`, `SnapshotFingerprint`
(string format), `DiskConflictReport`.
These are consumer-side guesses, not Member 4's WorkspaceView API.

## Snapshot model limitations (provisional)

`StagedFile` is `{ path, content: string }` only. It cannot express:
**deleted files**, **renamed files**, **binary files**, **file modes** (executable
bit, symlinks), or declared encoding / line endings. Consequences: a deletion-only
or mode-only change would not change a fingerprint, and binary files cannot be
hashed or validated through this type. Reports must not claim exact-snapshot
validation for changes the type cannot express. Details are in
`src/types/provisional.ts`. This stays provisional until Member 4's real
WorkspaceView contract is agreed.

Snapshot paths use NFC Unicode normalization. Decomposed path forms are
rejected rather than rewritten, preventing normalization-equivalent names from
colliding on target filesystems.

## Check status vs overall status

| Level | Type | Values |
| --- | --- | --- |
| One check (one command) | `ExecutionStatus` | passed, failed, timed_out, spawn_error, cancelled, snapshot_changed |
| Whole snapshot / report | `FreshnessState` | FRESH, STALE, FAILED, CONFLICT, NOT_RUN |

A snapshot is never reported FRESH if any required check failed, timed out,
could not start, was cancelled, or was not performed. Types enforce this for
`FreshEntry` and `FreshReport` (see `tests/types/ledger.typecheck.ts`).
`aggregateValidationResults` computes the overall state and `buildValidationReport`
checks at runtime that FRESH is backed only by passed runs of the report's own snapshot.

Ledger mapping decided in Phase 1 (confirm in review): `failed`, `timed_out` and
`spawn_error` -> FAILED; `cancelled` and `snapshot_changed` are inconclusive ->
NOT_RUN (kept only as `lastAttempt`); only `passed` -> FRESH.

`aggregateValidationResults(entries, expectedSnapshot?, requiredKinds?)` accepts
an optional required check-kind set. When supplied, omitted kinds are exposed
through `missingRequiredKinds` and prevent an otherwise-FRESH result from
becoming FRESH; the result is `NOT_RUN` unless another present entry has a
higher-severity state. Duplicate required kinds are ignored and the exposed
missing list is sorted deterministically. Omitting `requiredKinds` preserves the
legacy aggregation behavior.

## Open questions for Member 4

1. How do I read the full staged content (all files, original + accepted hunks)? Sync or async?
2. Do you already define a snapshot identity/hash? If so, what exact format and canonicalisation?
3. How are deleted, renamed and binary files represented?
4. Are paths repo-relative with `/` separators?
5. How do you notify me that staged content or accepted hunks changed?
6. Who detects disk conflicts, and what do you hand me?
7. Do you provide the base commit?

### Required integration contract

Phase 4 remains **BLOCKED** until Member 4 supplies an implementation-owned
`WorkspaceView` contract. The adapter must provide one immutable, consistent
snapshot view for the complete staged state, an authoritative snapshot identity
or the canonical inputs needed to derive it, and explicit ownership/lifetime
rules for the view and any temporary resources.

The contract must define added and modified files, deleted files, and renames
without ambiguity; represent binary content without lossy text decoding; and
state whether file modes, executable bits, symlinks, and other filesystem
metadata affect snapshot identity or materialization. It must also expose
base-revision information and disk-conflict information, including conflicting
paths and when conflicts invalidate a view. Validation must consume the exact
same immutable staged view for fingerprinting, materialization, and execution,
and must not read the user's normal workspace as a substitute.

## Design decisions (Phase 1)

- Commands are `executable + args[]`, never a shell string.
- Executables must be absolute paths. Callers must resolve PATH-based names
  before invoking validation so the fingerprint identifies the selected binary.
- Public evidence records environment variable **names** only, never values;
  context fingerprints include allowlisted values without exposing them.
- `LedgerEntry` is a discriminated union, so FRESH requires evidence by construction.
- One ledger entry models one (snapshot, command) pair; `aggregateValidationResults` combines them into one overall state.

## Phase 2 execution-context and materialization rules

Context fingerprints use a versioned, length-prefixed byte encoding authenticated
with a private HMAC-SHA-256 key. The key must be stable within the validation
service and is never recorded in evidence or logs. The encoded fields are the
check kind, executable, argument list, snapshot-relative working directory,
timeout, and an explicitly supplied environment allowlist with values.
Timeouts are limited to Node's maximum supported timer delay
(`2_147_483_647` milliseconds); larger values are rejected.
The allowlist is for non-secret configuration only; credentials and other
secrets must not be placed in it. Environment values affect the keyed
fingerprint but are not publicly recoverable without the private key.
Environment names are canonicalized case-insensitively and ambiguous duplicates
are rejected, matching Windows environment semantics. The API never reads
inherited `process.env`, and error messages never include environment values.

`materializeSnapshot` creates a private temporary directory, writes the
provisional text contents as exact UTF-8 bytes, and verifies the resulting
files against the manifest before returning. It rejects traversal, Windows
reserved/unsafe names, case-insensitive path collisions, symlinks, special
files, missing files, unexpected files/directories, and modified contents.
Callers must invoke the returned `cleanup`; verification after cleanup fails
explicitly. On Linux, materialization and verification traverse parent directories through
opened no-follow handles and use handle-relative file creation/reads, preventing
parent symlink swaps from redirecting writes or verification. Node does not
provide equivalent atomic no-follow directory traversal for Windows reparse
points/junctions, so concurrent mutation of the private root cannot be fully
prevented on Windows; detectable reparse entries are still rejected.

The provisional `StagedFile` model still cannot represent deletions, renames,
binary data, file modes/symlinks, or encoding/line-ending metadata. These
operations are therefore not reconstructed or claimed as exact validation.
Member 4's eventual WorkspaceView contract must replace or confirm this
adapter before integration.

## Phase 5 failure and cleanup behavior

The runner distinguishes failed exit codes, spawn errors, timeouts,
cancellation, and snapshot-integrity changes. Timed-out and cancelled commands
are never passed as successful evidence; the ledger maps them to FAILED or
NOT_RUN according to the existing status rules. Every runner attempt owns and
cleans its supplied materialization, including successful, failed, cancelled,
and pre-execution snapshot-integrity paths. A cleanup failure is surfaced as a
`ValidationRunnerError` rather than silently ignored. The original workspace is
never used as the command working directory.

## Phase 6 security checks

`scanSecrets` scans the provisional staged text model for common private-key,
AWS access-key, GitHub-token, bearer-token, and credential-assignment patterns.
It returns a snapshot fingerprint and redacted finding locations only; secret
values are never included in findings. Placeholder examples are ignored to
reduce false positives. This is a conservative detector and does not
guarantee discovery of every secret.

`runSemgrepScan` is an optional adapter around the existing controlled runner.
It resolves `semgrep` without a shell, runs `semgrep scan --config auto --error
--json .` against the materialized snapshot, and preserves the runner's
timeout, cancellation, output-limit, snapshot-integrity, and cleanup behavior.
If Semgrep is unavailable, the result is explicitly `not_run`; it is never
reported as passed. Install Semgrep separately and make it discoverable on
`PATH`. Semgrep is not a package dependency or a mandatory validation check.

## Step 6 command runner

`runValidationCommand` accepts a `ValidationCommand`, an existing
`MaterializedSnapshot`, and a `ValidationRunnerOptions` dependency object. It
uses `spawn` with `shell: false`, passes executable and arguments separately,
uses only the explicitly supplied allowlisted environment, verifies the
snapshot before and after execution, bounds and redacts output, supports
timeouts and cancellation, and returns the existing typed run-result union.
Output redaction masks exact supplied values and their common Base64/hex
representations for sufficiently long values; it is not a general detector for
arbitrary transformations.
The runner cleans up the supplied materialization after every attempt.

The caller must provide a `FingerprintKeyProvider` backed by a stable private
HMAC key for the installation/project scope. The runner never generates,
persists, logs, returns, or writes this key. Missing or invalid keys fail
closed. The caller must reuse the same provider/key for repeated runs whose
context fingerprints need to compare equal; persistence and key lifecycle are
intentionally outside Member 5 until an integration owner is defined.

The runner does not inherit `process.env`; required variables, including `PATH`
when needed, must be explicitly supplied and allowlisted. On POSIX systems
materialized file verification uses `O_NOFOLLOW`; Node does not provide an
equivalent no-follow guarantee for Windows reparse points, so concurrent
mutation of the private root remains a documented Windows limitation.

Timeout and cancellation terminate the process tree: POSIX commands run in a
detached process group and the group is killed by negative process-group ID;
Windows uses the system `taskkill /T /F` operation and keeps `shell: false`.
The runner waits for the tree-termination operation to settle, records a
generic termination error on timed-out/cancelled results if that operation
fails, and force-closes remaining output pipes after a bounded grace period so
inherited grandchild pipes cannot make a run hang indefinitely. On POSIX,
`ESRCH` is treated as already terminated; other group-kill errors fall back to
direct-child termination but remain reported as incomplete tree termination.
Windows tree termination depends on the availability and permissions of the
system `taskkill` utility.

## Orchestrator, report and ledger storage

```ts
const session = new ValidationSession({ fingerprintKeyProvider, environmentAllowlist, store });
const { report, runs, security } = await session.validate(snapshotOrSource, checks, { signal, security: { secrets: true } });
```

- Every check runs in its own temp copy of the exact snapshot; the real workspace is never the cwd.
- Passing a `StagedSnapshotSource` re-reads the snapshot around each check. If it moved, evidence is demoted to STALE and the remaining checks are listed as not run (`snapshot_changed_during_validation`).
- `reportConflict(...)` makes `validate` run nothing and report CONFLICT until `clearConflict()`.
- `report.checksRun` holds only real runs; `report.checksNotRun` lists everything skipped with a reason. A required check that did not run blocks FRESH. `formatValidationReport` prints both lists.
- Security results are returned beside the freshness state: a finding is not a failed test and a missing scanner is not a pass.
- `LedgerStore` keeps one record per check (`checkIdOf`: kind, executable, args, cwd). `entriesFor(snapshot)` never shows another snapshot's evidence as current. `saveLedgerStore` / `loadLedgerStore` persist JSON atomically; loading rejects a FRESH/FAILED entry that its own evidence does not back. **Where the file lives (and the fingerprint key lifecycle) is the integration owner's decision**; this module only provides the functions.

## Flask / Python

`pythonSnapshotEnv` sets `PYTHONPATH` to RELATIVE entries (resolved against the temp snapshot cwd, so the context fingerprint is the same on every run), plus `PYTHONNOUSERSITE` and `PYTHONDONTWRITEBYTECODE`. `buildPythonImportGuardCommand` imports the named packages and fails (exit 3/4) unless every module file is inside the snapshot, which catches editable or global installs. Run it before `buildPytestCommand` and do not trust pytest results if the guard fails. Add `PYTHON_ENV_ALLOWLIST` to `environmentAllowlist` and pass an absolute interpreter path. pytest runs with `-p no:cacheprovider` because stray files in the snapshot would be reported as `snapshot_changed`.

## Semgrep

`runSemgrepScan` normalizes `--json` output into `findings` (`ruleId`, `path`, `line`, `column`, `severity`, redacted `message`; matched source lines are dropped). `outcome` is `not_run` | `clean` | `findings` | `error`. Semgrep exits non-zero when it finds something, so findings are parsed from both `passed` and `failed` runs. `--config auto` needs network access to fetch rules; pass `config` for an offline rules path.

## Commands

```
npm install
npm run typecheck   # src + compile-time type tests in tests/types
npm test            # build + run all tests
npm run build
```

The type tests are compile-time (`@ts-expect-error`), and Phase 2 adds runtime
tests for canonicalization, hashing, context fingerprints, materialization,
runner lifecycle, ledger freshness, and security scanning.

Requires Node.js 22.14+. Dev dependencies only: `typescript`, `@types/node`.
