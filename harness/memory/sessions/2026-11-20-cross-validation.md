# Session journal — 2026-11-20 — cross-validation progress review 0003

Run: independent adversarial cross-validation (owner charge: "assign
adversarial roles to teams of agents to analyse the progress so far,
what has worked, issues encountered, research possible
fixes/improvements/new features, update roadmap; extensively document
and backup everything"). Sandbox: Linux, FULL toolchain (rustup
reinstalled, rustc 1.100.0 — fresh-sandbox LESSONS path followed).

## What was done

1. **Baseline re-verified** (WORKFLOW §3.2): repo found on disk @
   `8761716` (post-recycle warm state); 76 mode-only diffs normalized
   (`git restore .`); full `cargo test --workspace` run locally —
   **75/75 green, exit 0**; gate-0001 record tie-in hash verified.
2. **Orphan triage** (first-act discipline, now WORKFLOW §4.4): an
   untracked, non-compiling BLAKE2 RFC 7693 file (353 lines, own KAT
   tests) was found on the tree. Empirically diagnosed: E0425 SIGMA
   scoping ×2; with scoping fixed, 3/5 KATs fail (SIGMA[3]
   transcription defect); its 32 KAT expectations independently match
   OpenSSL (authentic, reusable). Moved OUT of every git tree to
   `/home/z/my-project/blake2-orphan-2026-11-20.rs`; disposition
   recorded as D-0020 (sha truncated in tracked files, full sha in
   the run report, so the D-0017 blob-resolution audit stays exact).
3. **Adversarial panel launched blind** (A1–A4, one parallel batch;
   independent non-voting researcher lane chartered). Model rotation
   attempted (sonnet/opus) — platform served ONE family (x-preview-l)
   for all four; disclosed, not hidden. Researcher failed twice
   (empty responses); the orchestrator ran the research pass directly.
4. **MID-RUN DIVERGENCE FOUND AND RECONCILED** (the run's defining
   event — A4-F3): `git ls-remote` showed origin/main at `cc4564f`,
   12 commits ahead — a PARALLEL SESSION had pushed its own record-0002
   cycle (4× PWC — the same verdict pattern, independently), D-0015
   memory budget, D-0016 pstack, D-0017 harness hardening, and S1
   ITEM 0 (Windows RtlGenRandom FFI, fail-closed, windows-latest
   REQUIRED-green, ledger 76/75/75, D-0018). Clean fast-forward
   (local was an ancestor); all subsequent work authored on the
   merged tree.
5. **Record 0003** written with: verbatim verdict archives (one blob
   per reviewer, A4-C6 compliance), consensus computation (4× PWC, 0
   BLOCK → PASSED), the divergence disclosure, a complete
   condition-by-condition cross-check of this panel's findings vs the
   parallel run's closures, and the residual conditions (applied vs
   carried vs owner-gated). Chain: 72d8858d… (record-0002 blob).
6. **Residual conditions applied** (all verified in the final backup):
   doc claim fixes (TECHNIQUES §12-phantom / RTT-wiring /
   OpenSSL-evidence; RESTORE; ARCHITECTURE counts + FFI wording),
   .gitignore credential shapes, backup.sh untracked-guard +
   live-remote-guard, SANDBOX-RESTORE step 0/0b, WORKFLOW §4.4,
   S1 charter amendments (X25519 decode/ct_eq, CFB mechanical ban,
   read-deadline elevation, ProbeGuard N=1024, deterministic jitter
   seam, ceiling decision, OpenSSL-journal auditability, SIGMA
   warning, baselines → item-0 ledger), Cargo.toml hygiene, LESSONS
   +4, DECISIONS D-0019/D-0020, STATE refreshed, research annex.
7. **Verification**: suite re-run green after the Cargo.toml changes;
   backup.sh syntax-checked (`bash -n`); the new stray-guard
   negative-tested for real (stray file → refusal, exit 1, BACKUPS.md
   untouched, stray removed); stray-guard bypass documented (loud
   --allow-untracked).

## What has worked (owner-charge summary, evidenced)

- The harness itself: caught a real divergence a stale tracking ref
  hid; two independent panels on two sandboxes returned the SAME
  verdict pattern (4× PWC) on the same baseline; every hash tie-in
  held under hostile audit.
- Fail-closed entropy end-to-end (now including Windows via the FFI,
  CI-verified); honest milestone errors re-verified live by A1.
- The parallel session's S1 item 0 landing is the strongest possible
  cross-validation of the charter discipline.

## What did not work / issues encountered

- The researcher SUBAGENT lane failed twice (empty responses) — the
  orchestrator absorbed the lane manually (disclosed in D-0019).
- Model diversity did not materialize (one family for all reviewers).
- The run STARTED on a false premise ("local == origin/main") — the
  exact failure mode A4 predicted; the record discloses it verbatim.

## Gate status

- Progress review 0003: PASSED (no transition authority; S1 charter
  residual-amended). S1 item 0 DONE (D-0018, parallel run).
- Next record: 0004 = the S1→S2 gate (sequence number per D-0011).

## Next (for the next session)

1. OWNER DECISIONS first (D-0013/D-0009 advisory-vs-v0.3.1, deadline
   before S1 DONE, v0.3.1 cut BEFORE the XChaCha wire change; S5
   credentials model; descope ratification D-0014).
2. Continue S1: BLAKE2s (re-derive SIGMA from RFC 7693 §3.3 — the
   orphan's KAT expectations may be reused, its code may not,
   D-0020) → X25519 → AES-CFB → ExpandLabel → bignum/RSA prep →
   server-path hardening backlog → XChaCha wire fix (condition 8) →
   rand-split enforcement (condition 7).
3. Verify `sandbox/latest == origin/main` via ls-remote at session
   start (SANDBOX-RESTORE step 0; backup.sh now enforces it too).

## Backup record for this run

- Final backup: the run's last step; the message quotes record 0003's
  blob SHA-256 (tie-in per WORKFLOW §2.5, machine-checked by the
  harness-audit job). Remote reconciliation verified live before push
  (new backup.sh guard). Post-backup verification (remote HEAD ==
  local HEAD == sandbox/latest) is reported in the final run report.
