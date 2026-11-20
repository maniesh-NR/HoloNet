# Session journal — 2026-11-20e: S1a closing (mechanical rand-split enforcement)

## Restore ritual (runbook 0 / 0b / 2 / 3)

- Warm path: repo found on disk; `git ls-remote` == HEAD == `1c82ad4`
  (remote reconciliation: main=1c82ad4 latest=1c82ad4 match=Y — the
  run-5 push fully landed, CI 44703200189 all-green 86/85/85).
- fileMode guard re-applied; hooks present; memory `--check` PASSED
  (lag 1); `update_memory.py` refresh run at session start.
- Toolchain ABSENT again (second recycle wipe of ~/.cargo) → rustup
  reinstall per SANDBOX-RESTORE step 2: **rustc 1.100.0**.
- Identity verified (maniesh-NR / noreply email) — persisted in-repo.

## Baseline verification (before any code change)

- `cargo test --workspace`: **86/86 green** — matches the CI-verified
  run-5 ledger exactly. Cargo.lock v3 confirmed before work started.

## Investigation (protocol: inspect first)

- Condition located: gate-0001 A2 round-2 **[C3]** — "enforce the
  security/non-security split mechanically (e.g. gate fill/bytes/hex/
  alnum behind #[doc(hidden)] or a dedicated non-security module, or
  add a workspace grep-audit test asserting no rand::{fill,bytes,hex,
  alnum} call outside holo-config IDs/tests) — verifiable by compile
  failure or the audit test." = ROADMAP S1 item 7.
- Call-site map (whole workspace): security `os_*` = holo-ss:918
  (slow-close CSPRNG draw seam, D-0023), holo-ss:1067 (random_salt,
  fail-closed), holo-engine:78 (os_hex(24) auth token). Non-security =
  **exactly one**: holo-config:131 `rand::hex(8)` profile IDs — the
  consumer the gate verdict itself classified. Zero weak calls in any
  test module.
- **Re-export finding:** holo-util/src/lib.rs line 10 had
  `pub use rand::{bytes, fill};` — `holo_util::fill` was callable
  WITHOUT naming `rand::`. A module-only split would have been
  silently defeated by it (became a LESSONS entry + part of D-0024).

## Shipped (D-0024, three layers)

1. Weak PRNG (`fill`/`bytes`/`hex`/`alnum` + COUNTER/splitmix64/
   next_u64) moved into `rand::nosec`, `#[doc(hidden)]`, loud docs
   (sources splitmix64-seeded time^pid^counter — predictable by design).
2. BOTH re-export paths closed: rand root names gone (old call sites
   are E0425) and the crate-root re-export deleted, with a why-comment.
3. Named audit test `rand_split_audit_no_weak_prng_outside_allowlist`
   (holo-util/src/rand.rs, `#[cfg(test)] mod rand_split_audit`):
   walks the engine root (CARGO_MANIFEST_DIR ancestors; skips
   target/hidden; floor assert ≥15 files found — 17 today), matches
   `nosec::`, `rand::fill`, `rand::bytes`, `rand::hex`, `rand::alnum`,
   `use rand::{`; allowlist = definition file + holo-config profile-ID
   consumer (+ `/tests/` integration dirs per the verdict's "outside
   holo-config IDs/tests"); failure message carries file:line +
   remediation (os_* or a justified allowlist extension + DECISIONS
   record).

## Negative evidence (both halves demonstrated live)

- Planted scratch `crates/holo-ss/src/zz_scratch_violation.rs` (orphan,
  never in a mod tree — cargo does not compile it; the audit walks it,
  which is the property demonstrated) → audit FAILED with
  `...zz_scratch_violation.rs:2: matched "rand::fill"` → removed.
- `sed`-reverted the holo-config call to `holo_util::rand::hex(8)` →
  `cargo check -p holo-config` → `error[E0425]: cannot find function
  hex in module holo_util::rand` → reverted to `nosec::hex(8)`, check
  Finished clean.

## Verification outcome

- Final suite: **87 green / 0 failed** (86 + 1; holo-util 7→8).
- Static `#[test]` count: **89** (88 + 1; audit has no cfg gates →
  +1 on all three OSes; expected CI ledger 87 Linux / 86 macOS /
  86 Windows — socks redirect reconciliation unchanged).
- Cargo.lock v3 HELD post-run (no Cargo.toml changes → no
  regeneration risk; verified anyway per the invariant).
- Known pre-existing warning only: `SaltCache::len` unused outside
  tests (run-4 artifact, already journaled run 5).
- The one weak consumer holo-config/src/lib.rs:131 now reads
  `holo_util::rand::nosec::hex(8)` with a never-for-security comment.

## Docs updated

ROADMAP S1 item 7 (DONE, both halves + evidence), THREAT-MODEL §G
(splitmix64 line flipped to mechanically-enforced + honest residual),
DECISIONS D-0024, LESSONS (+2: re-export closure; audit tests must be
negatively demonstrated), STATE (run-6 header, run-5 preserved),
PROJECT_MEMORY (objective/playbook/contracts/snapshot; run-5 push
line re-attributed), this journal. README/ARCHITECTURE counts left at
the CI-verified 86 — the 87 citation rides CI verification of the
next push (same honesty pattern as runs 4–5).

## Next

1. Owner: D-0009/D-0013 (advisory vs v0.3.1 — BEFORE the XChaCha wire
   change), S5 credentials model, D-0014; rotate the uploaded PAT.
2. S1b/S1c: BLAKE2s (orphan at /home/z/my-project/blake2-orphan-2026-
   11-20.rs reusable ONLY after re-derivation from RFC 7693 + its own
   KAT pass, D-0020) → X25519 (1M-vector execution mode decided
   first) → AES-CFB (its CI grep-audit follows THIS audit's pattern)
   → ExpandLabel → bignum/RSA. XChaCha wire fix stays owner-blocked.
3. CI verification of the 87-tree rides the next push; memory-gate lag
   self-heals at the backup commit.

## Backup

- Final step: `bash harness/scripts/backup.sh` with the run summary;
  push auth via the env-var credential helper if the token is present
  in the environment this session — otherwise the honest FAILED
  marker commits locally per the durability rule (outcome: BACKUPS.md
  tail).

## Verification outcome (post-push, owner PAT)

- Push chain this run: backup 652c346 + FAILED marker 5382c5f →
  manual retry push with the env-var credential helper LANDED
  1c82ad4..5382c5f → LANDED line + closure commit 13983d5 → in-script
  push failed honestly (no terminal) → FAILED marker 937554f → retry
  LANDED 5382c5f..937554f (the first retry attempt hit "Invalid
  username or token" because the env var had been dropped between
  shell sessions — re-loaded from the upload, NOT a token problem;
  journaled for the record). Final HEAD = 937554f.
- **CI run 44728988531 @ 937554f: SUCCESS, 6/6 jobs** (ubuntu, macos,
  windows, cross-check, 1.77.2, harness-audit). The 1.77.2 canary
  green confirms Cargo.lock v3 held through CI.
- **Per-OS ledger (parsed from job logs, socks redirect reconciled):
  87 Linux / 86 macOS / 86 Windows** — visible sums 77/76/76, zero
  FAILED lines, + the redirected holo-socks 10 per OS (its
  `> socks-test.log` step gates on `test result: ok` and the job is
  green). Exactly the predicted counts (86/85/85 + 1 ungated audit
  test on every OS). README + ARCHITECTURE + PROJECT_MEMORY + STATE
  citations updated to the verified numbers.
- BACKUPS.md carries the LANDED lines for both retry pushes; the
  FAILED markers document the in-script attempts honestly.
- Owner action requested: rotate the PAT (it transited chat/upload
  twice; recommended after every session that uses it).
