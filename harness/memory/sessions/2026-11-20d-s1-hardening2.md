# Session journal — 2026-11-20 (run 5): backup push LANDED + S1 hardening second pass (ProbeGuard decay, jittered slow-close, A2-F6 deadline)

## Goal
Land the run-3/4 backups with the owner-supplied token, re-verify CI,
record the per-OS ledger deferred from run 4, then continue the S1
amended charter: ProbeGuard decay (N=1024), CSPRNG-jittered slow-close
with an explicit ceiling (A3-C10), and the A2-F6 read-deadline
elevation.

## Session start
- update_memory.py refresh + --check PASS (lag 0; hooks live).
- Tree clean at d9e137e; Cargo.lock v3; core.fileMode false.

## Push landed (the session's first deliverable)
- Owner supplied the PAT as an upload. Used via env var
  `HOLO_GITHUB_TOKEN` + inline credential helper ONLY — never echoed,
  never written to a file, never baked into the remote URL or any
  commit. (The upload stays in upload/ untouched; recommend the owner
  rotate it after this session since it transited chat.)
- `git push origin main`: ef19a6f..d9e137e — 4 commits (run-3 pstack
  backup 2421428, run-4 hardening 0945325, FAILED markers 203f965 +
  d9e137e). The durability rule worked as designed: the FAILED markers
  rode along honestly.
- **CI run 44700103379 @ d9e137e: SUCCESS, 6/6 jobs** (ubuntu, macos,
  windows, cross-check, 1.77.2, harness-audit). Also confirming
  evidence: run 44684342580 @ ef19a6f had FAILED — the Cargo.lock v4
  regression exactly as predicted (1.77.2 canary logic held).
- **Per-OS ledger (deferred from run 4, now recorded): 83 Linux /
  82 macOS / 82 Windows** for the 83-tree. Parsed from job logs with
  one reconciliation: ci.yml redirects holo-socks output to
  socks-test.log, so naive "test result" sums undercount by 10
  (73 visible vs 83 real on Linux). Deltas vs Linux: macOS/Windows run
  5 of 6 integration tests (1 Linux-only, D-0018), Windows holo-util 8
  vs 7 (entropy test sets differ per OS), Windows holo-config 9 vs 10
  (1 cfg-gated). README badge/counts + ARCHITECTURE updated to the
  CI-verified numbers (76/75/75 → 83/82/82, run id cited).

## Baseline verification (before any code change)
- Toolchain: ~/…/tools/cargo was wiped by the recycle but ~/.cargo
  persisted (rustc 1.100.0 — same as run 4). PATH via ~/.cargo/bin.
- `cargo test --workspace`: **83/83 green** (per-crate sums re-checked).
- Cargo.lock v3 post-run: HELD.

## Done (S1 items — all three remaining server-path hardening items)
1. **ProbeGuard decay (A1-F8, N=1024):** `PROBE_GUARD_PEER_CAP = 1024`
   in holo-net; `on_failure` on a NEW peer at cap decays the stalest
   peer (min `last`) from BOTH maps; `tracked()` observer added. Named
   test `probe_guard_peer_map_decays_at_cap`: cap held under overflow,
   fresh peers survive, exactly the stale batch decays (6), aged-out
   re-admission costs one more stale slot (the honest bound),
   on_success still clears. Assertion-arithmetic bug caught by the test
   itself (zeros accounting: re-admission −1, slot eviction +1, net 0)
   — fixed the expectation, not the code.
2. **CSPRNG-jittered slow-close (A3-C10/F8):** `SLOW_CLOSE_MAX = 2 s`
   and `AUTH_READ_DEADLINE = 10 s` as named constants; `ServePolicy`
   (Copy struct) carries both, `serve_conn`/`accept` gained the param —
   all call sites updated (4 in holo-ss tests + engine integration).
   `slow_close_delay(backoff, ceiling, draw)` — full jitter uniform
   over `[0, min(backoff, ceiling)]`, draw parameterized (the
   `os_fill_at` seam pattern): production `os_fill`, tests seeded
   deterministic LCG. Entropy failure → Err → serve_conn falls back to
   the capped deterministic backoff (no panic; degrades to pre-S1
   behavior). The accidental 120 ms clamp REMOVED. Named test
   `slow_close_jitter_seeded_deterministic`: same seed reproduces, two
   seeds with identical failure counts differ (no live-draw flake),
   ceiling enforced over 64 seeds, zero-backoff stays zero, entropy
   error surfaces.
   **FOUND-BY-INSPECTION DEFECT (fixed):** the old code locked the
   ProbeGuard Mutex and slept INSIDE the lock — every concurrent
   connection serialized behind one probe's delay; with the ceiling
   raised to 2 s that would have been N×2 s. The lock now covers only
   the bookkeeping.
3. **A2-F6 read deadline:** `accept` sets the read timeout for the
   ENTIRE unauthenticated phase (salt + first chunk — both were
   unbounded `read_exact` hang points) and clears it the moment auth
   completes (idle tunnels unaffected). Deadline errors keep the
   platform kind (WouldBlock/TimedOut) internally but the attacker-
   observable behavior is uniform: delayed opaque close, no relay, no
   upstream dial. Named test `silent_after_valid_length_times_out`:
   short injected policy (300 ms/100 ms), two scenarios (valid length
   header then silence; connect then silence), `recv_timeout(5 s)` as
   the hang guard (pre-fix this test would fail by hanging), no upstream
   dial asserted.

## Verification
- `cargo test --workspace`: **86/86 green on Linux** (83 + 3: holo-net
  9→10, holo-ss 9→11; per-crate sums re-checked from runner output).
- Static `#[test]` count 88 (85+3).
- Cargo.lock v3 invariant post-run: HELD (no Cargo.toml change).
- Pre-existing warning noted, NOT introduced this run: `SaltCache::len`
  never used outside tests (run 4 artifact) — left untouched, recorded
  here for hygiene.
- CI verification of the 86-tree rides the next push (same honesty
  pattern as run 4).

## Docs updated
ROADMAP (three items annotated DONE with named tests + evidence;
remaining S1 crypto items named as next runs' work), THREAT-MODEL §C
(three entries flipped to DEFENDED with honest residuals: timeline
differing, decayed-peer re-admission, IP-rotation window), STATE (run-5
header, run-4 preserved), DECISIONS D-0023 (three recorded decisions +
the lock fix), LESSONS (3 run-5 entries: lock-across-sleep audit rule,
invariant-over-prediction for deterministic tests, CI log redirect
reconciliation), README + ARCHITECTURE (CI-verified counts), PROJECT_MEMORY,
this journal.

## Backup
- backup.sh with the D-0022-fixed guard; push with the env-var token
  (same hygiene as above); outcome: BACKUPS.md tail.

## Next
1. Owner: D-0009/D-0013 (advisory vs v0.3.1 — BEFORE the XChaCha wire
   change), S5 credentials, D-0014; rotate the uploaded PAT.
2. S1 continues: XChaCha wire fix + rand-split enforcement (S1a
   closing items), then BLAKE2s → X25519 → AES-CFB → ExpandLabel →
   bignum/RSA (S1b/S1c). The BLAKE2 orphan at
   /home/z/my-project/blake2-orphan-2026-11-20.rs is reusable material
   per WORKFLOW's orphan rule ONLY after re-derivation from RFC 7693 +
   its own KAT pass (record-0003 A3-C8/F10).

## Verification outcome (post-push)
- Push chain this run: ef19a6f..d9e137e (run-3/4 backlog) → CI
  44700103379 all-green 6/6, ledger 83/82/82 recorded → run-5 backup
  4ddd081 (backup.sh in-script push failed honestly: no terminal for
  the credential prompt → FAILED marker 7a00fcc committed per the
  durability rule) → manual retry push with the env-var credential
  helper carried d9e137e..7a00fcc → ledger closure commit f433de4.
- **CI run 44703200189 @ f433de4: all-green, 6/6 jobs. Per-OS ledger
  for the 86-tree: 86 Linux / 85 macOS / 85 Windows** (visible sums
  76/75/75 + the redirected holo-socks 10 — reconciled per the
  LESSONS entry). README badge/counts + ARCHITECTURE + ROADMAP
  citations updated to the verified numbers.
