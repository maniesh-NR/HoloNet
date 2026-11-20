# PROJECT_MEMORY — HoloNet operational state (single compressed source of truth)

Owner protocol (2026-11-19, pstack principles, D-0016; hooks/gate D-0021): this file is the
TOKEN-EFFICIENT OPERATIONAL VIEW — tech-stack rules, active playbook,
verification contracts. The BINDING durable memory stays in
`harness/memory/*` (append-only DECISIONS/LESSONS/BACKUPS, STATE,
ROADMAP, session journals; gate records in `harness/adversarial/verdicts/`,
hash-chained). On any conflict: harness is authoritative; update both.
`update_memory.py` (repo root) appends the git-activity section below;
run at session start; `--check` gates structure/freshness and
`--install-hooks` installs the pre-/post-commit hooks (D-0021).
Zero-noise rule: no raw history dumps beyond that
section — summarize decisions/files/next-steps only.

## Tech Stack & Architecture Rules (invariants)

- GPL-3.0-or-later monorepo. Engine: pure-std Rust, edition 2021,
  **zero third-party crates (D-0002)**, MSRV **1.77.2** (Win7 SP1 /
  macOS 10.15 floor). 11 crates under `engine/crates/` (holo-util,
  -config, -theme, -proto, -engine, -net, -crypto, -ss, -socks,
  holonetctl, holonetd). Frontends: app_flutter (Android), app_kmp
  (macOS), app_qt (Win/Linux); NDJSON JSON-RPC to holonetd
  127.0.0.1:7977; Material You via one verified Rust color engine.
- **Cargo.lock stays `version = 3`** — modern cargo silently rewrites
  v3→v4 and breaks the 1.77.2 CI job; re-check after EVERY cargo run
  and journal it. (Violated by the 0003 run — the v4 rewrite rode to
  origin/main; found + restored to v3 on 2026-11-20 run 3.)
- `unsafe`: forbidden except the chartered S1 Windows entropy FFI in
  `holo-util/src/rand.rs` (D-0008), fail-closed entropy everywhere.
- Honesty rules: no fake success — non-live drivers return milestone
  errors; test counts only ever quoted from tree/CI evidence.
- Hash-anchored records: verify at BLOB level
  (`git show HEAD:<path> | sha256sum`); `harness/**` is LF-pinned.
- Host (owner Windows PC): no Rust/MSVC — verification = static +
  GitHub API (anonymous for conclusions; cached git credential for
  logs: `git credential fill`, GCM_INTERACTIVE=never, never echo
  token). Copilot cloud sandbox available for real Linux execution.

## Current objective

Protocol re-affirmed 2026-11-20 run 3 (owner instruction): D-0021
memory hooks live; Cargo.lock v3 restored (live regression found on
origin/main); toolchain absent this recycle — 4W fallback, no engine
code changed.

S1 in progress: item 0 DONE 2026-11-20 (Windows FFI + data-dir + A2-C2,
D-0018; windows-latest required-green; run 44668106188). Next: S1
crypto extensions per amended charter (salt-replay cache + off-loopback
refusal first — small, named tests), then BLAKE2s/X25519/ExpandLabel/
bignum-RSA. Owner decisions (below) still pending, non-blocking.

## Verification contracts (how "done" is proven)

- Full matrix green on push: ubuntu/macos/1.77.2/cross-check/
  harness-audit green; windows REQUIRED-green since S1 item 0
  (D-0018 — the expected-red window is CLOSED). Verified green:
  run 44668106188 @ 2dae1ce (2026-11-20; earlier 44234338593 @
  fc9b889, 2026-11-18).
- Memory regression budget: RSS growth < 8 MB over 64 MB relayed
  (D-0015; local reference +88–376 KB; runner variance absorbed).
- 78 `#[test]` countable: `grep -rn "#\[test\]" engine/crates
  --include="*.rs" | wc -l` → 78 (per-OS ledger 76 Linux / 75 macOS /
  75 Windows via cfg gates; D-0018, CI-verified @ 2dae1ce).
- Every run ends: `bash harness/scripts/backup.sh "<summary>"`
  (WORKFLOW §1.2; push = completion). Gate records quote SHA-256 in
  the BACKUPS.md line; next record number = 0004 (S1→S2 gate,
  sequence-numbered per WORKFLOW §2.6).

## Active playbook / todo

1. [owner] D-0009/D-0013: advisory + signed v0.3.1 (cut BEFORE S1
   XChaCha20 wire change) or dated no-go; republish/delete invisible
   per-OS releases.
2. [owner] S5 credentials model (embedded vs user-supplied).
3. [owner] Confirm D-0014 (trojan = named v1.0 second protocol).
4. [dev] ~~S1 item 0~~ DONE 2026-11-20 (D-0018; ledger 76/75/75;
   expected-red window closed).
5. [dev] S1 rest per amended charter: salt-replay cache, off-loopback
   refusal, ProbeGuard decay, CSPRNG slow-close, close-vs-hang
   uniformity, XChaCha standard switch, rand-split enforcement,
   BLAKE2s (BLAKE2b cut unless justified), X25519 (1M-vector execution
   mode decided first), AES-CFB, ExpandLabel, bignum/RSA.
6. [dev] ~~A4-C2 harness-audit~~ DONE 2026-11-19 (full-tree integrity
   audit, D-0017); ~~A4-C3 backup.sh guards~~ DONE (rebase/unmerged
   refusal + WARN durability, negative-tested).
7. [research→charter] R-01..R-15 / C-01..C-15 backlog in ROADMAP.

## Key facts snapshot (2026-11-20, run 3)

- HEAD `ef19a6f` = origin/main (live ls-remote match this run); tree
  clean after core.fileMode=false (94 exec-bit phantom mods, 0
  content changes — SANDBOX-RESTORE 0b).
- RUN-3 FIX: Cargo.lock v3→v4 silent rewrite by the 0003 run's
  modern-cargo test re-run (was LIVE on origin/main; breaks the
  1.77.2 job) — v3 restored pre-push; LESSONS records the
  re-check-after-ANY-cargo-run rule.
- Gate 0001 PASSED (S0→S1); progress review 0002 PASSED (4×
  PROCEED_WITH_CONDITIONS; record 0002, chain 5bbc465c…→72d8858d…);
  cross-validation 0003 PASSED (4× PWC, 0 BLOCK; residuals applied
  or carried). Next record: 0004 = the S1→S2 gate.
- Tests: ledger 76 Linux / 75 macOS / 75 Windows (CI-verified run
  44668106188 @ 2dae1ce); static 78 re-verified this run; anonymous
  API rate-limited → evidence = engine diff vs 2dae1ce (Cargo.toml
  hygiene + the now-fixed lockfile line only). Toolchain ABSENT this
  sandbox (recycle) — 4W fallback, no engine code changed this run.
- Memory hooks live (D-0021): --check gate + --install-hooks
  (pre-commit refresh+stage; post-commit read-only warn).
- Known shipped-plane gaps (chartered in S1): no salt-replay cache;
  xchacha mislabel; ProbeGuard unbounded; deterministic slow-close.
- Release surface: only v0.2.0-linux / empty v0.2.0 / src-only v0.3.0
  public (D-0013 reconciliation pending).

## Recent Progress & Git Activity

```text
### Commit: 2421428 - backup: pstack re-affirm: memory hooks D-0021 + --check gate; PROJECT_MEMORY refreshed; Cargo.lock v3 restored (live v4 regression found on origin/main); 4W fallback static 78; engine unchanged vs 2dae1ce (maniesh-NR, 2026-11-20)
### Commit: ef19a6f - backup: cross-validation 0003 PASSED (4x PWC, panel consensus; mid-run remote divergence reconciled); residual conditions applied; tests 76 green; record sha256=2ad6fe71c58a8e6c39001966eab1d3c80a43e62b250601c (maniesh-NR, 2026-11-20)
### Commit: cc4564f - backup: S1 item 0 DONE + verified: Windows entropy FFI (SystemFunction036) fail-closed; windows-latest REQUIRED-green; ledger 76/75/75 (run on 92b4b15 success); A3-C3 window closed; D-0018; THREAT-MODEL G shi (maniesh-NR, 2026-11-20)
```
