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

S1 server-path hardening RUN 4 (2026-11-20): A2-C1 SaltCache + A3-C4
loopback-only bind SHIPPED, local 83-green, D-0022 backup retry fix;
CI verification + per-OS ledger + README counts ride the next push.

S1 in progress: item 0 DONE 2026-11-20 (Windows FFI + data-dir + A2-C2,
D-0018; windows-latest required-green; run 44668106188). Next per the
amended charter: ProbeGuard decay (N=1024), CSPRNG-jittered slow-close,
close-vs-hang read-deadline, XChaCha wire fix, rand-split enforcement,
then BLAKE2s/X25519/AES-CFB/ExpandLabel/bignum-RSA. Owner decisions
(below) still pending, non-blocking.

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
5. [dev] ~~S1 rest per amended charter: salt-replay cache, off-loopback
   refusal~~ DONE 2026-11-20 run 4 (A2-C1 SaltCache cap-1024 FIFO +
   A3-C4 loopback-only bind w/ HOLONET_PROXY_LISTEN_ANY override; +7
   named tests, local 83-green); remaining: ProbeGuard decay, CSPRNG
   slow-close, close-vs-hang uniformity, XChaCha standard switch,
   rand-split enforcement, BLAKE2s (BLAKE2b cut unless justified),
   X25519 (1M-vector execution mode decided first), AES-CFB, ExpandLabel,
   bignum/RSA.
6. [dev] ~~A4-C2 harness-audit~~ DONE 2026-11-19 (full-tree integrity
   audit, D-0017); ~~A4-C3 backup.sh guards~~ DONE (rebase/unmerged
   refusal + WARN durability, negative-tested).
7. [research→charter] R-01..R-15 / C-01..C-15 backlog in ROADMAP.

## Key facts snapshot (2026-11-20, run 4)

- Run 4 (S1 hardening): local suite **83 green** (rustc 1.100.0,
  reinstalled this run; baseline 76/76 re-verified before changes);
  static 85; Cargo.lock v3 HELD post-run (no Cargo.toml change → no
  regeneration; lesson refined: the hazard fires on lockfile
  regeneration only).
- SHIPPED: holo-ss SaltCache (A2-C1) + holo-socks loopback-only bind
  (A3-C4, override HOLONET_PROXY_LISTEN_ANY=1) — named tests green;
  ROADMAP + THREAT-MODEL §A/§C annotated/flipped with the honest
  residual (1024-connection eviction bound).
- Harness: D-0022 backup.sh retry-deadlock fixed (ancestor-check guard;
  scenarios A–E verified); push auth STILL absent — per-OS ledger,
  README/ARCHITECTURE counts deferred to the CI-verified push.
- Gate 0001 PASSED (S0→S1); progress review 0002 PASSED (4×
  PROCEED_WITH_CONDITIONS; record 0002, chain 5bbc465c…→72d8858d…);
  cross-validation 0003 PASSED (4× PWC, 0 BLOCK; residuals applied
  or carried; A2-C1/A3-C4 now closed by run 4). Next record: 0004 =
  the S1→S2 gate.
- Known shipped-plane gaps (chartered in S1, post-run-4): ~~no
  salt-replay cache~~ (closed run 4); ~~off-loopback bind~~ (closed
  run 4); xchacha mislabel; ProbeGuard unbounded; deterministic
  slow-close; close-vs-hang distinguisher.
- Release surface: only v0.2.0-linux / empty v0.2.0 / src-only v0.3.0
  public (D-0013 reconciliation pending).

## Recent Progress & Git Activity

```text
### Commit: 0945325 - backup: S1 hardening run 4: A2-C1 SaltCache (cap-1024 FIFO, opaque replay refusal, named test) + A3-C4 loopback-only proxy_listen bind (HOLONET_PROXY_LISTEN_ANY override, named tests); suite 76->83 local gree (maniesh-NR, 2026-11-20)
### Commit: 203f965 - backup: FAILED 2026-11-20T07:13:21Z (push did not land) (maniesh-NR, 2026-11-20)
### Commit: 2421428 - backup: pstack re-affirm: memory hooks D-0021 + --check gate; PROJECT_MEMORY refreshed; Cargo.lock v3 restored (live v4 regression found on origin/main); 4W fallback static 78; engine unchanged vs 2dae1ce (maniesh-NR, 2026-11-20)
```
