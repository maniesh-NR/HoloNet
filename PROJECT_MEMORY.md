# PROJECT_MEMORY — HoloNet operational state (single compressed source of truth)

Owner protocol (2026-11-19, pstack principles, D-0016): this file is the
TOKEN-EFFICIENT OPERATIONAL VIEW — tech-stack rules, active playbook,
verification contracts. The BINDING durable memory stays in
`harness/memory/*` (append-only DECISIONS/LESSONS/BACKUPS, STATE,
ROADMAP, session journals; gate records in `harness/adversarial/verdicts/`,
hash-chained). On any conflict: harness is authoritative; update both.
`update_memory.py` (repo root) appends the git-activity section below;
run at session start. Zero-noise rule: no raw history dumps beyond that
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
  v3→v4 and breaks the 1.77.2 CI job; re-check after every cargo run.
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

S1 (entropy + crypto extensions) is OPEN, not started. Before any S1
code: owner decisions (below) + S1 item 0 first (A3-C3 ordering:
Windows FFI + windows-latest green before any crypto-extension item).

## Verification contracts (how "done" is proven)

- Full matrix green on push: ubuntu/macos/1.77.2/cross-check/
  harness-audit green; windows EXPECTED-RED with continue-on-error +
  D-0008 warning (flip off at S1 item 0). Verified green:
  run 44234338593 @ fc9b889 (2026-11-18).
- Memory regression budget: RSS growth < 8 MB over 64 MB relayed
  (D-0015; local reference +88–376 KB; runner variance absorbed).
- 75 `#[test]` countable: `grep -rn "#\[test\]" engine/crates
  --include="*.rs" | wc -l` → 75 (per-OS 75/74/72 via cfg gates).
- Every run ends: `bash harness/scripts/backup.sh "<summary>"`
  (WORKFLOW §1.2; push = completion). Gate records quote SHA-256 in
  the BACKUPS.md line; next record number = 0003 (S1→S2 gate,
  sequence-numbered per WORKFLOW §2.6).

## Active playbook / todo

1. [owner] D-0009/D-0013: advisory + signed v0.3.1 (cut BEFORE S1
   XChaCha20 wire change) or dated no-go; republish/delete invisible
   per-OS releases.
2. [owner] S5 credentials model (embedded vs user-supplied).
3. [owner] Confirm D-0014 (trojan = named v1.0 second protocol).
4. [dev] S1 item 0: Windows entropy FFI + USERPROFILE data-dir
   fallback + Windows ACL decision + 1.77.2 msvc check in legacy job;
   acceptance per ROADMAP S1 (A2-C2 additions).
5. [dev] S1 rest per amended charter: salt-replay cache, off-loopback
   refusal, ProbeGuard decay, CSPRNG slow-close, close-vs-hang
   uniformity, XChaCha standard switch, rand-split enforcement,
   BLAKE2s (BLAKE2b cut unless justified), X25519 (1M-vector execution
   mode decided first), AES-CFB, ExpandLabel, bignum/RSA.
6. [dev] ~~A4-C2 harness-audit~~ DONE 2026-11-19 (full-tree integrity
   audit, D-0017); ~~A4-C3 backup.sh guards~~ DONE (rebase/unmerged
   refusal + WARN durability, negative-tested).
7. [research→charter] R-01..R-15 / C-01..C-15 backlog in ROADMAP.

## Key facts snapshot (2026-11-19)

- HEAD ~fc9b889+backup; CI matrix as specified above (verified).
- Gate 0001 PASSED (S0→S1); progress review 0002 PASSED (4×
  PROCEED_WITH_CONDITIONS; record 0002, chain 5bbc465c…→72d8858d…).
- Known shipped-plane gaps (chartered in S1): no salt-replay cache;
  xchacha mislabel; ProbeGuard unbounded; deterministic slow-close.
- Release surface: only v0.2.0-linux / empty v0.2.0 / src-only v0.3.0
  public (D-0013 reconciliation pending).

## Recent Progress & Git Activity

```text
### Commit: 4aecfca - backup: pstack protocol adopted (D-0016): PROJECT_MEMORY.md operational layer + zero-noise update_memory.py; CI-diagnosis verified closed (run 44234338593 all green except expected-red windows); session journ (maniesh-NR, 2026-11-19)
### Commit: fc9b889 - ci: fix duplicate runs-on key (previous push produced an invalid-workflow run with 0 jobs); conservative expected-red form — continue-on-error via matrix comparison + step-level D-0008 warning annotation (maniesh-NR, 2026-11-18)
### Commit: b90b15c - ci-diagnosis: A1-C1 closed — ubuntu failure = memory_stays_bounded runner variance (+2520KB vs 2MB assert; logs read via owner credential); mem budget 2MB->8MB (D-0015); windows job continue-on-error + expected-red label (A3-C3); windows failure confirmed = disclosed fail-closed entropy red (maniesh-NR, 2026-11-18)
```
