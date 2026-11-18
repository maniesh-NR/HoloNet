# HoloNet State Snapshot

Last updated: 2026-11-17 (UTC) — progress review 0002 run (adversarial
panel + forensics + research; record
`harness/adversarial/verdicts/0002-progress-review.md`, CONSENSUS 4×
PROCEED_WITH_CONDITIONS). First run on the owner's WINDOWS host (Git
Bash; no Rust toolchain, no MSVC — all verification this run was static
analysis + public GitHub API; nothing was executed locally).

- Restored from GitHub `maniesh-NR/HoloNet` @ `8761716` (branch `main`,
  = `sandbox/latest`), clean tree at start. Run ends with the mandated
  `harness/scripts/backup.sh` push (see BACKUPS.md tail).
- Engine: pure-std Rust workspace at `engine/` (edition 2021,
  GPL-3.0-or-later, zero third-party crates, D-0002). **11 crates**:
  holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net,
  holo-crypto, holo-ss, holo-socks, holonetctl, holonetd. No engine code
  changed this run (review-only + the remediations below).
- Tests: **75 `#[test]` functions countable from the tree** (crypto 17,
  theme 10, config 10, net 9, engine 8, ss 7, util 7, socks 5, proto 2);
  per-OS arithmetic 75/74/72 via the three cfg gates (verified by A1
  and Blue-Forensics independently). **NOT re-executed this run (no
  toolchain on this host) — see CI state below; "75 green" is a static
  count plus LOCAL evidence from 2026-11-13, not a fresh execution.**
- **FULL CI state at reviewed HEAD `8761716` (A1, API-verified
  2026-11-17): run 43382900976 shows ubuntu-latest FAILED at the
  "Tests (holo-engine integration)" step, the Rust 1.77.2 compatibility
  job FAILED (root cause found by Blue-Forensics: commit 53ff229
  rewrote Cargo.lock v3→v4, unreadable by cargo 1.77.2 — FIXED this
  run, verify green at the next push), and windows-latest failed at
  holo-ss (the DISCLOSED, by-design red until the S1 Windows entropy
  FFI, D-0008). The ubuntu failure is UNDIAGNOSED (logs need repo
  access; suspects: debug-mode throughput floor `mbps > 1.0` and the
  <2 MB RSS bound in engine/crates/holo-engine/tests/integration.rs) —
  A1-C1 requires diagnosis at the next run with toolchain/access.**
- Live data plane (v0.3.0): Shadowsocks AEAD (SIP004, 3 ciphers), local
  SOCKS5 pooled relay, `session.connect` wiring (default-deny dispatch
  with honest per-driver milestone errors — A1 re-verified), Material
  You theme system + Flutter/KMP/Qt frontends validated by golden
  vectors. Share-LINK import for all 7 schemes live; remaining import
  formats are S4.
- **Public release surface (A1, API-verified 2026-11-17): only
  `v0.2.0` (empty), `v0.2.0-linux` (tarball + SHA256SUMS.txt), and
  `v0.3.0` (source only) are visible. v0.2.0-windows/macos/android and
  all v0.3.0-* binary releases are NOT publicly downloadable despite
  "success" workflow runs — reconciliation + republish decision open
  (D-0013). README Releases section rewritten honestly this run.**
- **D-0009 RE-ESCALATED as D-0013 (2026-11-17):** the pre-hardening
  Windows binaries named in D-0009 are (per the API check) no longer
  publicly downloadable, which REDUCES exposure — but downloaded-before-
  removal copies are unknowable and the v0.3.1-or-advisory decision
  remains the owner's, now with a deadline (before S1 DONE; ideally at
  the next session start — A2-C3/A3-C7).
- Progress review 0002 remediations APPLIED THIS RUN (see the record's
  remediation list): `.gitattributes` LF pinning (A4-C1); WORKFLOW §2.6
  record-numbering/progress-review/blob-hash rules (A3-C1/A4-C5,
  D-0011); ROADMAP gate-numbering rewrites + S1/S2/S3/S5/S6/descope
  amendments + research backlog adoption; THREAT-MODEL §A/§C/§E/§G
  amendments (replay, SOCKS-hop consequence, release surface, Windows
  secrets); README honesty fixes (OpenSSL journals lost — A1-C4;
  Releases reality — A1-C3); Cargo.lock v3 restore (A1-C2 root cause);
  STATE.md full-CI disclosure (A1-C5); DECISIONS D-0011..D-0014;
  session journal 2026-11-17.
- NOT remediated this run (binding on next code run, per record 0002):
  harness-audit CI equality/range checks (A4-C2); backup.sh rebase
  guard + WARN durability (A4-C3); ubuntu-CI diagnosis (A1-C1 — needs
  a run with repo log access); everything S1. (SANDBOX-RESTORE Windows
  section + per-host re-verify wording: DONE this run, A4-C4.)
- Gate status: gate 0001 PASSED (S0→S1, S1 open to start); progress
  review 0002 PASSED (no transition authority; S1 charter AMENDED).
  Next record number: 0003 (expected: the S1→S2 gate, per WORKFLOW
  §2.6).
- Suggested next session START (A3-C7): owner decisions — D-0009/
  D-0013 (advisory vs v0.3.1, cut BEFORE the S1 XChaCha20 wire change
  if chosen) and S5 credentials model; then S1 item 0 (Windows FFI +
  Windows-green CI) with the A3-C3 ordering rule.

Re-verify after any restore before trusting this file — PER HOST
(A4-C4/D-0012, this host's honest procedure): tree clean at
`sandbox/latest`; `cargo test --workspace` green IF a Rust toolchain
exists (Linux sandbox expected 75); on a toolchain-less host (this
Windows one today), the honest fallback is the public CI conclusions
for HEAD via api.github.com (actions runs) — currently expecting: ubuntu
green-again only AFTER the next push (lockfile fix), 1.77.2 job expected
green after the same fix, windows-latest expected red until S1 item 0.
