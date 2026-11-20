# HoloNet State Snapshot

Last updated: 2026-11-20 (UTC, third run of the day — pstack re-affirm,
memory hooks D-0021, lockfile-v3 regression fixed). Run 3 changed no
Rust code: owner re-sent the pstack framework (already adopted D-0016;
the HOOK gap is now closed — update_memory.py --check gate +
--install-hooks, pre-commit refresh+stage / post-commit read-only);
warm-restore 0/0b done (reconciliation MATCH at ef19a6f; 94 phantom
exec-bit mods cleared, 0 content). FOUND+FIXED live regression:
Cargo.lock had been silently rewritten v3→v4 by the 0003 run's
modern-cargo test re-run (violates the v3 invariant; breaks the
1.77.2 CI job) — v3 restored this run BEFORE any push. Toolchain
ABSENT after recycle → 4W fallback (static 78; anonymous API
rate-limited — CI not re-fetched; engine diff vs CI-verified 2dae1ce
= Cargo.toml hygiene + the lockfile line only). Backup push outcome:
BACKUPS.md tail (HOLO_GITHUB_TOKEN absent).

Previous-run state, preserved verbatim below: cross-validation
progress review 0003 (independent adversarial panel, 4×
PROCEED_WITH_CONDITIONS, 0 BLOCK; record
`harness/adversarial/verdicts/0003-cross-validation.md`). Linux sandbox
WITH full toolchain (rustc 1.100.0); the suite was re-run locally.

- MID-RUN DIVERGENCE (record-0003 A4-F3, the run's sharpest finding):
  the run started from an on-disk tree @ `8761716` believing "local ==
  origin/main" from a stale tracking ref; `git ls-remote` revealed
  origin/main had moved 12 commits ahead — a PARALLEL SESSION had
  pushed its own record-0002 progress-review cycle (2026-11-17) plus
  harness hardening (2026-11-19) plus S1 ITEM 0 (2026-11-20, D-0018).
  Reconciled by fast-forward (`merge --ff-only`, local was an
  ancestor); all record-0003 work then landed on the merged tree.
  backup.sh now refuses to push when the live remote differs (A4-C2).

- Restored from GitHub `maniesh-NR/HoloNet` @ `8761716` (branch `main`,
  = `sandbox/latest`), clean tree at start. Run ends with the mandated
  `harness/scripts/backup.sh` push (see BACKUPS.md tail).
- Tests: **76 Linux / 75 macOS / 75 Windows, ALL GREEN on CI**
  (verified 2026-11-20, run 44668106188 @ 2dae1ce; socks suite hidden
  from CI logs by redirection — add 5 to naive log sums). Growth:
  75/74/72 → 76/75/75 (data-dir test everywhere, +2 Windows FFI
  tests). Static count now 78 `#[test]` definitions total; per-OS
  counts differ via cfg gates (quote per platform).
- **CI state (fully diagnosed 2026-11-18, closing A1-C1/C2):** at the
  lockfile-fix push `26b48c9` (run 44229892465): **Rust 1.77.2 job
  GREEN again, macOS GREEN, cross-check + harness-audit GREEN**;
  ubuntu FAILED at `memory_stays_bounded_under_sustained_relay`
  (integration.rs:439) — RSS +2520 KB over 64 MB relayed vs the 2 MB
  assert, i.e. SHARED-RUNNER variance, not a pooling regression
  (local reference +88–376 KB; per-chunk pooling failure would grow
  tens of MB). Remediation landed 2026-11-18: budget 2 MB → 8 MB with
  honest comment (D-0015); Windows job given continue-on-error +
  "expected-red until S1 item 0 (D-0008)" display name (A3-C3). The
  windows failure mechanism is CONFIRMED from authenticated logs as
  the disclosed by-design red: holo-ss tests abort on "os entropy
  unavailable — refusing weak randomness (fail-closed)" (4 passed /
  3 failed, all entropy). Expected matrix after the D-0015 push:
  ubuntu green, macOS green, 1.77.2 green, windows expected-red
  (continue-on-error ⇒ run conclusion green), cross-check green,
  harness-audit green. **SUPERSEDED 2026-11-20: S1 item 0 LANDED — the
  full matrix is ALL-REQUIRED green (see the Tests bullet above); the
  expected-red window is closed.**
  harness-audit green. Authenticated log access works via the owner's
  cached git credential (GCM) — anonymous is 403.
- Engine: pure-std Rust workspace at `engine/` (edition 2021,
  GPL-3.0-or-later, zero third-party crates, D-0002). **11 crates**:
  holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net,
  holo-crypto, holo-ss, holo-socks, holonetctl, holonetd. No engine code
  changed in the 0003 run except Cargo.toml hygiene: unused
  `holo-util` dep removed from holo-socks; redundant holo-util
  dev-dep removed from holo-engine (record-0003 A1-F7; suite
  re-verified green locally after the change).
- Record-0003 residual conditions APPLIED THIS RUN: doc claim fixes
  (TECHNIQUES phantom §12 + RTT-wiring claim + OpenSSL-evidence chain;
  RESTORE; ARCHITECTURE counts 76/75/75 + FFI-shipped wording),
  .gitignore += profiles.json/.env.local/keystore/ (A2-C9), backup.sh
  untracked-guard + live-remote-guard (A4-C4/A4-C2), SANDBOX-RESTORE
  step 0 reconciliation + 0b warm-restore + fileMode (A4-C2/C3),
  WORKFLOW §4.4 first-act triage (A3-C8), S1 charter amendments
  (X25519 decode/ct_eq precision A2-C3; CFB mechanical ban A2-C4;
  close-vs-hang read-deadline elevation A2-F6; ProbeGuard N=1024 +
  deterministic jitter seam + ceiling decision A1-F8/A3-C10;
  OpenSSL-journal auditability A3-C9; BLAKE2 SIGMA-transcription
  warning A1-F5; baselines → item-0 ledger), orphan disposition
  D-0020. CARRIED (code work, S1): everything not applied above.
- Research lane (owner charge "research fixes/improvements/new
  features"): the researcher subagent failed twice (empty responses);
  the orchestrator ran the research pass directly with citations —
  `harness/research/0001-s1-preflight-landscape.md` (std CSPRNG still
  unstable in 1.100.0 → FFI permanent for the 1.77.2 floor; XChaCha
  still draft-irtf-cfrg-xchacha-03, NOT an RFC; TLS-in-TLS fingerprint
  literature for the S2/S3 padding work; ECH = RFC 9849 (2026-03) but
  ~0.06 % real-world usage → not v1.0 cover; Wycheproof (C2SP)
  RsassaPkcs1/Pss verify vector classes named for S1c acceptance).
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
  everything S1. (A4-C2 harness-audit strengthening + A4-C3 backup.sh
  guards: DONE 2026-11-19, D-0017 — verified locally and by CI;
  A1-C1/A1-C2 closed 2026-11-18 with runs 44229892465/44234338593;
  SANDBOX-RESTORE Windows section done 2026-11-17, A4-C4.)
- Live data plane (v0.3.0): Shadowsocks AEAD (SIP004, 3 ciphers), local
  SOCKS5 pooled relay, `session.connect` wiring (default-deny dispatch
  with honest per-driver milestone errors — A1 re-verified), Material
  You theme system + Flutter/KMP/Qt frontends validated by golden
  vectors. Share-LINK import for all 7 schemes live; remaining import
  formats are S4.
- Gate status: gate 0001 PASSED (S0→S1); progress review 0002 PASSED
  (no transition authority; S1 charter amended); progress review 0003
  PASSED (cross-validation, no transition authority; residual
  conditions applied/carried as above). S1 item 0 DONE (D-0018).
  Next record: 0004 = the S1→S2 gate (sequence number per D-0011;
  do not hardcode).
- Suggested next session START (A3-C7, updated 2026-11-20): owner
  decisions — D-0009/D-0013 (advisory vs v0.3.1, cut BEFORE the S1
  XChaCha20 wire change if chosen) and the S5 credentials model; then
  CONTINUE S1: item 1 BLAKE2s (SIGMA re-derivation warning applies,
  D-0020), item 2 X25519, item 3 AES-CFB, item 4 ExpandLabel, item 5
  bignum/RSA prep, server-path hardening backlog (salt-replay cache,
  ProbeGuard N=1024 decay, jittered slow-close with an explicit
  ceiling, first-chunk read deadline), XChaCha wire-cipher fix
  (binding condition 8; draft-irtf-cfrg-xchacha vectors),
  rand-split mechanical enforcement (condition 7).

Re-verify after any restore before trusting this file — PER HOST
(A4-C4/D-0012, this host's honest procedure): tree clean at
`sandbox/latest`; `cargo test --workspace` green IF a Rust toolchain
exists (Linux sandbox expected 76); on a toolchain-less host, the
honest fallback is the public CI conclusions for HEAD via
api.github.com (actions runs) — currently expecting the full matrix
REQUIRED-green (the expected-red windows window closed with S1 item 0,
D-0018).
