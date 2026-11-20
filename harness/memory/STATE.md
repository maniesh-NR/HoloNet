# HoloNet State Snapshot

Last updated: 2026-11-20 (UTC, sixth run of the day — S1a closing item:
MECHANICAL rand-split enforcement, D-0024). Restore ritual: warm path
(runbook 0/0b) — remote reconciliation MATCH at 1c82ad4 == origin/main
(the run-5 push fully landed; CI 44703200189 all-green 86/85/85),
fileMode guard re-applied, hooks present, memory gate PASSED (lag 1).
Toolchain REINSTALLED via rustup (rustc 1.100.0; the recycle wiped
~/.cargo a second time — runbook step 2 is exercised and reliable).
Baseline re-verified **86/86 green BEFORE changes** (matches the
CI-verified run-5 ledger exactly). **RAND-SPLIT ENFORCEMENT SHIPPED**
(gate-0001 A2-C3 / ROADMAP S1 item 7) — both halves of the condition:
(1) compile-failure — weak PRNG (`fill`/`bytes`/`hex`/`alnum` +
splitmix64 machinery) moved to `rand::nosec` (`#[doc(hidden)]`, loud
never-for-crypto docs) and BOTH re-export paths closed (rand module
root + the crate-root `pub use rand::{bytes, fill}`; the crate-root
path was found by this run's call-site map — a module-only split would
have been silently defeated by it); old root calls are E0425,
demonstrated live; (2) the named workspace audit test
`rand_split_audit_no_weak_prng_outside_allowlist` scans every engine
`.rs` for `nosec::` + the weak root paths and fails with file:line
outside the two-entry allowlist (definition + the holo-config
profile-ID consumer, the ONE gate-classified non-security consumer);
negative-demonstrated on a planted scratch violation (audit FAILED
with the offending line, scratch removed). Call-site map: os_* =
holo-ss:918 (slow-close seam), holo-ss:1067 (random_salt),
holo-engine:78 (token); weak = holo-config:131 only. Local suite
**87 green** (86 + 1; the audit test has no cfg gates → +1 on all
three OSes; CI verification rides the next push); static count 89;
Cargo.lock v3 HELD post-run. Remaining S1: XChaCha wire fix
(owner-blocked on D-0009/D-0013), BLAKE2s (orphan available for
re-derivation per D-0020), X25519, AES-CFB (its planned CI grep-audit
follows THIS audit's pattern, per ROADMAP item 3), ExpandLabel,
bignum/RSA.

Previous-run state, preserved below (run 5 — S1 server-path
hardening second pass + backup push LANDED). **PUSH LANDED** with the
owner-supplied token (env var only, never stored): origin/main
ef19a6f..d9e137e (4 commits — run-3 pstack backup, run-4 hardening,
two honest FAILED markers); **CI run 44700103379 @ d9e137e all-green
(6/6 jobs)** — per-OS ledger parsed from job logs with the socks
redirect reconciled: **83 Linux / 82 macOS / 82 Windows** for the
83-tree (README + ARCHITECTURE counts updated to the CI-verified
numbers). Run 5 work (baseline re-verified 83/83 BEFORE changes;
toolchain persisted in ~/.cargo this time): **(1) PROBE GUARD DECAY —
SHIPPED** (`PROBE_GUARD_PEER_CAP` = 1024, stalest-`last` eviction,
named test `probe_guard_peer_map_decays_at_cap`); **(2) CSPRNG-JITTERED
SLOW-CLOSE — SHIPPED** (full jitter over [0, min(backoff, SLOW_CLOSE_MAX)],
ceiling 2 s = D-0023, os_fill draw via parameterized seam, named test
`slow_close_jitter_seeded_deterministic`; ALSO fixed found-by-inspection
defect: ProbeGuard Mutex was held across the sleep, serializing the
whole server behind one probe's delay); **(3) A2-F6 AUTH READ DEADLINE
— SHIPPED** (10 s over the whole unauthenticated phase, cleared
post-auth, `ServePolicy` injection for tests, named test
`silent_after_valid_length_times_out`). Local suite **86 green**
(83 + 3: +1 holo-net, +2 holo-ss); static count 88; Cargo.lock v3 HELD.
All three decisions recorded as D-0023; ROADMAP/THREAT-MODEL §C
annotated/flipped with honest residuals. serve_conn/accept gained the
`ServePolicy` param — all call sites updated (4 in-crate + engine
integration). **CI-VERIFIED: run 44703200189 @ f433de4 all-green
(6/6 jobs) — per-OS ledger 86 Linux / 85 macOS / 85 Windows** (socks
redirect reconciled; README/ARCHITECTURE now cite the verified 86
numbers). Remaining S1: XChaCha wire fix, rand-split enforcement,
BLAKE2s (orphan artifact available for re-derivation), X25519, AES-CFB,
ExpandLabel, bignum/RSA.

Previous-run state, preserved below (run 4 — S1 server-path hardening
first pass). Run 4: toolchain REINSTALLED via rustup (rustc
1.100.0; recycle had wiped it); baseline re-verified 76/76 green
BEFORE any change; **A2-C1 SALT-REPLAY CACHE SHIPPED** (holo-ss
SaltCache, bounded FIFO cap 1024, admitted in ServerConn::accept
before any crypto, replay = the same opaque auth_failed(); named test
`salt_cache_rejects_replayed_prefix` + `salt_cache_admit_and_evict_
semantics`; serve_conn/accept gained &Mutex<SaltCache>, all call
sites updated); **A3-C4 OFF-LOOPBACK BIND REFUSAL SHIPPED** (holo-socks
require_loopback_listen: every resolved IP must be loopback, names
fail closed, check precedes the OS bind; override env
HOLONET_PROXY_LISTEN_ANY=1; 5 new tests incl. the two named refusal
tests). **Local suite 83 green** (76 + 7: +5 holo-socks, +2 holo-ss);
static count 85; Cargo.lock v3 invariant HELD post-run (verified — no
Cargo.toml change → no regeneration; lesson refined accordingly).
Harness: **D-0022 backup.sh retry-deadlock fixed** (guard now refuses
only when the remote has commits local lacks; local-ahead =
fast-forward allowed; scenarios A–E negative/positive-tested in a
throwaway repo). ROADMAP/THREAT-MODEL §A/§C annotated/flipped with
local evidence; per-OS ledger + README counts ride the next
CI-verified push (push auth still absent — see BACKUPS.md tail).

Previous-run state, preserved below (run 3 — pstack re-affirm,
memory hooks D-0021, lockfile-v3 regression fixed; changed no Rust
code: owner re-sent the pstack framework (already adopted D-0016;
the HOOK gap closed — update_memory.py --check gate +
--install-hooks, pre-commit refresh+stage / post-commit read-only);
warm-restore 0/0b done (reconciliation MATCH at ef19a6f; 94 phantom
exec-bit mods cleared, 0 content). FOUND+FIXED live regression:
Cargo.lock had been silently rewritten v3→v4 by the 0003 run's
modern-cargo test re-run (violates the v3 invariant; breaks the
1.77.2 CI job) — v3 restored that run BEFORE any push. Toolchain
was ABSENT after recycle → 4W fallback (static 78; anonymous API
rate-limited — CI not re-fetched; engine diff vs CI-verified 2dae1ce
= Cargo.toml hygiene + the lockfile line only). Backup push outcome:
BACKUPS.md tail (HOLO_GITHUB_TOKEN absent).) Cross-validation
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
