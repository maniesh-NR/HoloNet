# HoloNet State Snapshot

Last updated: 2026-11-26 (UTC, run 12 — cron-fired 18:00 UTC session,
job 549467 per D-0036): **S2 BATCHES 1+2 LANDED**. Batch 1 (four
parallel agents): the NEW holo-tls crate (record layer + handshake
codec + transcript + alerts, RFC 8448 traces byte-identical, 21
tests), holo-crypto rsa_sign (RSASP1 + PKCS#1 v1.5 + PSS SIGN, NIST
CAVS 186-2 + Wycheproof + OpenSSL byte-exact, salt entropy seam, +10),
holo-tls spki (own DER walker, pin over the full SPKI span incl.
tag+len, RFC 6125 hostname rules, 11 python-verified fixture pins, the
loopback RSA-2048 key+cert fixture, 17), holo-tls schedule (FULL RFC
8446 §7.1 chain, RFC 8448 pinned incl. both Finished verify_data, 12).
D-0037: cfb_usage_audit hex-data exception (3 DER fixtures tripped the
substring scan; matcher exempts ≥12-char hex runs only; negative demo
re-run green). Batch 2: the handshake AGENT DIED post-delivery — lead
took over and fixed 3 defects its own tests caught: client flight
DOUBLE-WRAP (send_plaintext got an already-encoded record), server
transcript missing its own Finished before verifying the client's,
missing Debug derive; deterministic-flight hash re-pinned. MSRV
incident: LazyLock(1.80) → OnceLock across holo-tls (canary caught it;
run b8e37b3 FAILURE → 0ff442d SUCCESS). CI-GAP incident: holo-tls was
never in the workflow's per-package test list (compiled but its tests
never ran — caught by ledger reconciliation, NOT by red CI); Tests
(holo-tls) step added. **CI-VERIFIED: run 45886693866 @ da7aa42, 6/6
SUCCESS — ledger 194 Linux / 193 macOS / 193 Windows** (visible
184/183/183 + socks 10; +63 holo-tls on every OS; workspace local
194/0/3, lock v3, zero new warnings). e2e over REAL loopback TCP:
handshake + echo, all 3 suites, HRR with fresh key share + cookie,
transcript/pin/hostname/downgrade/wrong-sig rejections. S2 REMAINING:
the session.connect DRIVER deliverable (trojan framing, binding
condition 1) + R-05 interop harness, then gate 0005. Graph 170/135
check+smoke green.

Prior state: 2026-11-26 (UTC, run 11 — OWNER DECISIONS EXECUTED,
D-0035: D-0014 trojan descope default RATIFIED unchanged — the descope
rule is now owner-ratified, ROADMAP annotated, graph OD-d0014 decided;
PAT rotation DECLINED this round — old token kept, exposure window
owner-accepted residual, env-var discipline unchanged; CVE polling
DELEGATED to the executor — first authenticated poll 2026-11-26T06:52Z:
cve_id STILL NULL, daily automated poll scheduled, mechanical backfill
procedure recorded in D-0035 (repo-scoped advisory endpoint is the
reliable poll target; the global /advisories endpoint 404s until
promotion). Session was docs/harness-ONLY: zero engine changes;
baseline = the run-10 closure tree d8aac80 == origin/main, CI run
45495227224 SUCCESS. Toolchain absent after a SIXTH recycle wipe —
not reinstalled (no Rust code touched; honest fallback per
SANDBOX-RESTORE: the CI conclusion for HEAD is the evidence). Graph
161 nodes / 124 edges, check + RAG smoke green.
ADDENDUM ~07:20Z (D-0036, owner instruction): standing schedule —
the CVE-poll job 549422 (14:00 Rangoon daily, never fired) was
REPLACED by the daily **18:00 UTC autonomous session** (job 549467,
priority 10): CVE poll + ALL owner-input-free roadmap items as far as
the stage gates allow (S2 holo-tls open per the gate-0004 charter) +
per-stage backups + agent parallelization (run-10 pattern) +
MANDATORY pre-close next-day task refresh (create replacement BEFORE
deleting the old; old→new id chain journaled in each session journal;
degrades to poll-only when the owner-free roadmap is exhausted).
First firing 2026-11-26 18:00Z. Graph 162/126 check+smoke green.)

Prior state: 2026-11-25 (UTC, run 10 — S1b items 3/4/5 LANDED via a
five-agent parallel batch: AES-CFB128 (SP 800-38A, D-0030 mechanical
pub(crate)+grep-audit enforcement, negative demo live), tls13
HKDF-Expand-Label/Derive-Secret (RFC 8446 §7.1, RFC 8448 chain), bignum
CIOS Montgomery + rsa VERIFY-ONLY (PKCS#1 v1.5 + PSS; D-0031 CT
accepted-risk). Local 114-green (97+5+3+9), static 116, lock v3 held.
X25519 SHIPPED by the lead (two subagent deaths — taken over mid-session;
first-compile green; RFC's own python decode+ladder ALL 9 CHECKS PASSED;
1,000-iter release 0.12 s + 1M-iter release 124.46 s per D-0032).
Stage 1 (items 3/4/5) CI-VERIFIED run 45488934917 @ d6c37a0 AND stage 2
(X25519) CI-VERIFIED run 45491740796 @ 9cf3114 — BOTH SUCCESS (6/6;
per-OS ledger 120 Linux / 119 macOS / 119 Windows, visible 110/109/109
+ socks 10 reconciled). GATE 0004 (S1→S2) CONVENED: four blind reviewers
ALL returned PROCEED_WITH_CONDITIONS (0 BLOCK) — transition ALLOWED;
conditions executed in this closure push (SNI masking CUT D-0033, RSA
exponent validation enforced D-0034 +1 test, ledger citations refreshed,
verify scripts deposited in harness/scripts/verify/, LESSONS entries,
ROADMAP acceptance-text amendments). Record: harness/adversarial/verdicts/
0004-S2-gate.md (chain to 0003 verified). Local 121-green. Full narrative:
harness/memory/sessions/2026-11-25-s1b-completion.md.

Prior state: 2026-11-21 (UTC, run 9 — S1b OPENS: BLAKE2s shipped,
first S1b/S1c crypto primitive). Restore ritual: warm path (runbook
0/0b) — remote reconciliation MATCH at 880661e == origin/main (the
run-8 closure retry push landed; its LANDED ledger line was found
uncommitted in the working tree and rides THIS run's backup).
Working-tree strays triaged: only that BACKUPS.md line, inside
harness/ (allowed). Toolchain REINSTALLED via rustup a FOURTH time
(rustc 1.100.0 — the recycle wipes ~/.cargo reliably; runbook step 2
is the proven path); baseline re-verified **92/92 green BEFORE
changes** (static 94), matching the CI-verified run-8 ledger; lock v3
held throughout. **BLAKE2s SHIPPED (RFC 7693, ROADMAP S1b item 1; the
D-0020 orphan's code NOT reused — only its KAT expectations, each
re-verified this run against Python hashlib.blake2s AND OpenSSL 3.5.7
`dgst -blake2s256`):** `holo-crypto::blake2s` with `hash(key, data,
out_len)` one-shot (§3.3 semantics: key block d[0] when keyed,
non-final t = (i+1)*64 over the global block index, final t = ll (+64
keyed), unkeyed-empty → one zero block t=0), `digest`/`hex` unkeyed
BLAKE2s-256, and `mac(key32)` for the S2 WireGuard shape. SIGMA taken
from RFC §2.7 AND cross-checked against Appendix D's blake2s.c
sigma[10][16] (two in-document sources; SIGMA[3] = the orphan's
killer row, index [8] = 2). Rotations RIGHT (rotate_right 16/12/8/7).
Verification layers (5 named tests, +5): row permutation check; the
full Appendix B "abc" trace replayed state-by-state through the ONE
production compression fn (an `Option<&mut Vec>` trace hook — the
test exercises the production code path, not a reimplementation):
11 v[16] states + final h + digest 508c5e8c327c14e2…86 6759 82;
KATs unkeyed+keyed (8+8 lengths 0..255, inputs 0..len-1); the RFC
Appendix E self-test grand hash-of-hashes 6a411f08ce25adcdfb02aba64
1451cec53c598b24f4fc787fbdc88797f4c1dfe over 48 digests (outlen
16/20/28/32 × inlen 0/3/64/65/255/1024 × keyed+unkeyed — includes the
≥31-byte inputs that hid the orphan's defect). Local suite **97
green** (92 + 5), static 99, Cargo.lock v3 HELD. **CI-VERIFIED — in
two rounds: first push 6331952 FAILED the harness-audit graph-coverage
gate (missing SES-2026-11-21b node: markdown extended, graph.json not;
all 5 test jobs green even on that tree); fixed by extending graph.json
(+1 SES node, +4 T-blake2s nodes, +6 edges; graph check + RAG smoke
green locally); the fix push e3c8304 = CI run 44897540455 ALL-GREEN
(6/6) — per-OS ledger 97 Linux / 96 macOS / 96 Windows (visible
87/86/86 + redirected socks 10, reconciled); README badge + Status
block and ARCHITECTURE data points updated to the verified
numbers.** Remaining S1b/S1c: X25519 (execution-mode
decision first), AES-CFB (+ planned mechanical grep-audit),
ExpandLabel, bignum/RSA.

Previous-run state, preserved below (run 8 — XChaCha20 WIRE FIX,
binding condition 8 / D-0029; S1a now FULLY CLOSED). Restore ritual: warm path
(runbook 0/0b) — remote reconciliation MATCH at 17e5b8d == origin/main
(the run-7 push DID land; the BACKUPS.md FAILED tail was an in-script
attempt only, reconciled + LANDED line appended this run; CI of the
17e5b8d tree = run 44759108489 SUCCESS). fileMode guard re-applied,
hooks present, memory gate PASSED. Toolchain REINSTALLED via rustup a
third time (rustc 1.100.0 — the recycle wipes ~/.cargo reliably;
runbook step 2 is the proven path); baseline re-verified **87/87
green BEFORE changes** (static 89), matching the CI-verified run-6/7
ledger. **XCHACHA20 WIRE FIX SHIPPED (record-0003 A2-F8/A3-C3, gate
condition 8; D-0029):** holo-ss `Direction` now carries a method-sized
`Nonce` (N12/N24) — xchacha20-ietf-poly1305 seals/opens via
`aead_xchacha20poly1305_*` with the 24-byte LE SIP004 counter
(HChaCha20 subkey derivation inside the AEAD); the mislabeled
zero-IV re-key + dead `n24` store REMOVED (retired, no compat mode —
it never interopped with any standard peer; chunk 0 coincidentally
matches, divergence from the 2nd AEAD op). holo-crypto gained the
OFFICIAL draft-irtf-cfrg-xchacha-03 vectors fetched verbatim from the
IETF archive (§2.2.1 HChaCha20 subkey; A.2.1 XChaCha20 keystream, 4
blocks; A.1 AEAD ct+tag+the published intermediate Poly1305 key) —
primitives were already draft-correct, now PROVEN. Named holo-ss tests
`xchacha_wire_is_standard_aead_24byte_le_counter` (byte-exact
equivalence at nonce k=0,1,2) + `xchacha_wire_differs_from_the_
retired_zeroiv_construction` (divergence at chunk 1). Local suite
**92 green** (87 + 3 crypto vectors + 2 wire tests), static 94,
Cargo.lock v3 HELD. CVE status re-checked: GHSA-8h6m-w5qj-cq9g
published, cve_id still None (pending — backfill when assigned).
Remaining S1: BLAKE2s (S1b; SIGMA re-derivation warning applies,
D-0020), X25519, AES-CFB, ExpandLabel, bignum/RSA (S1b/S1c).
**CI-VERIFIED post-push: run 44872078593 @ 676a58c all-green (6/6 jobs
incl. the 1.77.2 canary + the harness-audit graph-coverage/RAG-smoke
checks over the extended graph) — per-OS ledger 92 Linux / 91 macOS /
91 Windows (visible 82/81/81 + redirected socks 10, reconciled;
README + ARCHITECTURE updated to the verified numbers). MID-RUN
DIVERGENCE (the third): a parallel graph/RAG session pushed bcf8da1 +
05f9906 mid-run; reconciled per WORKFLOW §1.4 (commit + rebase, one
DECISIONS.md conflict resolved keeping BOTH sides, my XChaCha decision
renumbered D-0027→D-0029 after theirs took D-0027/D-0028; graph.json
extended with D-0029/SES-2026-11-21a/3 test nodes, GAP-xchacha
closed, stale planned-test nodes flipped — graph check + RAG smoke
green locally before the push).**

Previous-run state, preserved below (run 7 — OWNER DECISIONS EXECUTED:
D-0025 advisory+v0.3.1, D-0026 S5 creds). Run 7
highlights: HoloNet-SA-0001 drafted AND published as GHSA-8h6m-w5qj-
cq9g (CVE requested); v0.3.1 cut from CI-verified 6314da0 — 4 per-OS
release builds all-green (windows 44758027482, macos 44758056729,
linux 44758090961, android 44758125210), all 7 binaries checksum-
verified, master SHA256SUMS.txt signed with Ed25519 (private key in
the executor sandbox, NOT in repo; pubkey committed docs/release-
signing.pub; stock-openssl verification documented in README);
7 phantom per-OS drafts deleted (2 vulnerable Windows builds
destroyed; public v0.2.0-linux kept, unaffected). Lesson learned:
4 tags pushed in ONE git push dropped their workflow events —
individual pushes with gaps fire reliably. Owner may still need to:
confirm D-0014 (trojan default), rotate the PAT used this session.
Previous-run state, preserved below (run 6 — S1a closing item:
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
bignum/RSA. **CI-VERIFIED post-push: run 44728988531 @ 937554f
all-green (6/6 jobs incl. the 1.77.2 canary — Cargo.lock v3 held
through CI) — per-OS ledger 87 Linux / 86 macOS / 86 Windows
(visible 77/76/76 + redirected socks 10, reconciled; README +
ARCHITECTURE counts updated to the verified 87 numbers).**

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
