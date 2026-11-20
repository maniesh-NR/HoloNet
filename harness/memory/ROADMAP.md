# HoloNet Roadmap — staged, gated, measurable

This is the only accepted stage sequence (`harness/WORKFLOW.md` §2). A
stage is DONE only when every acceptance criterion is demonstrably met AND
its completion gate records adversarial consensus. Stage order follows the
debugged rebuild plan captured in `docs/RESTORE.md` (each item below was
previously built and tested to green in an earlier session, pitfalls
included — the pitfalls live in `LESSONS.md`).

## Standing criteria (apply to every stage)

1. Official vectors first: every crypto/protocol primitive ships with its
   RFC/NIST test vectors as cargo tests; no vector, no merge.
2. Fail-closed entropy everywhere: security material comes only from
   `os_fill`-class OS entropy; any entropy failure is a hard error
   (gate-0001 binding condition; see docs/THREAT-MODEL.md §G).
3. Integration proof: components that can work together must demonstrably
   do so — each stage adds at least one end-to-end test over real loopback
   TCP (import → connect → SOCKS → tunnel → echo → stats → disconnect
   pattern).
4. Performance & memory: any new relay path gets a throughput and a
   memory-bounding regression (precedent: 64 MB relayed → observed
   +88–376 KB RSS, asserted bound < 2 MB).
5. Literature techniques with citations in `docs/TECHNIQUES.md` where they
   measurably help (precedent: CUBIC, BBR-model, CoDel, DRR, HyStart++).
6. Honesty: not-yet-live protocols keep returning per-driver milestone
   errors. Zero unsafe in shipped crypto paths — the ONLY permitted
   exception is the chartered Windows entropy FFI (D-0008). Test count
   never drops.
7. Gate: transition into the next stage requires unanimous non-BLOCK
   consensus per `harness/ADVERSARIAL.md`.

## S0 — Core + crypto foundation + first live data plane — DONE (v0.3.0)

- Compact core (util/proto/config/links/engine/theme/bins), Material You
  system, holo-crypto (ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20,
  AES-256-GCM, SHA-2, HMAC, HKDF, EVP_BytesToKey), holo-net (RTT/RTO,
  token bucket, DRR, CoDel, CUBIC+HyStart++, BBR-model, padding,
  ProbeGuard, BufferPool), holo-ss (SIP004 AEAD client+server, 3 ciphers,
  anti-probing), holo-socks (RFC 1928/1929 pooled relay, DRR shaping),
  engine wiring (`session.connect` → probe → local SOCKS; milestone errors
  elsewhere). 71 tests green; releases on 4 OSes.

## S1 — entropy + crypto extensions — NEXT (gate 0001: consensus; AMENDED at progress review 0002)

Charter: the security foundation the TLS/QUIC stages need, in dependency
order. **Amended at gate 0001** (A2 conditions C1/C2, findings F1/F2/F9;
bignum/RSA prep moved here from S2). **Amended at progress review 0002**
(record `0002-progress-review.md`): internal ordering fixed — item 0
merges FIRST and windows-latest green precedes every crypto-extension
item; acceptance additions: salt-replay cache, Windows secret-at-rest,
off-loopback refusal (pulled in from S6), 1M-vector execution mode;
annotations: BLAKE2b cut-or-justify, constant-time bar for X25519/bignum.

0. **Per-platform CSPRNG, fail-closed** (A2-C1, blocks everything else).
   **S1 item 0: DONE 2026-11-20** (runs 44666798185/44668106188):
   RtlGenRandom FFI via SystemFunction036 landed (sole unsafe,
   forbid(unsafe_code) everywhere else), fail-closed with injection
   seam; data-dir HOME/USERPROFILE/hard-error + test (A2-C2/D-0018);
   windows-latest FULL suite green as REQUIRED job (76/75/75
   Linux/macOS/Windows); legacy job checks 1.77.2 msvc target;
   THREAT-MODEL §G shipped-provenance; continue-on-error window
   closed (A3-C3).

   Unix `/dev/urandom` via `os_fill`: DONE in the gate-0001 remediation
   (`rand.rs` split into fail-closed OS entropy vs non-security splitmix;
   `random_salt` + `ensure_token` converted; failure-injection test added).
   **Windows decision (D-0008): audited, contained FFI exception to the
   no-unsafe rule — RtlGenRandom / BCryptGenRandom — scoped to
   `holo-util/src/rand.rs` ONLY, fail-closed, re-reviewed at every gate.**
   Acceptance: the Windows path compiles on Rust 1.77.2, errors visibly
   when the system call fails, and per-platform provenance stays in
   `docs/THREAT-MODEL.md` §G.
1. BLAKE2s and BLAKE2b (RFC 7693) — remember ROTR, not ROTL.
   **Progress review 0002, A3-C6/F13: BLAKE2b has NO consumer in any
   chartered S1–S7 stage (WireGuard needs BLAKE2s; TLS/QUIC use SHA-2) —
   CUT from S1 unless a consumer is named and justified; BLAKE2s stays.**
   **Record-0003 warning (A1-F5): the crashed session's BLAKE2 orphan
   implemented ROTR correctly yet still failed its own KATs for inputs
   ≥31 bytes — the real killer was a mis-transcribed SIGMA row
   (SIGMA[3][8]) plus missing `use super::SIGMA` scoping. Re-derive the
   message schedule from RFC 7693 §3.3 — never transcribe it by eye.
   The orphan's 32 KAT expectations were independently verified against
   OpenSSL and ARE reusable; the orphan's code is NOT (D-0020).**
2. X25519 (RFC 7748) — a24 = 121665; inversion exponent p−2 with limb 0
   0xffffffeb…; reject the all-zero shared secret.
   **Contributory-behavior policy (A2): all-zero-output check ONLY,
   TLS 1.3-style; non-canonical u-coordinates accepted as-is — documented
   so S2/S3 inherit a decision, not an accident.**
   **Record-0003 precision (A2-C3): "accepted as-is" means decoded per
   RFC 7748 §5 — mask bit 255, little-endian, arithmetic mod 2^255−19 —
   with NO canonical-form rejection; it does NOT permit skipping the
   decode steps. The all-zero shared-secret compare must use the
   constant-time `ct_eq`; acceptance adds a non-canonical-acceptance
   test and quotes the RFC text verbatim when drafting.**
   **Execution-mode decision required before implementation (progress
   review 0002, A3-C5/F5): the RFC 7748 §5.2 1,000,000-iteration vector
   runs release-mode-only or behind an opt-in cfg — never as a default
   debug-mode CI test.**
   **Constant-time bar (progress review 0002, A3-C6/F13): X25519 and the
   bignum item must record a constant-time criterion (code-review
   checklist or recorded accepted-risk decision) — vectors alone pass a
   variable-time implementation; handed to A2 at the S1→S2 gate.**
3. AES-CFB (NIST SP 800-38A) — legacy provider paths only.
   **Constraint (A2): unauthenticated; forbidden outside an authenticated
   wrapper.**
   **Record-0003 enforcement (A2-C4): the constraint is mechanical, not
   prose — raw CFB encrypt/decrypt types are not `pub` outside the
   authenticated wrapper module, and a CI grep-audit fails on any `cfb`
   reference outside that module (same spirit as the rand-split audit,
   binding condition 7).**
4. TLS 1.3 key schedule helpers: HKDF-Expand-Label / Derive-Secret per
   RFC 8446 §7.1.
5. **Bignum + RSA verification prep (moved from S2, A2-F9):** CIOS
   Montgomery multiplication, RSA PKCS#1 v1.5 + PSS verify — S2's
   CertVerify needs them; final-carry-limb pitfall applies.

Server-path hardening backlog (A2-F5; **lands in S1** — tightened from
"by S2" at progress review 0002, A3-C5/F7):
- **Salt-replay cache (progress review 0002, A2-C1/F2 — NEW):** bounded
  exact-match per-server seen-salt LRU (time-windowed; NO Bloom filter —
  SIP022 forbids false-positive rejection), checked in
  `ServerConn::accept`; replay rejected through the SAME opaque
  auth-failure path as garbage (no new oracle); named test: a replayed
  salt+first-chunk connection is rejected. THREAT-MODEL §C amended
  2026-11-17.
- ProbeGuard: use the recorded `last` — decay and evict stale peers (the
  map currently grows unboundedly per distinct failing peer).
- Randomized slow-close via CSPRNG jitter (deterministic today — the
  determinism is itself a fingerprint, NDSS '20).
- Uniform close-vs-hang behavior for rejected vs valid length frames
  (distinguisher recorded in THREAT-MODEL §C). **Record-0003 elevation
  (A2-F6): a valid-length frame that then goes silent blocks the
  per-connection thread in `read_exact` with NO socket timeout — an
  unauthenticated resource-exhaustion vector on self-hosted servers.
  The fix must add a read deadline on the server's first-chunk read,
  not merely uniformize timing.**
- **Off-loopback `proxy_listen` refusal (progress review 0002, A3-C4 —
  pulled IN from S6):** refuse non-loopback binds unless an explicit
  override is set; named test: 0.0.0.0/:: bind refused without override.
  The v0.3.0 data plane binds today; deferral to S6 was a sequencing
  failure, not scoping discipline.

Acceptance criteria (all measurable):
- **Internal ordering (progress review 0002, A3-C3): item 0 merges
  FIRST; until windows-latest is green the Windows CI job runs
  `continue-on-error: true` with display name "Test (windows-latest;
  expected-red until S1 item 0)", flipped off at item-0 completion; the
  legacy job additionally runs a 1.77.2
  `cargo check --target x86_64-pc-windows-msvc`.**
- Fail-closed entropy: failure-injection test green
  (`os_entropy_fails_closed_on_unreadable_source`); Windows entropy FFI
  merged with tests; provenance current in THREAT-MODEL.md §G.
- **Windows secret-at-rest (progress review 0002, A2-C2/F4): daemon
  data dir falls back to USERPROFILE, hard-errors when neither
  HOLONET_DATA nor HOME/USERPROFILE resolves (never CWD "."); a
  recorded Windows ACL decision for ipc-token/profiles.json is
  reflected in THREAT-MODEL §A/§G.**
- Windows enforceability (A3-C3): the FULL workspace suite — including
  the 5 Windows-runnable engine integration tests — green on
  `windows-latest` CI **(SATISFIED by S1 item 0, D-0018: ledger
  76/75/75, run 44668106188 — the job is now REQUIRED-green; the
  continue-on-error window is closed)**; a Windows 1.77.2 compile check
  (done: legacy job checks `cargo check --target
  x86_64-pc-windows-msvc`); a Windows FFI failure-injection seam
  (done: INJECT_FAIL in `win_entropy`; direct linkage has no
  dynamic-load path — record-0003 A2 cross-check).
- Windows FFI specifics (A2-C1): (a) all `unsafe` confined to
  `holo-util/src/rand.rs` — verifiable by `grep -rn "unsafe"
  engine/crates/` returning zero hits outside that file; (b) explicit
  fail-closed error on syscall failure with a test; (c) RtlGenRandom
  chosen for the Windows 7 SP1 floor (BCryptGenRandom alone is Win8+);
  (d) THREAT-MODEL §G updated from "interim fail-closed" to the shipped
  provenance.
- RFC 7693 official vectors for BLAKE2s/b (keyed and unkeyed) pass.
- RFC 7748 §5.2 test vectors (including iteration counts) pass; the
  all-zero shared secret is rejected as an error, not silently accepted.
- NIST SP 800-38A CFB128 vectors pass.
- ExpandLabel: RFC 8446 §7.1 defines the construction; the recorded
  key-schedule vectors come from RFC 8448 (Simple 1-RTT handshake) —
  port those, plus in-crate loopback transcripts (A3-C4 citation fix).
- RSA/bignum: CIOS Montgomery verified against published Montgomery
  test vectors; PKCS#1 v1.5 verify against RFC 8017 §9.2 vectors; PSS
  against RFC 8017 §9.1.2 vectors; PLUS an in-crate RSA-2048 self-test
  cert (self-made, labeled as such — NOT an official vector set).
- Server-path hardening, named tests (A3-C2, checked at the S1→S2 gate):
  **salt-replay cache rejects a replayed salt+first-chunk connection
  (progress review 0002, A2-C1); off-loopback proxy_listen bind refused
  without explicit override (A3-C4);**
  ProbeGuard map bounded under 1024 distinct failing peers (decay/eviction
  test — N pinned at 1024, record-0003 A1-F8); CSPRNG-jittered
  slow-close seeded from `os_fill` through an injected-seam pattern
  (deterministic test via seeded entropy — two peers with identical
  failure counts get different delays WITHOUT a flaky live-draw
  comparison — record-0003 A3-C10) and the intended delay ceiling
  stated explicitly (today ProbeGuard computes up to 10 s but
  serve_conn clamps to 120 ms — the ceiling must be a decision, not an
  accident); close-vs-hang uniformity for length-rejected vs
  length-valid frames plus the first-chunk read deadline (A2-F6
  elevation above).
- OpenSSL cross-checks during development, recorded in the session
  journal WITH the exact command lines and ≥16 hex characters of each
  digest quoted (a bare "cross-checked" note does not satisfy this —
  record-0003 A3-C9; process evidence, not an in-tree artifact).
- No new third-party crates; the ONLY permitted unsafe is the chartered
  Windows entropy FFI (D-0008) — containment now compile-time-enforced
  by `#![forbid(unsafe_code)]` on every crate except holo-util
  (D-0018); workspace test count grows monotonically per platform from
  the CURRENT baselines (Linux 76 / macOS 75 / Windows 75 — the item-0
  ledger, D-0018; supersedes the post-gate-0001 75/74/72 figures;
  cfg-gated tests count differently per OS, A1-C5).
- Gate: the S1→S2 gate (record number assigned sequentially — see
  WORKFLOW §2.6, D-0011; do NOT hardcode record numbers) required
  before starting TLS.

## S2 — holo-tls: from-scratch TLS 1.3 client (RFC 8446)

X25519, suites 0x1301/02/03, HRR cookie, RSA CertVerify (PKCS#1 v1.5 +
PSS via CIOS Montgomery bignum — final carry limb!), SPKI pinning, SNI
masking, hostname match, in-crate loopback server with embedded RSA-2048
cert. ~18 tests. Acceptance: full handshake + application data over
loopback; transcript-hash mismatch and pin mismatch rejected; downgrade
attempts rejected.

**Charter amendments (progress review 0002, A3-C2/C6/F3/F13):**
- **Driver deliverable (binding condition 1, now in the charter body):
  S2 delivers ONE TLS-based driver wired into `session.connect` with
  named end-to-end tests (import → connect → tunnel → echo → stats),
  not just the library.**
- **No X.509 parser — SPKI pinning operates on raw DER; hidden ASN.1
  dependencies are a charter violation if any appear.**
- **"SNI masking" must be defined-and-tested or cut before S2 starts**
  (as written it is untestable).
- Green-R2 feasibility check: feasible-as-scoped ≈1.5–3k LOC given S1
  crypto (calibration: TIIGER-TLS/tls13tutorial precedents); the hard
  parts (chain building, tickets, 0-RTT) are exactly what
  pinning+loopback honestly skip.

## S3 — holo-quic: from-scratch QUIC v1 (RFC 9000/9001/9221)

Initial salt, header protection (AES / ChaCha 5-byte, sample after the pn
field), pn decode window seeded from the FIRST packet, CRYPTO reassembly
by offset, server flight in Handshake packets, SCID alias map. ~25 tests
incl. 100 KB loopback echo. Acceptance: handshake + stream data + loss
recovery over a lossy simulated link; interop-observable framing only
(loopback) — **i.e. packets a reference QUIC endpoint can decode, tested
via captured fixtures; no live-network interop claim (ambiguity flagged
at progress review 0002, A3-F13, resolved by this wording).**

**Rescoping note (progress review 0002, Green-R2): real QUIC stacks run
3.7k–10.3k LOC with documented ongoing logic bugs (NDSS 2026); S3 is
chartered as a CLIENT-RELAY PROFILE ONLY — no 0-RTT, no connection
migration, no qlog, no v2 — reusing holo-net's CUBIC. Full-stack parity
is explicitly out of scope for v1.0.**

## S4 — holo-config importers

Share-LINK import for all seven schemes is ALREADY live and tested
(`holo-config/src/links.rs`: ss SIP002+legacy, vmess, vless-reality,
trojan, hy2, tuic, wg — imported profiles report honest milestone errors
at connect until their drivers exist). S4 delivers the remaining formats:

Clash YAML (reality-opts, ws-opts; inline `[IPv6]:443` is a scalar, not a
flow list), V2Ray/sing-box JSON (incl. classic wireguard `local_address`),
WireGuard/AmneziaWG INI (Jc/Jmin/Jmax → amneziawg), base64 subscriptions.
~30 new tests. Acceptance: every importer round-trips into the flat
driver parameter registry (holo-proto `Params`; docs/ARCHITECTURE.md
"driver SPI") and feeds a live driver end-to-end where that driver
exists (SS today; others as they land).

## S5 — holo-provider — SPLIT at progress review 0002 (A3-C7/F11)

**S5a (first):** VPN Gate CSV + mirror, plus at most TWO other
providers, with the provider-fixture → registry → live-dial chain test
(binding condition 2). **S5b (descope-eligible remainder):** the rest.

Opera/SurfEasy digest-auth RPC (api2.sec-tunnel.com v4/*, se0316 creds,
4 h cache), VPN Gate CSV + mirror, Cloudflare WARP registration
(v0a4005/reg → warp_wg + warp_masque + dualpath), Mozilla Guardian,
Proton, Tor, Obscura, Lantern. ~51 tests. Acceptance: offline fixtures
only (no live network in tests), cache semantics tested, no credential
material committed.

**OWNER DECISION REQUIRED BEFORE S5 CHARTERS (progress review 0002,
A3-C7/F11): the credentials model.** "se0316 creds" named in tracked
files contradict D-0001 "no credentials" and WORKFLOW §3.3 — embedded
shared credentials in a public GPL binary are burnable and ToS-exposed.
Options: user-supplied-at-runtime only, or embedded-with-recorded-risk-
acceptance. **Green-R2 reality check (2026-11-17): reorder S5a = VPN
Gate (official CSV, zero ToS friction) → Opera (unofficial API, drift
risk) → warp_wg (needs the WG driver); CUT warp_masque/Proton/Tor/
Obscura/Lantern/Mozilla from v1.0 scope (warp_masque alone ≈ rescoped
S3 + MASQUE framing).**

## S6 — system crates

**Policy pre-decision REQUIRED at or before the S5→S6 gate (progress
review 0002, A3-C8/F10): D-0002/D-0008 must be amended to define the
TUN/killswitch FFI scope (wintun.dll is a third-party BINARY, colliding
with the zero-third-party-crates claim) and a Windows killswitch
mechanism must be named, or v1.0 killswitch is recorded Linux-only.
"Salamander" obfuscation is renamed/rescoped at the same time — it is
Hysteria's UDP obfs layer and is only coherent after S3 (Green-R2).**

Bonding (Dual-Path Active Tuning: hot-standby, stripe, mirror; intent
scoring), DNS + adblock filter matcher, killswitch (nftables), split
tunnel, TUN (Linux ioctl; wintun/utun staged), platform classification,
Salamander obfuscation. Acceptance: killswitch and split-tunnel semantics
tested with fake rule engines; TUN unit-tested against a virtual device
abstraction.

## S7 — frontends + packaging

Wire live tunnel status into Flutter/KMP/Qt (they already speak NDJSON
JSON-RPC to holonetd); CI matrix pinned to Rust 1.77.2 for the
Win7/Catalina floor; flatpak/AppImage/NSIS. Acceptance: each frontend
displays real session state driven by the daemon; packaging reproducible
from a clean checkout.

## Descope rule (NAMED at progress review 0002 — closes gate-0001 A3-C1, one cycle late; D-0014, owner may override)

If a stage overruns, cut breadth before cutting honesty: **v1.0 ships
Shadowsocks AEAD + trojan (TLS-based, framing over the S2 holo-tls
client) as the two LIVE protocols — the smallest delta from the shipped
SS data plane, exercising every S1/S2 deliverable (Green-R2 analysis);
hy2/tuic (QUIC-based) are the named ALTERNATES only if S3 completes on
schedule —** with honest milestone errors for everything else — never a
fake or half-validated plane.

**Descope tripwire (progress review 0002, A3-C2/F15; closes gate-0001
A3-C5, one cycle late):** if a stage is not acceptance-complete after
**4** session journals in `harness/memory/sessions/` (calibration: this
rule was written when exactly 1 journal existed), the next gate MUST
decide — split the stage, cut breadth under the descope rule, or extend
with a recorded owner sign-off (DECISIONS.md entry).

**Terminal gate (progress review 0002, A3-C2; closes gate-0001 A3-C5's
terminal-gate requirement): the terminal gate (S7 completion + release
assessment, record number assigned sequentially per WORKFLOW §2.6)
checks: per-platform green matrix; artifact signatures per carried
condition 5; D-0009/D-0013 disclosure status; THREAT-MODEL re-review;
descope-rule conformance — all before any v1.0 publication.**

## Research backlog adopted at progress review 0002

From Green-R1 (fixes/improvements; full table + citations in the run's
report, summarized in the 0002 session journal): R-01 salt-replay cache
(= A2-C1, S1), R-02 ProbeGuard bounding + randomized slow-close (S1),
R-05 subprocess-oracle interop harness against shadowsocks-rust/sing-box
binaries in CI (S1 backlog — CI-side only, D-0002 intact), R-07 OpenSSL
CLI differential + NIST ACVP fixtures (S1 backlog; also closes the
OpenSSL process-evidence debt honestly), R-09 DNS-leak hardening /
remote resolution default (S1 backlog), R-13 write_vectored + zero-copy
memo (S1 backlog), R-14 release hygiene — toolchain pin, --locked,
minisign signatures, one-line SBOM, SLSA L1/L2 (ops, closes D-0009/
D-0013 partially), R-03 configurable first-packet padding (S2+), R-04
SIP004 UDP relay + R-08 SOCKS5 UDP ASSOCIATE (S2+ milestone with
interop acceptance), R-06 fuzz workspace (S2+), R-10 dudect-style
timing tests + u128 audit (S2+, feeds the S1 constant-time bar), R-11
BBR gated / recalibrate vs BBRv3 (S2+), R-12 CoDel hard-limit (S2+),
R-15 auth tightening + config-epoch hot-reload (S2+).

From Green-R2 (features/roadmap): S3 client-relay rescope (applied
above), S5 reorder+cuts (applied above), S6 Salamander rescoping
(applied above), S7 packaging notes (NSIS not MSIX for Win7; flatpak
proxy-mode-only caveat; macOS notarization and Play org-account are
owner-cost decisions to record when S7 charters), WireGuard Noise-IK
coverage note (S1 crypto list covers Noise-IKpsk2 except: generalize
ct_eq into holo-util, ensure BLAKE2s keyed-mode vectors — folded into
S1 items 1–2 annotations), trojan descope naming (applied above).

## Binding conditions carried from gate 0001

Checked at the S1→S2 gate unless a later stage is named. Provenance: round-2
verdicts of A1/A2/A3/A4, archived verbatim in
`harness/adversarial/verdicts/0001-*.md`.

1. **Driver-layer chartering (A3-C1, before the S1→S2 gate)**: S2–S5 must
   name the Registry driver factories each stage registers (S2 delivers
   one TLS-based driver wired into `session.connect`; a WireGuard driver
   stage precedes/accompanies warp_wg); the descope rule must NAME the
   v1.0 TLS/QUIC-based protocol.
2. **Cross-service integration (A3-C6, S5/S6 charters)**: S5 adds a
   provider-fixture → registry → live-dial chain test; S6 adds a
   real-kernel killswitch/nftables Linux CI test or an explicit
   "unverified on real kernel" THREAT-MODEL marker.
3. **v1.0 operationalization + terminal gate 0008 (A3-C5)**: state
   whether TUN/killswitch/packaging are v1.0-blocking; define the
   descope tripwire (stage exceeding N recorded sessions triggers the
   decision); charter the terminal gate (S7 completion + release
   assessment).
4. **backup.sh `--interim` push milestone (A3-C7)**: optional interim
   push after remediation-complete and before panel launches; recorded
   as a DECISIONS entry when added.
5. **Artifact signing (A2-C5, S7 charter)**: minisign/cosign-style
   detached signatures, or a recorded owner decision not to sign.
6. **Off-loopback proxy_listen refusal (A2-C6)**: refuse
   non-loopback binds unless an explicit override is set.
   **SUPERSEDED at progress review 0002 (A3-C4): pulled INTO S1 — the
   "S6 otherwise" deferral exposed a live open-proxy footgun on the
   shipped v0.3.0 plane.**
7. **Mechanical rand-split enforcement (A2-C3, with the S1 FFI work)**:
   grep-audit test or module gating so `fill/bytes/hex/alnum` cannot be
   called for security material by mistake.
8. **XChaCha20 standard compliance (A1-C2, in S1)**: switch holo-ss to
   holo-crypto's standard `aead_xchacha20poly1305_*` (24-byte nonce)
   with draft-irtf-cfrg-xchacha vectors, or de-scope the cipher with an
   honest non-interop note; remove the dead `n24` store
   (holo-ss/src/lib.rs:97-98).
9. **Bookkeeping refresh at every gate (A3-C4)**: STATE.md and
   ARCHITECTURE.md "Current workspace" re-checked against the tree
   (partially done this run).

Applied THIS run (verified, not carried): backup.sh FAILED-marker commit
+ message sanitization (A4-C1/C2), restore fast path `-B main` + token
invocation wording (A4-C3/C4), WORKFLOW §1.3 durability scoping (A4-C5),
.gitignore id_ed25519/id_ecdsa (A4-C6), harness-audit CI job (A4-C6),
ci.yml permissions narrowed to read (A1-F8), holonetctl honest entropy
error (A1-C6), stale "randomized" comments fixed (A2-C2), published-
releases disclosure + D-0009 (A1-C1/C4), per-platform test baselines
(A1-C5), links-importer scope corrected (A3-F3), ARCHITECTURE refresh
(A3-F3/C4), RFC 8448/8017 citations fixed (A3-F8).
