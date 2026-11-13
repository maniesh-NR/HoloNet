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

## S1 — entropy + crypto extensions — NEXT (gate 0001: consensus, binding conditions applied)

Charter: the security foundation the TLS/QUIC stages need, in dependency
order. **Amended at gate 0001** (A2 conditions C1/C2, findings F1/F2/F9;
bignum/RSA prep moved here from S2).

0. **Per-platform CSPRNG, fail-closed** (A2-C1, blocks everything else).
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
2. X25519 (RFC 7748) — a24 = 121665; inversion exponent p−2 with limb 0
   0xffffffeb…; reject the all-zero shared secret.
   **Contributory-behavior policy (A2): all-zero-output check ONLY,
   TLS 1.3-style; non-canonical u-coordinates accepted as-is — documented
   so S2/S3 inherit a decision, not an accident.**
3. AES-CFB (NIST SP 800-38A) — legacy provider paths only.
   **Constraint (A2): unauthenticated; forbidden outside an authenticated
   wrapper.**
4. TLS 1.3 key schedule helpers: HKDF-Expand-Label / Derive-Secret per
   RFC 8446 §7.1.
5. **Bignum + RSA verification prep (moved from S2, A2-F9):** CIOS
   Montgomery multiplication, RSA PKCS#1 v1.5 + PSS verify — S2's
   CertVerify needs them; final-carry-limb pitfall applies.

Server-path hardening backlog (A2-F5; must land by S2):
- ProbeGuard: use the recorded `last` — decay and evict stale peers (the
  map currently grows unboundedly per distinct failing peer).
- Randomized slow-close via CSPRNG jitter (deterministic today).
- Uniform close-vs-hang behavior for rejected vs valid length frames
  (distinguisher recorded in THREAT-MODEL §C).

Acceptance criteria (all measurable):
- Fail-closed entropy: failure-injection test green
  (`os_entropy_fails_closed_on_unreadable_source`); Windows entropy FFI
  merged with tests; provenance current in THREAT-MODEL.md §G.
- Windows enforceability (A3-C3): the FULL workspace suite — including
  the 5 engine integration tests — green on `windows-latest` CI (today
  that job is honestly red: fail-closed entropy aborts token/salt
  generation on Windows; turning it green IS the visible pass condition
  for the FFI); a Windows 1.77.2 compile check (windows-latest pinned to
  1.77.2 or `cargo check --target x86_64-pc-windows-msvc` in the legacy
  job); a Windows FFI failure-injection seam analogous to `os_fill_at`.
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
- Server-path hardening, named tests (A3-C2, gate 0002 checks them):
  ProbeGuard map bounded under N distinct failing peers (decay/eviction
  test); CSPRNG-jittered slow-close seeded from `os_fill` (two peers with
  identical failure counts get different delays); close-vs-hang
  uniformity for length-rejected vs length-valid frames.
- OpenSSL cross-checks during development, recorded in the session
  journal (process evidence, not an in-tree artifact — stated per A1-F10).
- No new third-party crates; the ONLY permitted unsafe is the chartered
  Windows entropy FFI (D-0008); workspace test count grows
  monotonically per platform from the post-gate-0001 baselines
  (Linux 75 / macOS 74 / Windows 72 — cfg-gated tests count differently
  per OS, A1-C5).
- Gate 0002 (S1 → S2) required before starting TLS.

## S2 — holo-tls: from-scratch TLS 1.3 client (RFC 8446)

X25519, suites 0x1301/02/03, HRR cookie, RSA CertVerify (PKCS#1 v1.5 +
PSS via CIOS Montgomery bignum — final carry limb!), SPKI pinning, SNI
masking, hostname match, in-crate loopback server with embedded RSA-2048
cert. ~18 tests. Acceptance: full handshake + application data over
loopback; transcript-hash mismatch and pin mismatch rejected; downgrade
attempts rejected.

## S3 — holo-quic: from-scratch QUIC v1 (RFC 9000/9001/9221)

Initial salt, header protection (AES / ChaCha 5-byte, sample after the pn
field), pn decode window seeded from the FIRST packet, CRYPTO reassembly
by offset, server flight in Handshake packets, SCID alias map. ~25 tests
incl. 100 KB loopback echo. Acceptance: handshake + stream data + loss
recovery over a lossy simulated link; interop-observable framing only
(loopback).

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

## S5 — holo-provider

Opera/SurfEasy digest-auth RPC (api2.sec-tunnel.com v4/*, se0316 creds,
4 h cache), VPN Gate CSV + mirror, Cloudflare WARP registration
(v0a4005/reg → warp_wg + warp_masque + dualpath), Mozilla Guardian,
Proton, Tor, Obscura, Lantern. ~51 tests. Acceptance: offline fixtures
only (no live network in tests), cache semantics tested, no credential
material committed.

## S6 — system crates

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

## Descope rule (proposed default, owner may override)

If a stage overruns, cut breadth before cutting honesty: v1.0 may ship
with fewer live protocols (SS + one TLS/QUIC-based protocol) and honest
milestone errors for the rest — never a fake or half-validated plane.

## Binding conditions carried from gate 0001

Checked at gate 0002 unless a later stage is named. Provenance: round-2
verdicts of A1/A2/A3/A4, archived verbatim in
`harness/adversarial/verdicts/0001-*.md`.

1. **Driver-layer chartering (A3-C1, before gate 0002)**: S2–S5 must
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
6. **Off-loopback proxy_listen refusal (A2-C6; S6 otherwise)**: refuse
   non-loopback binds unless an explicit override is set.
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
