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
- RFC 7693 official vectors for BLAKE2s/b (keyed and unkeyed) pass.
- RFC 7748 §5.2 test vectors (including iteration counts) pass; the
  all-zero shared secret is rejected as an error, not silently accepted.
- NIST SP 800-38A CFB128 vectors pass.
- ExpandLabel vectors from RFC 8446 §7.1 (and its test-vector appendix)
  pass.
- RSA/bignum: CIOS Montgomery and PKCS#1 v1.5 + PSS verify pass official
  vectors (RSA-2048 self-test cert).
- OpenSSL cross-checks during development, recorded in the session
  journal (process evidence, not an in-tree artifact — stated per A1-F10).
- No new third-party crates; the ONLY permitted unsafe is the chartered
  Windows entropy FFI (D-0008); workspace test count grows monotonically
  from the post-gate-0001 baseline of 75.
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

Clash YAML (reality-opts, ws-opts; inline `[IPv6]:443` is a scalar, not a
flow list), V2Ray/sing-box JSON (incl. classic wireguard `local_address`),
share links (ss SIP002 + legacy, vmess b64 JSON, vless reality, trojan,
hy2, tuic, wg), WireGuard/AmneziaWG INI (Jc/Jmin/Jmax → amneziawg), base64
subscriptions. ~40 tests. Acceptance: every importer round-trips into the
flat driver parameter registry (ARCHITECTURE §6) and feeds a live driver
end-to-end where that driver exists (SS today; others as they land).

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
