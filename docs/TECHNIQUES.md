# Techniques from the scientific literature

HoloNet's transport layer is built on published, peer-reviewed techniques
rather than ad-hoc heuristics. Each item below names the source paper/spec,
what we implemented, and where the code and its regression tests live.

The rule of the project applies here too: **every claim is backed by a test**
(vector tests for crypto, deterministic link-simulation tests for congestion
control, end-to-end tests for shaping), and anything not yet wired into a
real data path is labeled as such.

## 1. RTT estimation & retransmission timeouts

**Source:** V. Jacobson, "Congestion Avoidance and Control", SIGCOMM '88;
M. Allman, V. Paxson, E. Blanton, "TCP Congestion Control", RFC 5681;
V. Paxson et al., "Computing TCP's Retransmission Timer", RFC 6298.

**What we implement** (`holo_net::RttEstimator`):
- SRTT / RTTVAR EWMA exactly per RFC 6298 (α = 1/8, β = 1/4, first-sample
  rule SRTT = R, RTTVAR = R/2);
- RTO = SRTT + max(G, K·RTTVAR) with K = 4, G = 1 ms clock granularity;
- Karn's algorithm: retransmitted segments never produce RTT samples;
  `on_retransmit()` doubles the RTO with a 60 s cap.

**Tests:** convergence to a stable RTT, spike behavior, backoff doubling
(`holo-net` `rtt_estimator_rfc6298_convergence`).

**Wired into:** the SS dialer records connect RTT samples; the estimator is
the shared building block for the v0.4 QUIC/UDP transports.

## 2. Congestion control

### 2a. BBR (model portion)
**Source:** N. Cardwell, Y. Cheng, C. S. Gunn, Y. A. Wang, H. T. Kaur,
V. Jacobson, "BBR: Congestion-Based Congestion Control", Communications of
the ACM, Vol. 60 No. 2, 2017 (also ACM Queue 2016).

**What we implement** (`holo_net::Bbr`):
- BtlBw max-filter over a delivery-rate window (10 s);
- RTprop min-filter over a 10 s window;
- ProbeBW pacing-gain cycle `[1.25, 0.75, 1, 1, 1, 1, 1, 1]`;
- ProbeRTT: no RTprop refresh for 10 s → drain to 4·MSS for 200 ms;
- cwnd = 2·BDP + 4·MSS quantization headroom (BDP = BtlBw · RTprop).

**Tests:** on a deterministic bottleneck-link model (fixed service rate,
bounded queue, xorshift loss RNG), BBR reaches ≥ 45 % of link capacity
quickly and converges to the bottleneck rate while keeping the maximum
observed RTT under 10× base RTT — i.e. it fills the pipe without filling
the queue (`bbr_converges_near_bottleneck_without_queue_blowup`).

### 2b. CUBIC
**Source:** S. Ha, I. Rhee, L. Xu, "CUBIC: A New TCP-Friendly High-Speed
TCP Variant", ACM SIGOPS Operating Systems Review 42(5), 2008.

**What we implement** (`holo_net::Cubic`): the cubic window function
`W(t) = C(t−K)³ + W_max` with C = 0.4, β = 0.7 multiplicative decrease, the
TCP-friendly region, and RFC 6928 IW10 startup.

### 2c. HyStart++ slow start
**Source:** M. Kühlewind, R. Scheffenegger, B. Briscoe, "HyStart++:
Modified Slow Start for TCP", RFC 9065, 2021.

**What we implement** (inside `holo_net::Cubic`): round-trip grouping of
RTT samples, exit from slow start when the round minimum RTT grows past
eta·min or the 16·MSS threshold, Conservative Slow Start (half-MSS growth)
for 5 rounds before congestion avoidance.

**Tests:** loss-free convergence without collapse
(`cubic_converges_without_collapse`).

**Status:** both controllers are validated and ready, and are the CC layer
of the v0.4 QUIC/UDP transports (kernel TCP does its own CC for the current
Shadowsocks-over-TCP path — layering a userspace CC on kernel TCP would be
theater, so we don't).

## 3. Fair queuing — Deficit Round Robin

**Source:** M. Shreedhar, G. Varghese, "Efficient Fair Queuing Using
Deficit Round Robin", ACM SIGCOMM '95 / IEEE/ACM Transactions on Networking.

**What we implement** (`holo_net::DrrQueue` + `holo_socks::Shaper`): the
deficit-counter scheme — each flow accumulates its quantum per visit and
serves queued items while the deficit covers their byte cost; empty flows
reset their deficit. The local SOCKS relay pushes every chunk through one
shared token bucket, and waiters are served strictly in DRR order so a
single stream cannot monopolize a configured rate limit.

**Tests:** 2:1 quantum fairness invariant held over the whole drain
(`drr_fairness_two_flows`); end-to-end: a 128 KB/s engine rate limit
actually throttles a live tunnel (`shaping_rate_limit_end_to_end` in the
engine integration suite).

## 4. Active queue management — CoDel

**Source:** K. Nichols, V. Jacobson, "Controlling Queue Delay", ACM Queue
10(5), 2012.

**What we implement** (`holo_net::CoDel`): the sojourn-time state machine —
target 5 ms, interval 100 ms, the count-controlled inversesqrt drop
schedule, reset on idle.

**Tests:** zero drops when sojourn stays under target; first drop only
after the interval of persistent overload (`codel_drops_only_under_persistent_overload`).

**Status:** validated; will gate the UDP egress queue of the v0.4 QUIC
transport.

## 5. Pacing — token bucket

**Source:** the token/leaky bucket family as standardized in traffic
conditioning (e.g. RFC 2697/2698-style single-rate conditioning).

**What we implement** (`holo_net::TokenBucket`): continuous refill,
bounded burst, non-blocking `try_acquire` returning the deficit wait, and
a blocking `acquire` capped at 50 ms sleeps so shutdown stays responsive.

**Tests:** burst-then-refill timing accuracy (`token_bucket_limits_rate`).

## 6. Traffic-analysis padding

**Motivation:** P. Sirinam, M. Imani, M. Juarez, M. Wright, "Deep
Fingerprinting: Undermining Website Fingerprinting Defenses with Deep
Learning", ACM CCS 2018 (defenses must hide length); K. Dyer, S. Coull,
T. Ristenpart, T. Shrimpton, "Protocol Misidentification Made Easy with
Format-Transforming Encryption", ACM CCS 2013 (padding as part of
format-shaping).

**What we implement** (`holo_net::Padder`): two policies — uniform-random
padding up to a configurable maximum, and bucket padding to a ladder of
common sizes (64 B … 8 KiB) with a random position inside the bucket so
bucket boundaries themselves don't fingerprint. xorshift64* PRNG seeded
from system time.

**Tests:** bound enforcement for every policy, zero-seed robustness
(`padder_bounds_and_policies`).

**Status:** available to tunnel framings; the current SS frames keep
interop sizes (padding is opt-in per profile in v0.4 framings).

## 7. Active-probing resistance

**Motivation:** the measurement literature on censorship-enforcement
active probing of fully-encrypted proxies (FOCI/'Free and Open
Communications on the Internet' workshop proceedings, 2021–2023): probes
distinguish proxies by their *behavior* on malformed handshakes (response
timing, error codes, connection counts) even when the wire format is
indistinguishable from random.

**What we implement** (`holo_net::ProbeGuard` + `holo_ss::serve_conn`):
- one opaque error for every crypto failure (salt, length, payload) — no
  error-code oracle;
- oversized-length frames treated as auth failures (the classic probe
  trick of claiming a 64 KiB payload) — directly tested by
  `oversized_length_is_rejected_without_upstream` (added at gate 0001);
- per-peer exponential backoff (50 ms doubling, clamped to 120 ms on the
  wire today; the full 10 s cap is staged in ROADMAP S1) with reset on
  successful authentication;
- delayed slow-close before dropping probed connections — deterministic
  today; CSPRNG-jittered randomization is staged with the S1 entropy work
  (the interim exposure is recorded in docs/THREAT-MODEL.md §C).

**Tests:** monotone backoff, success-reset, cap
(`probe_guard_backs_off_and_resets`); wrong-password client never reaches
the upstream dialer (`tampered_salt_is_rejected_strictly`); forged
oversized-length rejection without any upstream dial
(`oversized_length_is_rejected_without_upstream`).

## 8. Memory behavior — buffer pooling

**Source:** engineering practice; validated empirically here.

**What we implement** (`holo_net::BufferPool`): fixed-size 16 KiB relay
buffers recycled through a bounded free-list; over-capacity allocations
are simply not recycled (no unbounded pool growth, no blocking).

**Test result (v0.3.0, Linux, debug build):** relaying **64 MB** through
the full chain (SOCKS5 → SS AEAD tunnel → upstream) grew RSS by **376 KB**
— 0.6 % of the transferred volume — proving the steady state allocates
nothing per chunk (`memory_stays_bounded_under_sustained_relay`).

## 9. Cryptography

All primitives are hand-written std-only implementations validated against
official vectors (see `holo-crypto` tests; also cross-checked against
OpenSSL during development):

- ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, HChaCha20/XChaCha20 —
  Y.-A. Nir, A. Langley, "ChaCha20 and Poly1305 for IETF Protocols",
  RFC 8439. NOTE: the RFC 7539-era printed ciphertext for the §2.4.2
  example is superseded — RFC 8439's value (and OpenSSL's output) is
  authoritative; our test vector comments document this.
- SHA-256/SHA-1 — FIPS 180-4; MD5 — RFC 1321 (only for the legacy
  Shadowsocks password KDF); HMAC — RFC 2104/4231; HKDF — RFC 5869
  (HKDF-SHA1 for the SS session subkey, info "ss-subkey").
- AES-128/192/256 — FIPS 197 (S-box *generated* from the GF(2⁸) inverse +
  affine map, never transcribed); GCM — NIST SP 800-38D (NIST test cases 3
  and 4 reproduced bit-for-bit).
- EVP_BytesToKey — the OpenSSL KDF used by the Shadowsocks password format.

## 10. What we deliberately did NOT integrate (yet)

- **FEC** (forward error correction, à la KCP/Hysteria-era designs):
  adds bandwidth cost; the payoff needs a UDP transport first (v0.4).
- **Masque/HTTP3 datagram scheduling**: depends on the QUIC stack.
- **MPTCP-style multipath scheduling**: our bonding (Dual-Path Active
  Tuning) already covers the user-visible behavior; a paper-grade
  scheduler (e.g. MPTCP's coupled congestion control, RFC 6356) lands
  with the QUIC work.

Every "not yet" here is a documented milestone (docs/RESTORE.md,
docs/ARCHITECTURE.md §12), never a silent stub.
