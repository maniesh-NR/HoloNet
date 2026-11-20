# Research Report RES-01 — S1 pre-flight fixes, improvements, landscape

- Date: 2026-11-20 (UTC). Run: cross-validation progress review 0003.
- Provenance (honest): the researcher SUBAGENT failed twice with empty
  responses (recorded in the 0003 prompts archive); the orchestrator
  ran this research pass directly via web search + local empirical
  checks. Every load-bearing claim carries a citation or an explicit
  "could not confirm". Items marked (speculative) are judgment, not
  fact. Feeds the roadmap; is NOT a verdict and casts no vote.

## 1. Executive summary

1. Rust std still has NO stable CSPRNG as of rustc 1.100.0 (2026-11-09,
   empirically verified in this sandbox: `std::random::random` fails
   with E0658 "use of unstable library feature `random`") — the
   D-0018/D-0008 Windows FFI remains NECESSARY for the stable/1.77.2
   toolchain floor; monitor rust-lang/libs-team issue #393
   (https://github.com/rust-lang/libs-team/issues/393) — even if it
   stabilizes, the project's 1.77.2 Win7/Catalina pin means the FFI
   stays (effort S to re-evaluate each gate).
2. XChaCha20-Poly1305 is STILL AN IETF DRAFT — latest is
   draft-irtf-cfrg-xchacha-03
   (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03;
   the bikeshedders/xchacha-rfc repo's last CFRG push was 2020,
   https://github.com/bikeshedders/xchacha-rfc). Could not confirm any
   newer draft rev or RFC number. Binding condition 8's "draft-irtf-
   cfrg-xchacha vectors" wording is therefore CORRECT as-is, and the
   wire change should cite the draft honestly (effort S: none, wording
   already right).
3. TLS-in-TLS is THE 2024–2026 detection frontier for exactly this
   project's planned v1.0 shape (trojan-over-holo-tls, D-0014): Xue et
   al., "Fingerprinting Obfuscated Proxy Traffic with Encapsulated
   TLS" (USENIX Security '24,
   https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf)
   and the NDSS '25 cross-layer-RTT fingerprint work
   (https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf)
   both give concrete mitigations (RTT alignment, shaping, routing-rule
   hygiene) that the S2/S3 padding and shaping work should adopt as
   named acceptance items (effort M).
4. ECH was published as RFC 9849 in March 2026
   (https://jazz.security/dlp-explained/dlp-basics/encrypted-client-hello-breaks-web-filtering-and-dlp)
   but real-world usage was measured at ~0.06 % of connections against
   a ~2 % ceiling (Corrata, May 2025, cited by
   https://cdt.org/insights/do-not-stick-out-the-dynamics-of-the-ech-rollout)
   — ECH is NOT yet reliable censorship cover; do not charter it for
   v1.0 (speculative but grounded: "do not stick out" dynamics mean
   early-adopter ECH traffic is itself exceptional).
5. For S1c's bignum/RSA verify acceptance, Project Wycheproof (now
   maintained under C2SP) provides the canonical NEGATIVE vector
   classes RsassaPkcs1Verify + RsassaPssVerify
   (https://github.com/C2SP/wycheproof/blob/main/doc/files.md),
   complementing NIST CAVP RSAVS
   (https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures)
   — closes record-0003 A2-C5's negative-test gap with a concrete,
   citable source (effort S to name them in the charter).

## 2. Fixes (chartered S1 items)

- **Windows CSPRNG (item 0, DONE):** RtlGenRandom via SystemFunction036
  for the Win7 SP1 floor remains the right call in 2026: BCryptGenRandom
  has Win8+ caveats on unpatched Win7, ProcessPrng is Win10-era only
  (could not confirm a Windows-version table newer than the D-0018
  rationale — treat as consistent, not freshly verified). The LNK2019
  import-lib lesson (2dae1ce) matches known MSVC behavior for
  header-macro-exported APIs. No action.
- **std CSPRNG:** see Executive summary #1. The empirical check in this
  sandbox is the strongest available evidence; re-run the one-liner at
  each toolchain bump (effort S).
- **XChaCha (condition 8):** see Executive summary #2. HChaCha20 test
  vectors: the draft's appendix carries the HChaCha20/1 test vector;
  the holo-crypto RFC 8439 work already covers the underlying ChaCha
  core (effort S once BLAKE2s lands the module pattern).
- **X25519 (item 2):** record-0003 A2-C3's precision amendment (decode
  per RFC 7748 §5: mask bit 255, little-endian, mod 2^255−19; no
  canonical-form rejection; ct_eq for the all-zero check) matches what
  RFC 7748 §5 literally prescribes for processing; could not confirm
  implementation comparisons (Go/BoringSSL) from primary sources in
  this pass — the A2 verdict flagged the same gap, so the charter's
  "quote the RFC text verbatim when drafting" requirement stands.
- **bignum/RSA verify (item 5):** CIOS Montgomery pitfalls are well
  covered by the charter (final-carry limb). ADD to the acceptance
  (already done in the 0003 charter amendments via A2-C5):
  carry-boundary vectors (modulus top limb all-ones, operand = R−1) and
  Wycheproof RsassaPkcs1Verify/RsassaPssVerify negative classes
  (Bleichenbacher e3 / BERserk-style forgery cases are exactly what
  Wycheproof ships) + NIST CAVP RSAVS as the positive set. Cite:
  https://github.com/C2SP/wycheproof/blob/main/doc/files.md and
  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures.

## 3. Improvements (pure-std relay)

- **Vectored IO:** std::io::Write::write_vectored is stable and usable
  for header+payload coalescing on the relay path (could not confirm
  2026-era semantics changes; treat as stable-API usage) — low-risk
  throughput win for the S1 hardening pass (effort S; requires a
  throughput regression per standing criterion 4 to justify).
- **Read deadlines:** TcpStream::set_read_timeout is the std answer to
  the close-vs-hang DoS elevation (record-0003 A2-F6) — the S1 fix is a
  deadline on the server's first-chunk read, not a select loop (effort
  S).
- **Thread-per-connection:** without mio/epoll (D-0002 forbids the
  crates; std exposes no poller), thread-per-connection + pooled
  buffers remains the honest architecture for the local relay's
  connection counts; the existing BufferPool + DRR shaping already
  covers fairness. No change recommended for v1.0 (speculative for
  >1k-connection servers — out of scope for a local proxy).
- **Memory bounding:** the RSS-delta regression pattern (assert < 8 MB
  over 64 MB relayed, D-0015) is sound; cross-platform caveat is
  runner allocator variance, already handled by the D-0015 evidence.
  No change.

## 4. Landscape + new features (2025–2026)

- **TLS-in-TLS / proxy fingerprinting:** see Executive summary #3. The
  USENIX '24 paper's mitigation section and the NDSS '25 RTT paper
  should be cited in docs/TECHNIQUES.md when the S2/S3 padding/shaping
  items land, with named acceptance tests (RTT alignment between inner
  and outer flows; no cross-layer timing correlation above baseline).
- **ECH:** published (RFC 9849, 2026-03) but deployment is minimal and
  "do not stick out" dynamics apply (CDT, April 2026,
  https://cdt.org/insights/do-not-stick-out-the-dynamics-of-the-ech-rollout);
  firewalls already ship ECH-defense strategies (e.g. Cisco Secure
  Firewall ECH docs). Verdict: not v1.0 cover; revisit post-v1.0 with a
  deployment-uptake gate (speculative).
- **QUIC/UDP blocking:** could not confirm a fresh 2026 measurement
  report in this pass — do NOT quote blocking rates into the roadmap
  without one; the descope rule (D-0014) already makes QUIC-based
  protocols optional at v1.0, which is the safe posture regardless.
- **Provider landscape:** could not confirm material 2025–2026 changes
  to VPN Gate mirrors / WARP registration in this pass; S5a's
  Green-R2 ordering (VPN Gate → Opera → warp_wg) stands. Re-check at
  S5 chartering.
- **Highest-value next live protocol after SS+TLS+QUIC:** the D-0014
  choice (trojan over the S2 holo-tls client) remains the best
  cost/benefit: smallest delta from the shipped SS plane, exercises
  every S1/S2 deliverable, and trojan's design (TLS with a password
  pre-shared key + honest TLS fingerprint) is precisely what the S2
  client ships. Hysteria2/TUIC would additionally need the S3 QUIC
  stack (double dependency); MASQUE ≈ re-scoped S3. Confirmed as the
  recorded default — no change (speculative judgment, consistent with
  the Green-R2 analysis cited in D-0014).

## 5. D-0009/D-0013 playbook

- The record-0002 re-escalation (D-0013) already reconciled the
  release-surface facts (the affected Windows binaries are not publicly
  downloadable; exposure = copies downloaded before removal,
  unknowable). Precedent class for shipped-weak-RNG (Debian OpenSSL
  2008; npm/Go randomness advisories): publish the advisory + fixed
  release; silent deletion is the outlier. The A2 verdict's concrete
  recommendation stands as the best playbook: (a) short Windows-scoped
  advisory with the honest impact triad (fingerprinting/linkability,
  local IPC-token prediction, NOT content decryption — the SIP004 salt
  is wire-public), (b) v0.3.1 cut AFTER S1 item 0 (satisfied — it has
  landed) and BEFORE the XChaCha wire change, (c) if any asset removal,
  Windows zips only, never silent. OWNER DECISION — deadline per
  D-0013 (before S1 is marked DONE).

## 6. Prioritized roadmap recommendations

1. [S] Adopt Wycheproof (C2SP) RsassaPkcs1Verify + RsassaPssVerify and
   NIST CAVP RSAVS as NAMED acceptance sources for S1c — closes the
   A2-C5 negative-test gap with citable vectors. (Applied this run via
   the charter amendment already carried; add the URLs to the S1
   acceptance text at implementation time.)
2. [S] Name TLS-in-TLS mitigations (USENIX '24 / NDSS '25) as S2/S3
   acceptance items: inner/outer RTT alignment and shaping checks in
   docs/TECHNIQUES.md with the citations. (Carried; apply at S2
   chartering.)
3. [S] Add a one-line std-CSPRNG re-check (the E0658 one-liner) to each
   gate's toolchain-bump checklist — if `std::random` stabilizes at a
   releasable Rust, record a D-entry re-evaluating the FFI (the 1.77.2
   floor still keeps the FFI for Windows).
4. [M] write_vectored coalescing on the relay hot path with a
   throughput regression (standing criterion 4) — schedule with the S1
   server-path hardening pass, not before.
5. [S] ECH post-v1.0 watcher entry on the roadmap's opportunities list;
   no v1.0 charter change.
6. [-] No roadmap change for QUIC-blocking rates or provider drift —
   could-not-confirm; revisit at S3/S5 chartering.
