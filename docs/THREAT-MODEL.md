# HoloNet Threat Model

Created at gate 0001 (review A2 condition C2). Maintained under the
harness workflow: changes are decision-log entries, never silent edits.
This document states what HoloNet defends, what it does NOT defend, and
which code carries each promise.

## Adversary classes

### A. Local co-resident adversary

A hostile process, or another user, on the SAME machine (stalkerware, a
shared PC, an over-reaching "IT admin"). In scope, partially.

Defenses (shipped):
- IPC listens on 127.0.0.1:7977 only, every method except `hello`/`ping`
  requires prior token auth (`engine/crates/holo-engine/src/lib.rs`).
- The IPC token is generated from **fail-closed OS entropy**
  (`holo_util::rand::os_hex`) and compared **constant-time**
  (`holo_crypto::ct_eq`).
- `ipc-token` and `profiles.json` are written owner-only (0600, unix)
  — profiles carry proxy passwords and WireGuard private keys.

Accepted limits (honest):
- Root/ptrace, memory inspection, and keyloggers are OUT of scope — no
  client-only software defends those.
- The local SOCKS listener binds without its own auth; `proxy_listen`
  must stay a loopback address. Binding it off-loopback is an
  open-relay footgun the user must avoid (hardening staged with the S6
  killswitch/split-tunnel work).
- `harness/scripts/backup.sh` passes the GitHub token in a push URL,
  transiently visible in process argv during a backup — accepted
  single-user-sandbox tradeoff (documented; a credential-helper flow is
  the backlog alternative).

### B. On-path DPI censor (middlebox)

The primary adversary. In scope.
- Shadowsocks AEAD (SIP004) wire traffic is indistinguishable from
  random bytes; three ciphers; per-direction independent nonces.
- Padding policies (traffic-analysis countermeasures with literature
  citations, `docs/TECHNIQUES.md`) are opt-in per profile.
- TLS 1.3 (S2) and QUIC (S3) staging adds SNI masking and QUIC-framed
  paths.

Accepted limits: volume/timing metadata remain visible unless padding is
enabled; no cover traffic; TCP-level behavioral fingerprinting is only
mitigated by future framing stages.

### C. Active prober (connects to the user's server and forges handshakes)

In scope. NOTE: the shipped daemon runs the SS CLIENT; the server relay
(`serve_conn`) is exercised by tests and self-hosting.

Defenses (shipped, tested):
- ONE opaque error for every crypto failure — salt, length, payload
  (`holo-ss/src/lib.rs`, `auth_failed()`); no error-code oracle.
- Forged oversized length (the classic prober trick) is rejected as an
  auth failure and never dials upstream
  (`oversized_length_is_rejected_without_upstream`).
- A wrong-password client provably never reaches the upstream dialer
  (`tampered_salt_is_rejected_strictly`).
- Per-peer exponential backoff, reset on success (`holo_net::ProbeGuard`).

Accepted limits (staged in ROADMAP S1, "server-path hardening"):
- Close-vs-hang timing can distinguish "length decrypted and in-range"
  from "length rejected" — uniformization staged.
- The slow-close delay is deterministic today (50ms·2^n clamped to
  120 ms on the wire); CSPRNG-jittered randomization staged with the S1
  entropy work.
- ProbeGuard maps have no decay/eviction yet — unbounded growth under
  many distinct failing peers (memory DoS on a long-running server);
  staged.
- UDP is not implemented and reports an honest milestone error.

### D. Upstream observer (the chosen exit server operator)

Limited by design: the exit sees destinations and post-exit traffic.
Choosing a server is a trust decision HoloNet cannot remove. Future
stages (S5 providers, chain modes) widen the choice set only.

### E. Supply chain / substituted binary

In scope, partially:
- EVERY release job (linux, windows, macos, android) publishes
  `SHA256SUMS.txt` next to its archives — verify with
  `sha256sum -c SHA256SUMS.txt` before running anything.
- Zero third-party crates (D-0002) keeps the dependency attack surface
  empty; CI pins the Rust 1.77.2 legacy floor and cross-checks
  musl/Android builds.

Accepted limits: no artifact signing yet (backlog); checksums hosted on
GitHub are not MITM-proof if GitHub itself is hostile to the user —
verify out-of-band where possible; CI actions are pinned to major tags,
not SHAs (backlog).

### F. Implementation side channels (remote timing / cache attacks on our crypto)

**OUT OF SCOPE — stated honestly:**
- AES in holo-crypto is table-based: cache-timing exposure exists.
  ChaCha20-Poly1305 is the recommended default where this matters;
  AES-256-GCM remains available.
- `ct_eq` (constant-time equality) guards AEAD tag verification and the
  IPC token compare.
- Rust std guarantees no constant-time execution anywhere; RFC/NIST
  vectors prove CORRECTNESS, not timing resistance. Revisit if threat
  intel changes (e.g., demonstrated remote cache timing on proxies).

## G. Entropy (cross-cutting — decision D-0008)

Security material (AEAD salts, auth tokens, future keys/nonces) comes
ONLY from `holo_util::rand::os_fill` — **fail-closed**:

- Unix (Linux, macOS, Android): `/dev/urandom`; a read failure is a hard
  error, never a fallback.
- Windows: pure std has NO CSPRNG and `/dev/urandom` does not exist —
  `os_fill` FAILS CLOSED with an explicit error. Windows binaries shipped
  today therefore REFUSE to generate security material rather than
  silently degrading (a dial attempt errors: "os entropy unavailable").
  This is the honest interim state; S1 stages the audited, contained FFI
  exception (RtlGenRandom / BCryptGenRandom) scoped to
  `engine/crates/holo-util/src/rand.rs` ONLY, re-reviewed at every gate.
- `splitmix64` remains for NON-security uses only (IDs, jitter, test
  data) and is documented as such at the source.

## Revision history

- 2026-11-13 — created at gate 0001 (A2-C2), including the D-0008
  entropy decision recorded in `harness/memory/DECISIONS.md`.
