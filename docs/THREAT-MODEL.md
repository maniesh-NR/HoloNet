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
  must stay a loopback address. Consequence TODAY (progress review 0002,
  A2-F10): while it is loopback, ANY local process can ride the tunnel
  and blend its traffic with the user's — loopback is a co-location
  boundary, not an authentication boundary. Binding off-loopback would
  additionally create an unauthenticated open proxy; refusal (unless
  explicitly overridden) is chartered in S1 (A3-C4), not deferred to S6.
- `harness/scripts/backup.sh` passes the GitHub token in a push URL,
  transiently visible in process argv during a backup — accepted
  single-user-sandbox tradeoff (documented; a credential-helper flow is
  the backlog alternative).
- Secret files (`ipc-token`, `profiles.json`) are created with the
  default umask and tightened to 0600 immediately after — std Rust
  cannot create-with-mode, so a brief window exists (accepted interim,
  gate-0001 A1-F7); FFI-based restrictive-create is the S6 backlog.

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
- **Salt REPLAY is not defended (progress review 0002, A2-F2 — raised
  from omission to explicit limit):** the server keeps NO seen-salt
  cache, so a censor who captures a genuine client handshake (salt +
  first chunk) can replay it; the server will accept, re-dial the
  recorded target, and behave observably differently from
  reference implementations that reject replays — a known active-probe
  fingerprint (IMC '20). A bounded exact-match salt cache with
  opaque-path rejection (identical behavior to garbage — no new
  oracle, no Bloom filter per SIP022's false-positive prohibition) is
  chartered in S1 (A2-C1).
- Close-vs-hang timing can distinguish "length decrypted and in-range"
  from "length rejected" — uniformization staged.
- The slow-close delay is deterministic today (50ms·2^n clamped to
  120 ms on the wire); CSPRNG-jittered randomization staged with the S1
  entropy work (the deterministic delay is itself a fingerprint —
  NDSS '20 "Detecting Probe-resistant Proxies").
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
  `sha256sum -c SHA256SUMS.txt` before running anything. (The checksum
  steps were added in the gate-0001 run; the PUBLISHED v0.2.0/v0.3.0
  release assets predate them and carry no checksum files — the first
  checksummed release will be the next tag push.)
- **Release-surface reality (progress review 0002, A1-F3, API-verified
  2026-11-17):** only `v0.2.0` (empty), `v0.2.0-linux` (tarball +
  SHA256SUMS.txt), and `v0.3.0` (source only) are publicly visible. The
  per-OS v0.2.0/v0.3.0 binaries the workflows built are NOT currently
  downloadable; the D-0009 exposure list must be read against this
  reality (see DECISIONS D-0013).
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
- Windows (S1 item 0 LANDED 2026-11-19, D-0008/D-0018): `os_fill` calls
  **RtlGenRandom** (advapi32 SystemFunction036) via the chartered,
  contained FFI exception scoped to
  `engine/crates/holo-util/src/rand.rs` ONLY — the sole `unsafe` in the
  workspace, re-reviewed at every gate. Fail-closed preserved: any
  syscall failure is an explicit error (test-covered via the injection
  seam), never a weak fallback. RtlGenRandom (not BCryptGenRandom) is
  the call because it has existed since Windows XP, covering the
  Windows 7 SP1 floor without a CNG-availability caveat.
- **Windows secret-at-rest (D-0018, with the S1 FFI):** `ipc-token` and
  `profiles.json` live under the resolved data dir
  (`HOLONET_DATA` → `HOME` → `USERPROFILE` → hard error; CWD fallback
  REMOVED — A2-C2). std Rust cannot set Windows ACLs without further
  FFI, which D-0008's containment forbids; the recorded decision is to
  rely on the per-user ACLs Windows applies to profiles under
  `\Users\<user>\` (user + Administrators + SYSTEM). Residual: another
  admin/SYSTEM-privileged local actor can read the token/profiles —
  consistent with §A's accepted limits (root/ptrace out of scope).
  Revisit only if a threat model change requires tighter ACLs.
- `splitmix64` remains for NON-security uses only (IDs, jitter, test
  data) and is documented as such at the source.
- **Windows secret-at-rest (progress review 0002, A2-F4/C2):** the
  0600 owner-only writes are unix-only (`#[cfg(unix)]`); std Rust has
  no Windows ACL API, and the daemon's data dir falls back
  `HOME` → `"."` (relative CWD) — on Windows `HOME` is usually unset.
  Today this is masked (fail-closed entropy aborts before any write);
  the S1 Windows FFI acceptance therefore ALSO requires: data-dir
  fallback to `USERPROFILE`, hard error when neither `HOLONET_DATA`
  nor `HOME`/`USERPROFILE` resolves (never CWD), and a recorded
  Windows ACL decision for `ipc-token`/`profiles.json`.
- **Disclosure (gate 0001, A1-C1):** the PUBLISHED v0.2.0/v0.3.0
  binaries predate this hardening — at those tags, Windows builds
  generated AEAD salts and the IPC token from the splitmix64 fallback
  (time/pid-seeded, predictable). The fail-closed behavior above
  applies from the gate-0001 remediation commit (53ff229) onward.
  Owner decision required (D-0009): publish an advisory or cut a
  v0.3.1 re-release from the hardened tree.

## Revision history

- 2026-11-13 — created at gate 0001 (A2-C2), including the D-0008
  entropy decision recorded in `harness/memory/DECISIONS.md`.
- 2026-11-17 — progress review 0002 amendments: §A local-SOCKS-hop
  consequence made explicit (A2-F10); §C salt-replay omission raised to
  an explicit accepted limit with the S1 cache charter (A2-C1/F2), slow-
  close fingerprint citation added; §E public release-surface reality
  recorded (A1-F3); §G Windows secret-at-rest gap and S1 acceptance
  additions (A2-F4/C2).
