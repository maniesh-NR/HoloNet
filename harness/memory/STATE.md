# HoloNet State Snapshot

Last updated: 2026-11-13 (UTC) — harness/workflow installation run, gate
0001 CLOSED (consensus reached; see `harness/adversarial/verdicts/`).

- Restored from GitHub `maniesh-NR/HoloNet` @ `8dc9b66` (branch `main`)
  after a full sandbox recycle; toolchain reinstalled (rustc 1.100.0);
  git identity = owner's (D-0006). Local commits this run: `8dc9b66` →
  `53ff229` (interim: harness + remediation) → final backup commit.
- Engine: pure-std Rust workspace at `engine/` (edition 2021,
  GPL-3.0-or-later, zero third-party crates, D-0002). **11 crates**:
  holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net,
  holo-crypto, holo-ss, holo-socks, holonetctl, holonetd.
- Tests: **75 green on Linux** (macOS 74 / Windows 72 — cfg-gated tests
  count differently per OS; quote per platform). Verified this run with
  `cargo test --workspace`, exit 0. Baseline 71 at v0.3.0; +4 gate-0001
  hardening tests. The memory regression asserts growth < 2 MB over
  64 MB relayed (Linux-only test).
- **Windows CI is honestly RED on this tree** and stays red until the S1
  Windows entropy FFI lands (D-0008): fail-closed entropy aborts
  token/salt generation on Windows, so the engine integration tests
  cannot pass there yet. Full windows-latest suite green is an S1
  acceptance criterion (ROADMAP S1).
- Live data plane (v0.3.0): Shadowsocks AEAD (SIP004, 3 ciphers), local
  SOCKS5 pooled relay, `session.connect` wiring, honest per-driver
  milestone errors, Material You theme system + Flutter/KMP/Qt frontends
  validated by golden vectors. Share-LINK import for all 7 schemes is
  live (`holo-config/src/links.rs`); remaining import formats (Clash
  YAML, V2Ray/sing-box JSON, WG INI, subscriptions) are S4.
- **Published v0.2.0/v0.3.0 binaries predate the fail-closed entropy
  hardening** (Windows salts/IPC tokens were splitmix64-derived at those
  tags) — disclosure D-0009, escalated to the owner: advisory vs
  v0.3.1 re-release decision pending.
- Gate-0001 hardening (this run): fail-closed entropy
  (`holo-util/src/rand.rs` os_fill vs non-security splitmix; converted
  consumers), ct_eq IPC token compare, 0600 at-rest secrets,
  `docs/THREAT-MODEL.md`, SHA256SUMS on all four release jobs, README /
  TECHNIQUES / ARCHITECTURE claim corrections, backup.sh FAILED-marker
  hardening, .gitignore credential-shape hardening, harness-audit CI
  job (gate-record ↔ backup-log tie-in).
- Harness installed this run (`harness/`): binding workflow, adversarial
  protocol with recorded independence limits, memory files, event-driven
  `scripts/backup.sh`, rolling restore tag `sandbox/latest` (activates
  with this run's end-of-run backup).
- Gate 0001 (S0 → S1): **PASSED on consensus** — round 1: A1
  PROCEED_WITH_CONDITIONS, A2 BLOCK, A3 launch-failure (non-response), A4
  PROCEED_WITH_CONDITIONS; remediation `53ff229`; round 2: ALL FOUR
  reviewers non-BLOCK. Records: `harness/adversarial/verdicts/0001-*`.
  **S1 may start in the next run** under its amended charter and the
  binding conditions listed in ROADMAP ("Binding conditions carried from
  gate 0001").
- Not yet built (see ROADMAP S1+ and docs/RESTORE.md): Windows entropy
  FFI, BLAKE2s/b, X25519, AES-CFB, ExpandLabel, bignum/RSA prep, TLS 1.3,
  QUIC v1, remaining importers, providers, system crates, TUN.

Re-verify after any restore before trusting this file: tree clean at
`sandbox/latest`, `cargo test --workspace` green (75 Linux), CI badge —
expect the windows-latest job RED until S1 lands (see above).
