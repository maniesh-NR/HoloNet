# HoloNet State Snapshot

Last updated: 2026-11-13 (UTC) — harness/workflow installation run, gate
0001 cycle (post-remediation state).

- Restored from GitHub `maniesh-NR/HoloNet` @ `8dc9b66` (branch `main`,
  clean tree) after a full sandbox recycle; toolchain reinstalled
  (rustc 1.100.0); git identity set to the owner's (D-0006).
- Engine: pure-std Rust workspace at `engine/` (edition 2021,
  GPL-3.0-or-later, zero third-party crates, D-0002). **11 crates**:
  holo-util, holo-config, holo-theme, holo-proto, holo-engine, holo-net,
  holo-crypto, holo-ss, holo-socks, holonetctl, holonetd.
- Tests: **75/75 green** — verified this run with
  `cargo test --workspace` (exit 0). Baseline was 71 at v0.3.0; +4
  gate-0001 hardening tests (fail-closed entropy ×2, forged
  oversized-length rejection, secrets-at-rest perms). The memory
  regression asserts growth < 2 MB (Linux-only test, per gate-0001
  A1-C3). CI (`.github/workflows/ci.yml`) mirrors this on
  ubuntu/windows/macos + musl/Android cross-checks + Rust 1.77.2 floor.
- Live data plane (v0.3.0): Shadowsocks AEAD (SIP004, 3 ciphers),
  local SOCKS5 pooled relay, `session.connect` wiring, honest per-driver
  milestone errors, Material You theme system + Flutter/KMP/Qt
  frontends validated by golden vectors.
- Gate-0001 hardening (this run): entropy is FAIL-CLOSED
  (`holo-util/src/rand.rs`: `os_fill` for security material, splitmix64
  demoted to non-security; `random_salt`/`ensure_token` converted; the
  interim Windows state is an explicit error — see THREAT-MODEL §G);
  IPC token compare constant-time (`holo_crypto::ct_eq`); `ipc-token`
  + `profiles.json` owner-only (0600 unix); `docs/THREAT-MODEL.md`
  created; release jobs publish `SHA256SUMS.txt` on ALL four platforms;
  README/TECHNIQUES claims corrected to match code.
- Harness installed this run (`harness/`): binding workflow, adversarial
  protocol with recorded independence limits, memory files,
  `scripts/backup.sh` (FAILED-marker hardening), rolling restore tag
  plan `sandbox/latest`. The tag itself activates with the FIRST
  end-of-run backup — the final step of this very run.
- Not yet built (see `ROADMAP.md` S1+ and `docs/RESTORE.md`): TLS 1.3,
  QUIC v1, importers beyond SS links, providers, system crates, TUN.
- Releases: v0.2.0 and v0.3.0 tags with linux/windows/macos/android
  assets (portable binaries; GUI from source).
- Gate 0001 (S0 → S1 transition): round 1 verdicts A1
  PROCEED_WITH_CONDITIONS, A2 BLOCK, A4 PROCEED_WITH_CONDITIONS, A3
  launch-failure; remediation applied; panel re-run in progress — see
  `harness/adversarial/verdicts/`.

Re-verify after any restore before trusting this file: tree clean at
`sandbox/latest`, `cargo test --workspace` green, CI badge green.
