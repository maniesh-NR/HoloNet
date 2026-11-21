# HoloNet

**A cross-platform VPN and censorship-resistance suite — one Rust engine, three native frontends, one Material You theme.**

[![CI](https://github.com/maniesh-NR/HoloNet/actions/workflows/ci.yml/badge.svg)](https://github.com/maniesh-NR/HoloNet/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/engine-Rust%201.77%2B-orange.svg)](engine/Cargo.toml)
[![Platforms](https://img.shields.io/badge/platforms-Win7%20%E2%80%93%2011%20%7C%20macOS%2010.15%2B%20%7C%20Linux%20%7C%20Android%208%2B-lightgrey.svg)](#platform-matrix)
[![Crates](https://img.shields.io/badge/dependencies-0%20third--party%20crates-success.svg)](ATTRIBUTION.md)
[![Tests](https://img.shields.io/badge/tests-91-green-brightgreen.svg)](#status--honesty)

HoloNet pairs a Rust engine (`holonetd`) with native frontends: Flutter for
Android, Kotlin Multiplatform (Compose) for macOS, and Qt 6/QML for Windows
and Linux. Every frontend is **Material You** (Material Design 3 dynamic
color): one seed color produces the full 33-role M3 palette on every OS —
byte-identical, because all four implementations (Rust/Dart/Kotlin/C++) port
the same verified color engine. On Android 12+ the wallpaper's Monet palette
takes over when dynamic color is on.

```
Flutter (Android)   Compose (macOS)   Qt6/QML (Win+Linux)
        └───────────────┼──────────────────┘
      Material You: one seed → 33 M3 roles on every OS
             NDJSON JSON-RPC over 127.0.0.1:7977
                        │
              holonetd (Rust) — theme.get / settings.set
```

## What's new in v0.3.0 — the first live data plane

- **holo-crypto**: hand-written, std-only ChaCha20 / Poly1305 / AEAD /
  XChaCha20 / AES-256-GCM / SHA-2 / HMAC / HKDF, validated against RFC &
  NIST vectors (OpenSSL CLI cross-checks were also run during development,
  but those session journals were lost to a sandbox recycle before the
  harness existed — they stand as recollection, not recorded evidence;
  re-running them as recorded process evidence is charted in ROADMAP S1).
  Zero dependencies.
- **holo-net**: transport techniques from the published literature —
  RFC 6298 RTT/RTO, CUBIC (SIGOPS 2008) + HyStart++ (RFC 9065), BBR (CACM
  2017, model portion), Deficit Round Robin fair queuing (SIGCOMM '95),
  CoDel AQM (ACM Queue 2012), token-bucket pacing, traffic-analysis
  padding, active-probe guard. Validated with deterministic bottleneck-link
  simulations. Citations and wiring map: [docs/TECHNIQUES.md](docs/TECHNIQUES.md).
- **holo-ss**: the first live protocol — Shadowsocks AEAD (SIP004, wire
  format) client dialer + server relay, three ciphers
  (`chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `aes-256-gcm`),
  strict-fail anti-probing (opaque errors, oversized-length rejection,
  per-peer exponential backoff, delayed slow-close — CSPRNG-jittered
  randomization is staged in S1).
- **holo-socks**: RFC 1928/1929 local SOCKS5 entry point whose relay is
  pooled (steady state allocates nothing: **64 MB relayed → RSS growth
  observed +88–376 KB; asserted bound < 8 MB (D-0015), Linux CI**) and DRR-fair
  under a user-configured rate limit (`relay.max_rate_kbps`).
- **Engine wiring**: `session.connect` probes the server, starts the local
  SOCKS listener from `proxy_listen`, and reports honest per-driver
  milestone errors for every protocol that is not live yet.
- **91/91 tests green** (71 at v0.3.0 plus gate-0001 hardening tests
  plus the S1 hardening items plus the run-8 XChaCha standardization —
  CI-verified run 44872078593: 92 Linux / 91 macOS / 91 Windows,
  cfg-gated counts differ),
  including 6 end-to-end integration tests over real loopback TCP
  (IPC → import → connect → SOCKS → AEAD tunnel → echo → stats →
  disconnect) plus throughput and memory-bounding regressions.

## The Material You pipeline (v0.2.0's centerpiece)

1. **`engine/crates/holo-theme`** — the reference implementation, tested
   (10 tests + golden hex vectors for cross-language port validation):
   sRGB ↔ CIELAB, chroma gamut mapping, six tonal palettes from a seed,
   all 33 M3 roles for light/dark, contrast invariants (≥3:1 on/on pairs).
2. **Daemon bridge** — `theme.get {osTheme}` returns the role map derived
   from the persisted seed; `settings.set` updates it. `holonetctl seed
   "#B3261E" && holonetctl theme dark` shows the whole scheme change live.
3. **Ports** — `app_flutter/lib/material_you.dart`,
   `app_kmp/.../MaterialYou.kt`, `app_qt/cpp/materialyou.{h,cpp}` — the
   same algorithm in each language, validated against the Rust golden
   vectors.
4. **UIs** — M3 expressive in all three: large top app bars, navigation
   bars, FABs, container-scale cards, shape scale, seed pickers; dark /
   light / follow-system everywhere.

## Releases

**Release-surface status (progress review 0002, 2026-11-17 — verified
against the GitHub API):** only three releases are publicly visible today —
`v0.2.0` (empty), `v0.2.0-linux` (static musl tarball + `SHA256SUMS.txt`),
and `v0.3.0` (source tarball only). The per-OS artifacts the v0.2.0/v0.3.0
release workflows built on 2026-11-08 turned out to be unpublished
**drafts** — API-verified and DELETED on 2026-11-20 per decision D-0025
(the two Windows drafts held pre-hardening builds; never republished —
see [security advisory SA-0001](docs/advisories/2026-11-20-sa-0001-v0.2.0-v0.3.0-windows-weak-entropy.md)).
**v0.3.1** is the first full per-OS release, cut from the hardened,
CI-verified tree: `v0.3.1-windows` / `-macos` / `-linux` / `-android`
per-OS builds, plus a main `v0.3.1` release carrying the advisory and a
signed master checksum manifest. `v0.2.0-linux` predates the fail-closed
entropy hardening but is NOT affected by SA-0001 (Linux used
`/dev/urandom`; see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §G).

Intended release matrix (what `release.yml` builds per tag push):

| Tag | Assets | Runs on |
|---|---|---|
| `*-linux` | static musl tarball (x64) | any x86_64 Linux — Mint 20/21/22 and newer |
| `*-windows` | x64 + x86 zip | Windows 7 SP1 – 11 |
| `*-macos` | x64 + arm64 tarballs | macOS 10.15 Catalina + |
| `*-android` | arm64 + armv7 engine tarballs | Android 8.0+ (engine; APK from source) |

Binaries are **portable**: unpack and run, no installer. Release jobs
publish `SHA256SUMS.txt` next to their archives — verify downloads before
running anything (`sha256sum -c SHA256SUMS.txt`). The GUI frontends build
from source — see [docs/BUILDING.md](docs/BUILDING.md). Tag pushes rebuild
everything via [`.github/workflows/release.yml`](.github/workflows/release.yml).

### Verifying release signatures

From v0.3.1 on, the main release carries a signed master checksum
manifest: `SHA256SUMS.txt` (hashes of every per-OS asset) +
`SHA256SUMS.txt.sig` (Ed25519 detached signature). Verify with stock
openssl — no extra tooling:

```bash
openssl pkeyutl -verify -pubin -inkey release-signing.pub   -rawin -in SHA256SUMS.txt -sigfile SHA256SUMS.txt.sig
sha256sum -c SHA256SUMS.txt          # for the files you downloaded
```

`release-signing.pub` lives in this repo under `docs/`. The private
key is generated and held OUTSIDE the repository (mechanism documented
in `harness/memory/DECISIONS.md`, D-0025); re-signing under an
owner-held key is the recorded S7 packaging criterion.

## Quick start

```bash
cd engine
cargo test                        # 87 tests on Linux (86 macOS / 86 Windows — cfg-gated; CI-verified run 44728988531)
cargo build --release -p holonetd -p holonetctl
./target/release/holonetd &       # data dir + IPC token auto-created
./target/release/holonetctl theme dark     # the full M3 role map
./target/release/holonetctl seed "#0061A4" # reseed every frontend
./target/release/holonetctl import "ss://…#MyNode"
```

Frontends: `app_flutter/` (Android), `app_kmp/` (macOS), `app_qt/`
(Windows/Linux) — see `docs/MATERIAL_YOU.md` for the cross-platform
color contract, `docs/BUILDING.md` for building, and `docs/RESTORE.md`
for the engine restoration plan.

## Status & honesty

Complete and tested: the Material You system, the IPC core, and the first
live data plane — Shadowsocks AEAD tunneled through the local SOCKS5
entry point (86 Linux / 85 macOS / 85 Windows tests green — CI-verified
run 44703200189, including six end-to-end loopback
integration tests). The remaining planes (TLS 1.3, QUIC, importers,
providers, system crates) are staged in `harness/memory/ROADMAP.md` from
the designs captured in `docs/RESTORE.md`; every stage transition is
gated by adversarial consensus (see `harness/`). Nothing fakes success:
the connect path reports pending work explicitly, entropy FAILS CLOSED
on every platform without a CSPRNG path, and the security baseline —
including what is deliberately out of scope — is written down in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Harness: memory, backups, adversarial gates

Development runs under a binding execution workflow (`harness/WORKFLOW.md`):

- **Backups are event-driven and always the LAST step** of every execution
  plan and every prompt output — never a fixed time interval. Restoring a
  fresh sandbox is `git clone` + `git checkout sandbox/latest` (rolling tag)
  followed by `harness/memory/SANDBOX-RESTORE.md`.
- **Durable memory lives in the repo** (`harness/memory/`): state snapshot,
  staged roadmap with measurable acceptance criteria, decision log,
  failure lessons, backup log, and per-run session journals — pushed with
  every backup.
- **Stage transitions require adversarial consensus** per
  `harness/ADVERSARIAL.md`: a fixed panel of adversarial reviewers
  (Reliability Skeptic, Security Red, Strategy Adversary, Process Auditor)
  independently examines completed work and the next stage charter; a
  transition happens only when no reviewer blocks. Verdict records are
  hash-chained in `harness/adversarial/verdicts/`.

## Platform matrix

| OS | Arch | Notes |
|---|---|---|
| Windows 7–11 | x86, x64 | Qt 5.15 LTS (Win7) / Qt 6; wintun |
| macOS 10.15+ | x64, arm64 | Compose Multiplatform; utun |
| Linux Mint 20/21/22 | x64, arm64 | Qt 6; /dev/net/tun, nftables |
| Android 8.0+ | armv7, arm64 | Flutter + Monet (12+); VpnService fd attach |

## Attribution

See [ATTRIBUTION.md](ATTRIBUTION.md) — Material Design 3 (Google), the
Rust/Flutter/Kotlin/Qt toolchains, the protocol projects HoloNet targets
(WireGuard, AmneziaWG, Shadowsocks, Xray/VLESS, Hysteria2, …), the free
access providers (Tor, VPN Gate, Proton, WARP, …) and the standards bodies
whose RFCs the clean-room implementations follow.

## Legal

HoloNet is censorship-resistance software. Laws governing VPNs, proxies and
circumvention tools differ by jurisdiction — know yours before using or
redistributing. This project ships only client software: no servers, no
infrastructure, no credentials. The trademark holders named in
[ATTRIBUTION.md](ATTRIBUTION.md) are not affiliated with, and do not
endorse, this project.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE). The notice applies:
HoloNet is distributed under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
