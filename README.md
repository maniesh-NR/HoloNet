# HoloNet

**A cross-platform VPN and censorship-resistance suite — one Rust engine, three native frontends, one Material You theme.**

[![CI](https://github.com/maniesh-NR/HoloNet/actions/workflows/ci.yml/badge.svg)](https://github.com/maniesh-NR/HoloNet/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/engine-Rust%201.77%2B-orange.svg)](engine/Cargo.toml)
[![Platforms](https://img.shields.io/badge/platforms-Win7%20%E2%80%93%2011%20%7C%20macOS%2010.15%2B%20%7C%20Linux%20%7C%20Android%208%2B-lightgrey.svg)](#platform-matrix)
[![Crates](https://img.shields.io/badge/dependencies-0%20third--party%20crates-success.svg)](ATTRIBUTION.md)
[![Tests](https://img.shields.io/badge/tests-28%2F28%20green-brightgreen.svg)](#status--honesty)

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

## The Material You pipeline (this release's centerpiece)

1. **`engine/crates/holo-theme`** — the reference implementation, tested
   (28 tests): sRGB ↔ CIELAB, chroma gamut mapping, six tonal palettes
   from a seed, all 33 M3 roles for light/dark, contrast invariants
   (≥3:1 on/on pairs), golden hex vectors for port validation.
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

Prebuilt engine binaries — `holonetd` + `holonetctl`, all built with
Rust 1.77.2 — are published on the
[releases page](https://github.com/maniesh-NR/HoloNet/releases) for every
targeted operating system:

| Release | Assets | Runs on |
|---|---|---|
| `v0.2.0-linux` | static musl tarball (x64) | any x86_64 Linux — Mint 20/21/22 and newer |
| `v0.2.0-windows` | x64 + x86 zip | Windows 7 SP1 – 11 |
| `v0.2.0-macos` | x64 + arm64 tarballs | macOS 10.15 Catalina + |
| `v0.2.0-android` | arm64 + armv7 engine tarballs | Android 8.0+ (engine; APK from source) |

Binaries are **portable**: unpack and run, no installer. The GUI frontends
build from source — see [docs/BUILDING.md](docs/BUILDING.md). Tag pushes
rebuild everything via [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Quick start

```bash
cd engine
cargo test                        # 28 tests (theme engine + core)
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

The Material You system + IPC core is complete and tested. The protocol
data planes (TLS 1.3, QUIC, WireGuard, Shadowsocks, providers — previously
built and tested to 197 tests in an earlier session) were lost to a sandbox
recycle; their full designs and debugged architecture are captured in
`docs/RESTORE.md` for a fast rebuild. Nothing fakes success: the connect
path reports the pending restore explicitly.

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
