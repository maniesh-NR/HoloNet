# HoloNet Architecture

HoloNet is a cross-platform privacy and censorship-resistance client. One
**Rust** engine (`holonetd`) implements the control plane, the Material You
theme service and the JSON-RPC IPC; three native frontends (Flutter for
Android, Compose Multiplatform for macOS, Qt 6/QML for Windows and Linux)
render Material You UIs over it. GPL-3.0, zero external crates.

## System overview

```
Flutter (Android)   Compose (macOS)   Qt6/QML (Win+Linux)
        └───────────────┼──────────────────┘
      Material You: one seed → 33 M3 roles on every OS
             NDJSON JSON-RPC 2.0 (127.0.0.1:7977, token auth)
                        │
                   holonetd (Rust)
        theme.get / settings.set / profiles / events
```

## Current workspace

```
engine/crates/
  holo-util/     hex, base64, JSON model, randomness
  holo-theme/    Material You color engine (reference, 10 tests + goldens)
  holo-proto/    driver SPI: Params, Conn/Dialer/Driver/Registry
  holo-config/   Profile/Settings/Store + share-link importer (9 tests)
  holo-engine/   IPC server/client, theme bridge, sessions (4 tests)
  holonetd/      daemon binary
  holonetctl/    CLI (state/list/import/theme/seed/connect)
app_flutter/     Android: material_you.dart + M3 UI + Monet channel
app_kmp/         macOS: MaterialYou.kt + Compose M3 UI
app_qt/          Win/Linux: materialyou.{h,cpp} + QML M3 UI
docs/            MATERIAL_YOU.md · RESTORE.md · this file
```

The protocol data planes (crypto, TLS 1.3, QUIC, WireGuard, Shadowsocks,
providers, bonding…) were built and tested to 197 tests in earlier
sessions and lost to a sandbox recycle; `docs/RESTORE.md` captures their
debugged designs for a fast rebuild. The connect path honestly reports
the pending restore — nothing fakes success.

## Material You data flow

1. Seed (`seed_color`) persists in the daemon settings store.
2. `theme.get {osTheme}` → holo-theme derives light/dark roles → 33-role
   hex map (+ `_mode`, `_seed`, `_dynamic` metadata).
3. Frontends re-derive locally with their own port of the same engine
   (offline-first) and reconcile with the daemon on connect.
4. `settings.set` reseeds → every frontend on every OS follows.

See docs/MATERIAL_YOU.md for the full cross-platform color contract.

## Platform matrix

| OS | Arch | Frontend | Notes |
|---|---|---|---|
| Windows 7–11 | x86, x64 | Qt 5.15 (Win7) / Qt 6 | wintun (staged) |
| macOS 10.15+ | x64, arm64 | Compose Multiplatform | utun (staged) |
| Linux Mint 20/21/22 | x64, arm64 | Qt 6 | /dev/net/tun, nftables |
| Android 8.0+ | armv7, arm64 | Flutter + Monet (12+) | VpnService fd attach |
