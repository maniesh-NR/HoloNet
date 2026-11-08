# Attribution & Credits

HoloNet is clean-room software: everything under `engine/` was written from
scratch against public specifications — RFCs, NIST test vectors, published
protocol documents and vendor APIs — with **zero third-party Rust crates**.
None of the projects below contributed code to HoloNet; they contributed the
ideas, specifications and open ecosystems that HoloNet is built to
interoperate with. Credit where credit is due.

## Design language

- **Material Design 3 / Material You** — Google. The color system (tonal
  palettes, the 33 color roles, dynamic color) follows Google's published
  Material Design 3 guidelines and its open-source
  `material-color-utilities` reference (Apache-2.0). `holo-theme` implements
  the same contract using CIELAB tone/chroma — a documented deviation from
  Google's HCT color space (see
  [docs/MATERIAL_YOU.md](docs/MATERIAL_YOU.md)).

## Toolchains & frameworks

- **Rust** — the Rust Foundation and contributors (MIT OR Apache-2.0).
- **Flutter / Dart** — Google (BSD-3-Clause) — the Android frontend.
- **Kotlin & Compose Multiplatform** — JetBrains (Apache-2.0) — the macOS
  frontend.
- **Qt 6 / QML** — The Qt Company (GPL-3.0 / LGPL-3.0) — the Windows &
  Linux frontend.

## Protocol specifications HoloNet targets

The data planes for these protocols are on the restoration roadmap
([docs/RESTORE.md](docs/RESTORE.md)); their designs are the work of the
people and projects below:

- **WireGuard®** — Jason A. Donenfeld and contributors. WireGuard is a
  registered trademark of Jason A. Donenfeld.
- **AmneziaWG** (including the Salamander obfuscation) — the Amnezia project.
- **Shadowsocks** — clowwindy and the Shadowsocks contributors.
- **VLESS / REALITY** — the XTLS / Xray-core project.
- **V2Ray** — the V2Ray / v2fly community.
- **sing-box** — SagerNet.
- **Hysteria2** — the Hysteria project.
- **TUIC** — the TUIC project.
- **NaïveProxy** — klzgrad.
- **Cloak** — the Cloak project.
- **Lampshade**, **Cover-DTLS**, **Samizdat** — their respective authors.
- **OpenVPN** (used over Cloak) — OpenVPN Inc.
- **IKEv2/IPsec** (RFC 7296), **MASQUE** (RFC 9298 / RFC 9484),
  **TLS 1.3** (RFC 8446), **QUIC** (RFC 9000 / RFC 9001) — the IETF.

## Free / visitor access services the provider layer targets

- **Tor** — The Tor Project, Inc.
- **VPN Gate** — the Academic project of the University of Tsukuba, Japan
  (Daiyuu Nobori).
- **Opera VPN** — Opera (SurfEasy infrastructure).
- **Proton VPN** — Proton AG (free tier).
- **Cloudflare WARP** — Cloudflare, Inc.
- **Mozilla / Firefox Private Network (Guardian)** — Mozilla.
- **Lantern** — the Lantern project.
- **Obscura** — Obscura VPN.

## Ideas worth naming

- **Speedify** (Connectify) — the channel-bonding user experience that
  inspired HoloNet's dual-path bonding design.
- **Oblivion** — the unofficial WARP clients that inspired the WARP
  front-hop / behind-hop workflows.

## Cryptography & color test vectors

RFC 8439 (ChaCha20-Poly1305), RFC 7748 (X25519), RFC 8032 (Ed25519),
FIPS 197 (AES), NIST CAVP (AES-GCM, SHA-2) and RFC 7693 (BLAKE2) vectors
were used to validate the cryptography core; the Material You golden
vectors follow Google's published values.

## This repository

HoloNet's code was written from scratch for this project, developed with
AI assistance (GLM, by Z.ai) under the direction of the repository owner.
The project's honesty rule applies here too: features that are not finished
report themselves as unfinished — in the binaries and in the docs.
