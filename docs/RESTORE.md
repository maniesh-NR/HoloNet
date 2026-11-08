# Engine restoration plan (post-recycle)

The protocol engine was previously built and tested (197 tests) across two
sessions. A sandbox recycle wiped the tree; this session rebuilt the
compact core (util/proto/config/links/engine/theme/bins — 28 tests) plus
the full Material You system (see docs/MATERIAL_YOU.md). The pieces below
are captured in enough detail to rebuild quickly — each was debugged to
green in the earlier sessions, pitfalls included.

## Previously built & tested (rebuild in this order)

1. **holo-crypto** — ChaCha20/Poly1305/AEAD (RFC 8439), BLAKE2s/b
   (RFC 7693 — ROTR not ROTL!), SHA-1/2/MD5, HMAC, HKDF + TLS 1.3
   ExpandLabel, AES (FIPS-197) + CFB + GCM (NIST), X25519 (RFC 7748;
   a24 = 121665, invert exponent = p−2 = 0xffffffeb… limb 0).
   ~15 vector tests.
2. **holo-tls** — from-scratch TLS 1.3 client (RFC 8446): X25519, suites
   0x1301/02/03, HRR cookie, RSA CertVerify (PKCS#1 v1.5 + PSS via a
   bignum with CIOS Montgomery — remember the final carry limb), SPKI
   pinning, SNI masking, hostname match, in-crate loopback server with an
   embedded RSA-2048 cert. ~18 tests.
3. **holo-quic** — from-scratch QUIC v1 (RFC 9000/9001/9221): Initial salt
   38762cf7f55934b34d179ae6a4c80cadccbb7f0a; header protection (AES mask /
   ChaCha 5-byte, sample after the pn field); pn decode window seeded from
   the FIRST packet (not u64::MAX — the bug that dropped packets ≥ 128);
   CRYPTO reassembly by offset; server flight in Handshake packets; test
   server keyed by SCID alias map. ~25 tests incl. 100KB loopback echo.
4. **holo-config importers** — Clash YAML (reality-opts, ws-opts),
   V2Ray/sing-box JSON (incl. classic wireguard `local_address`), share
   links (ss SIP002 + legacy, vmess b64 JSON, vless reality, trojan, hy2,
   tuic, wg), WireGuard/AmneziaWG INI (Jc/Jmin/Jmax… → amneziawg),
   base64 subscriptions. ~40 tests. YAML: inline `[2001:db8::1]:443` is a
   scalar, not a flow list.
5. **holo-provider** — Opera/SurfEasy digest-auth RPC (api2.sec-tunnel.com
   /v4/*, se0316 creds, 4h cache), VPN Gate CSV + mirror, Cloudflare WARP
   registration (v0a4005/reg, client_id → reserved bytes) → warp_wg +
   warp_masque + dualpath profiles, Mozilla Guardian, Proton, Tor,
   Obscura, Lantern. ~51 tests.
6. **System crates** — bonding (Dual-Path Active Tuning: hot-standby,
   stripe, mirror; intent scoring), DNS + adblock filter matcher,
   killswitch (nftables), split tunnel, TUN (Linux ioctl; wintun/utun
   staged), platform classification, Salamander obfuscation.
7. **Frontends + packaging** — Flutter/KMP/Qt (now Material You —
   this session), CI matrix (Rust 1.77.2 pins for Win7/Catalina),
   flatpak/AppImage/NSIS.

## Reference material still valid

- docs/ARCHITECTURE.md §6 driver parameter registry (flat string maps)
- The Material You settings keys are already wired: `theme_mode`,
  `seed_color`, `dynamic_color` (holo-config Settings + theme.get).
