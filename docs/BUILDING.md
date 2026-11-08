# Building HoloNet

## Engine (all platforms)

Requirements: **Rust 1.77.2+**. The release builds pin 1.77.2 so the Windows
binaries run on Windows 7 SP1 and the macOS binaries on 10.15 Catalina
(Rust dropped Windows 7 in 1.78). The engine has **zero third-party crates**
— no vendoring, no network fetches beyond the toolchain itself.

```bash
cd engine
cargo test --workspace                 # 28 tests
cargo build --release -p holonetd -p holonetctl
# → engine/target/release/{holonetd,holonetctl}
```

Cross-builds (same sources, per-platform toolchains):

| Target | Command | Notes |
|---|---|---|
| Linux (any distro) | `rustup target add x86_64-unknown-linux-musl` then `cargo build --release --target x86_64-unknown-linux-musl …` | fully static, runs on Mint 20/21/22+ |
| Windows x64/x86 | `rustup target add i686-pc-windows-msvc` (from Windows/MSVC) | Win7 SP1+ with Rust 1.77.2 |
| macOS x64/arm64 | `rustup target add aarch64-apple-darwin`, `export MACOSX_DEPLOYMENT_TARGET=10.15` | Catalina+ |
| Android arm64/armv7 | NDK r27; set `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=<ndk>/aarch64-linux-android24-clang` and `CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=<ndk>/armv7a-linux-androideabi24-clang` | API 24 = Android 8.0 |

`.github/workflows/release.yml` performs all of the above automatically on
tag push (`v*`) and attaches the artifacts to the matching GitHub release.

## Frontends

The frontends are Material You source skeletons — the color engines
(`material_you.dart`, `MaterialYou.kt`, `materialyou.{h,cpp}`) are complete
and validated against the Rust golden vectors; the shell UIs build with
their native SDKs:

- **app_qt — Windows / Linux**: `cmake -B build -DCMAKE_BUILD_TYPE=Release
  && cmake --build build` (Qt 6). Windows 7: open `app_qt/win7/HoloNet.pro`
  with Qt 5.15 LTS. See `app_qt/README.md`.
- **app_flutter — Android**: `flutter build apk` (Flutter SDK 3.22+,
  `app_flutter/`). See the AndroidManifest/VpnService sources.
- **app_kmp — macOS**: source-only at this milestone — copy
  `desktop/src/jvmMain/kotlin/net/holonet/app/` into a Compose
  Multiplatform template (JDK 17+). See `app_kmp/README.md`.

## Running

```bash
./holonetd &                       # IPC on 127.0.0.1:7977 (token auth)
./holonetctl state                 # engine state
./holonetctl theme dark            # the full 33-role Material You map
./holonetctl seed "#0061A4"        # reseed every frontend
./holonetctl import "ss://…"       # import a share link
```
