# HoloNet — KMP frontend (macOS)

Kotlin Multiplatform + Compose Multiplatform desktop frontend, fully
**Material You**: `MaterialYou.kt` is the Kotlin port of the verified Rust
`holo-theme` crate (one seed → tonal palettes → all 33 M3 color roles),
and the Compose theme is built from those roles. The seed persists through
the daemon (`settings.set`) so the macOS, Android (Flutter) and
Windows/Linux (Qt) frontends stay in perfect color sync.

Build (macOS, JDK 17+):
    ./gradlew :desktop:packageDistributionBundle   # DMG bundle
    ./gradlew :desktop:run                          # dev run

Layout: desktop/src/jvmMain/kotlin/net/holonet/app/
    MaterialYou.kt — the Material You color engine (port of holo-theme)
    Main.kt — Compose M3 UI + IPC (theme.get / settings.set)
