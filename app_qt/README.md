# HoloNet — Qt frontend (Windows / Linux)

Qt 6 + QML frontend, fully **Material You**: `cpp/materialyou.{h,cpp}` is the
C++ port of the verified Rust `holo-theme` crate (one seed → tonal palettes →
all 33 M3 color roles), registered as the QML `Theme` singleton. `Main.qml`
binds every surface to those roles and applies the M3 shape scale; seed
changes push to the daemon (`settings.set`) so Android (Flutter) and macOS
(Compose) follow instantly.

Build:
    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

Windows 7: use the Qt 5.15 LTS project (win7/HoloNet.pro).
