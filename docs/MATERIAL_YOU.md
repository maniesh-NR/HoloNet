# Material You across every HoloNet OS

One seed color → the complete Material Design 3 scheme, byte-identical on
Android (Flutter), macOS (Compose), Windows/Linux (Qt) and the daemon.

## The contract

- **Engine**: `engine/crates/holo-theme` (Rust, 10 tests + golden hex
  vectors for cross-language port validation) is the reference.
  Color model: CIELAB with tone = L\*, hue = atan2(b\*, a\*), chroma = C\*
  (documented deviation from Google's HCT), chroma gamut-mapped by binary
  search. Six palettes from the seed — primary (chroma ≥ 48), secondary
  (16), tertiary (hue +60°, 24), neutral (4), neutral-variant (8), error
  (hue 25°, 84) — all 33 roles at the M3 tone assignments for light/dark.
- **Ports**: `app_flutter/lib/material_you.dart`,
  `app_kmp/desktop/src/jvmMain/kotlin/net/holonet/app/MaterialYou.kt`,
  `app_qt/cpp/materialyou.{h,cpp}`. Each implements the identical math and
  is validated against the Rust golden vectors:
  - seed `#6750A4` dark → surface `#151218`, primary `#6750a4` (light T40)
  - seed `#B3261E` dark → primary `#ffb4a5`, surface `#19110f`
- **Persistence**: the seed lives in the daemon settings
  (`seed_color`, `theme_mode`, `dynamic_color`). `theme.get {osTheme}`
  returns the resolved 33-role hex map; `settings.set` reseeds — every
  frontend on every OS follows instantly.
- **Android dynamic color**: on Android 12+ with dynamic color ON, the
  platform's Monet (wallpaper) palette replaces the seeded scheme via the
  `dynamiccolor` MethodChannel; the seed still rules macOS/Windows/Linux
  and any Android below 12.

## Settings

| Key | Values | Meaning |
|---|---|---|
| `theme_mode` | system / dark / light | mode selection |
| `seed_color` | `#RRGGBB` | the Material You seed |
| `dynamic_color` | true / false | Android 12+ Monet when available |

## UI shape (all platforms)

M3 expressive: large top app bars, navigation bars (bottom on mobile),
FABs, cards on the surface-container scale, the M3 shape scale (4/8/12/16/28
dp), seed picker with curated presets + custom hex, follow-system mode.

## IPC

```
→ {"method":"theme.get","params":{"osTheme":"dark"}}
← {"result":{"primary":"#ffb4a5","onPrimary":"#690000", …33 roles…,
             "_mode":"system","_seed":"#B3261E","_dynamic":"true"}}
→ {"method":"settings.set","params":{"values":{"seed_color":"#0061A4"}}}
```
