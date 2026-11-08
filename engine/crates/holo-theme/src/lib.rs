//! holo-theme — the Material You (Material Design 3) color system for
//! HoloNet: one seed color → tonal palettes → light/dark color roles.
//!
//! This crate is the *reference implementation* of HoloNet's dynamic-color
//! math; the Flutter (Dart), KMP (Kotlin) and Qt (C++) frontends port this
//! file verbatim so every platform renders identical Material You themes.
//!
//! Color model (documented deviation): Google's Material Color Utilities
//! builds tonal palettes in HCT (hue/chroma/tone, CAM16-based). This
//! engine uses **CIELAB (L\*a\*b\*) with tone = L\*** and hue/chroma as the
//! polar a\*/b\* coordinates:
//!   - tone T (0–100)  ↔ L\* directly (HCT also defines tone on a 0–100
//!     lightness axis, so tone values line up with Material's),
//!   - hue             ↔ atan2(b\*, a\*),
//!   - chroma          ↔ C\* = hypot(a\*, b\*) (clamped into sRGB gamut).
//! The result is a close, visually-equivalent approximation of HCT palettes
//! while staying dependency-free and fast; role tone assignments follow the
//! Material 3 spec exactly, so contrast relationships are preserved.
//!
//! Everything is `pub` so the engine can expose `theme.get` over IPC and
//! the frontends can re-derive the same roles locally (offline-first).

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A color as 8-bit RGBA (alpha last). sRGB, gamma-encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argb {
    pub a: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Argb {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Argb {
        Argb { a: 255, r, g, b }
    }

    /// `#RRGGBB` (or `#AARRGGBB`).
    pub fn from_hex(s: &str) -> Option<Argb> {
        let h = s.trim().trim_start_matches('#');
        let (a, rgb) = match h.len() {
            6 => (255u8, h),
            8 => (u8::from_str_radix(&h[..2], 16).ok()?, &h[2..]),
            _ => return None,
        };
        if rgb.len() != 6 || !rgb.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(Argb {
            a,
            r: u8::from_str_radix(&rgb[0..2], 16).ok()?,
            g: u8::from_str_radix(&rgb[2..4], 16).ok()?,
            b: u8::from_str_radix(&rgb[4..6], 16).ok()?,
        })
    }

    /// `#RRGGBB` (alpha dropped — roles are opaque).
    pub fn to_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }

    /// Parse `0xAARRGGBB` (the classic Android int form).
    pub fn from_u32(v: u32) -> Argb {
        Argb {
            a: ((v >> 24) & 0xff) as u8,
            r: ((v >> 16) & 0xff) as u8,
            g: ((v >> 8) & 0xff) as u8,
            b: (v & 0xff) as u8,
        }
    }

    /// WCAG relative luminance (0.0–1.0) for contrast checks.
    pub fn luminance(self) -> f64 {
        fn lin(c: u8) -> f64 {
            let c = c as f64 / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * lin(self.r) + 0.7152 * lin(self.g) + 0.0722 * lin(self.b)
    }
}

/// CIELAB color (D65). `l` = L\* (tone), hue = atan2(b, a), chroma = |(a,b)|.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Lab {
    l: f64,
    a: f64,
    b: f64,
}

impl Lab {
    fn hue_deg(self) -> f64 {
        let h = self.b.atan2(self.a).to_degrees();
        if h < 0.0 {
            h + 360.0
        } else {
            h
        }
    }

    fn chroma(self) -> f64 {
        self.a.hypot(self.b)
    }

    /// Lab at the same hue/chroma but the given tone (L\*).
    fn at_tone(self, tone: f64) -> Lab {
        Lab { l: tone, a: self.a, b: self.b }
    }

    /// Lab at the given hue (degrees) and chroma with tone unchanged.
    fn at_hue_chroma(self, hue_deg: f64, chroma: f64) -> Lab {
        let (s, c) = hue_deg.to_radians().sin_cos();
        Lab { l: self.l, a: chroma * c, b: chroma * s }
    }
}

// ---------------------------------------------------------------------------
// sRGB ↔ Lab
// ---------------------------------------------------------------------------

const WHITE_POINT: [f64; 3] = [0.95047, 1.0, 1.08883]; // D65

fn srgb_to_lab(c: Argb) -> Lab {
    let lin = |v: u8| {
        let v = v as f64 / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    let (r, g, b) = (lin(c.r), lin(c.g), lin(c.b));
    // linear sRGB → XYZ (D65)
    let x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b;
    let y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b;
    let z = 0.0193339 * r + 0.1191920 * g + 0.9503041 * b;
    let f = |t: f64| {
        const E: f64 = 216.0 / 24389.0; // (6/29)^3
        const K: f64 = 24389.0 / 27.0; // (29/3)^3
        if t > E {
            t.cbrt()
        } else {
            (K * t + 16.0) / 116.0
        }
    };
    let (fx, fy, fz) = (
        f(x / WHITE_POINT[0]),
        f(y / WHITE_POINT[1]),
        f(z / WHITE_POINT[2]),
    );
    Lab {
        l: 116.0 * fy - 16.0,
        a: 500.0 * (fx - fy),
        b: 200.0 * (fy - fz),
    }
}

fn lab_to_srgb_clamped(lab: Lab) -> Argb {
    // Binary-search the largest chroma scale that stays in sRGB gamut at
    // this tone (Material's gamut mapping, applied on chroma). Tone 0/100
    // collapse to pure black/white because any chroma is out of gamut there.
    if lab_in_gamut(lab) {
        return lab_to_srgb_exact(lab);
    }
    let mut lo = 0.0f64;
    let mut hi = 1.0f64;
    // Squeeze chroma toward neutral until in gamut (24 iterations ≈ exact).
    let mut best = Lab { a: 0.0, b: 0.0, ..lab };
    for _ in 0..24 {
        let mid = (lo + hi) / 2.0;
        let candidate = Lab { a: lab.a * mid, b: lab.b * mid, l: lab.l };
        if lab_in_gamut(candidate) {
            best = candidate;
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lab_to_srgb_exact(best)
}

/// True when the Lab color maps into [0,1] linear sRGB without clamping.
fn lab_in_gamut(lab: Lab) -> bool {
    match lab_to_linear(lab) {
        Some((r, g, b)) => {
            (0.0..=1.0).contains(&r) && (0.0..=1.0).contains(&g) && (0.0..=1.0).contains(&b)
        }
        None => false,
    }
}

/// Lab → linear sRGB; None when XYZ leaves the Lab cube entirely (no valid
/// inverse, e.g. L\* outside 0–100 with residual chroma).
fn lab_to_linear(lab: Lab) -> Option<(f64, f64, f64)> {
    let fy = (lab.l + 16.0) / 116.0;
    let fx = fy + lab.a / 500.0;
    let fz = fy - lab.b / 200.0;
    let finv = |t: f64| {
        const E: f64 = 6.0 / 29.0;
        const K: f64 = 3.0 * E * E;
        if t > E {
            t * t * t
        } else {
            K * (t - 4.0 / 29.0)
        }
    };
    let x = finv(fx) * WHITE_POINT[0];
    let y = finv(fy) * WHITE_POINT[1];
    let z = finv(fz) * WHITE_POINT[2];
    let r = 3.2404542 * x - 1.5371385 * y - 0.4985314 * z;
    let g = -0.9692660 * x + 1.8760108 * y + 0.0415560 * z;
    let b = 0.0556434 * x - 0.2040259 * y + 1.0572252 * z;
    Some((r, g, b))
}

fn lab_to_srgb_exact(lab: Lab) -> Argb {
    let (r, g, b) = lab_to_linear(lab).unwrap_or((0.0, 0.0, 0.0));
    let enc = |mut v: f64| -> u8 {
        v = v.clamp(0.0, 1.0);
        let s = if v <= 0.0031308 {
            v * 12.92
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (s.clamp(0.0, 1.0) * 255.0).round() as u8
    };
    Argb::rgb(enc(r), enc(g), enc(b))
}

// ---------------------------------------------------------------------------
// Tonal palette
// ---------------------------------------------------------------------------

/// One Material tonal palette: a fixed hue+chroma rendered at tones 0–100.
#[derive(Debug, Clone, Copy)]
pub struct TonalPalette {
    /// Hue in Lab degrees (0–360).
    hue: f64,
    /// Chroma (C*).
    chroma: f64,
}

impl TonalPalette {
    /// A palette at `hue` degrees with `chroma`.
    pub fn new(hue: f64, chroma: f64) -> TonalPalette {
        TonalPalette { hue: hue.rem_euclid(360.0), chroma }
    }

    /// The palette color at `tone` (0–100 = L\*).
    pub fn tone(&self, tone: f64) -> Argb {
        let neutral = Lab { l: tone, a: 0.0, b: 0.0 };
        let colored = neutral.at_hue_chroma(self.hue, self.chroma);
        lab_to_srgb_clamped(colored)
    }
}

// ---------------------------------------------------------------------------
// Scheme (Material 3)
// ---------------------------------------------------------------------------

/// The six M3 palettes derived from one seed.
#[derive(Debug, Clone)]
pub struct Palettes {
    pub primary: TonalPalette,
    pub secondary: TonalPalette,
    pub tertiary: TonalPalette,
    pub neutral: TonalPalette,
    pub neutral_variant: TonalPalette,
    pub error: TonalPalette,
}

impl Palettes {
    /// Derive all six palettes from `seed` (the Material You algorithm:
    /// primary keeps the seed hue at full chroma, secondary/tertiary/neutral
    /// progressively desaturate, tertiary rotates hue +60°, error is fixed).
    pub fn from_seed(seed: Argb) -> Palettes {
        let lab = srgb_to_lab(seed);
        let hue = lab.hue_deg();
        let chroma = lab.chroma();
        Palettes {
            // M3: primary chroma is max(seed, 48) — keeps vivid seeds vivid
            // and lifts dull ones.
            primary: TonalPalette::new(hue, chroma.max(48.0).min(120.0)),
            secondary: TonalPalette::new(hue, 16.0),
            tertiary: TonalPalette::new(hue + 60.0, 24.0),
            neutral: TonalPalette::new(hue, 4.0),
            neutral_variant: TonalPalette::new(hue, 8.0),
            error: TonalPalette::new(25.0, 84.0),
        }
    }
}

/// Theme mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
}

impl Mode {
    pub fn parse(s: &str) -> Mode {
        match s.trim().to_ascii_lowercase().as_str() {
            "light" => Mode::Light,
            _ => Mode::Dark,
        }
    }
}

/// All Material 3 color roles for one mode. Field names follow the M3 spec
/// so the frontend ports map 1:1 (`onPrimary`, `primaryContainer`, …).
#[derive(Debug, Clone)]
pub struct Scheme {
    pub primary: Argb,
    pub on_primary: Argb,
    pub primary_container: Argb,
    pub on_primary_container: Argb,
    pub secondary: Argb,
    pub on_secondary: Argb,
    pub secondary_container: Argb,
    pub on_secondary_container: Argb,
    pub tertiary: Argb,
    pub on_tertiary: Argb,
    pub tertiary_container: Argb,
    pub on_tertiary_container: Argb,
    pub error: Argb,
    pub on_error: Argb,
    pub error_container: Argb,
    pub on_error_container: Argb,
    pub background: Argb,
    pub on_background: Argb,
    pub surface: Argb,
    pub on_surface: Argb,
    pub surface_variant: Argb,
    pub on_surface_variant: Argb,
    pub outline: Argb,
    pub outline_variant: Argb,
    pub surface_container_lowest: Argb,
    pub surface_container_low: Argb,
    pub surface_container: Argb,
    pub surface_container_high: Argb,
    pub surface_container_highest: Argb,
    pub inverse_surface: Argb,
    pub inverse_on_surface: Argb,
    pub surface_tint: Argb,
    pub scrim: Argb,
}

/// Full Material 3 color scheme: all 31 roles, tone assignments per the M3
/// spec table (light: primary=T40/on=100/container=T90; dark: primary=T80/
/// on=T20/container=T30; surfaces on the neutral palette).
pub fn scheme(p: &Palettes, mode: Mode) -> Scheme {
    let m = match mode {
        Mode::Light => LightDark { p: 40.0, on: 100.0, c: 90.0, on_c: 10.0, s: 98.0, on_s: 10.0, sv: 90.0, on_sv: 30.0, inv: 20.0, inv_on: 95.0 },
        Mode::Dark => LightDark { p: 80.0, on: 20.0, c: 30.0, on_c: 90.0, s: 6.0, on_s: 90.0, sv: 30.0, on_sv: 80.0, inv: 90.0, inv_on: 20.0 },
    };
    Scheme {
        primary: p.primary.tone(m.p),
        on_primary: p.primary.tone(m.on),
        primary_container: p.primary.tone(m.c),
        on_primary_container: p.primary.tone(m.on_c),
        secondary: p.secondary.tone(m.p),
        on_secondary: p.secondary.tone(m.on),
        secondary_container: p.secondary.tone(m.c),
        on_secondary_container: p.secondary.tone(m.on_c),
        tertiary: p.tertiary.tone(m.p),
        on_tertiary: p.tertiary.tone(m.on),
        tertiary_container: p.tertiary.tone(m.c),
        on_tertiary_container: p.tertiary.tone(m.on_c),
        error: p.error.tone(m.p),
        on_error: p.error.tone(m.on),
        error_container: p.error.tone(m.c),
        on_error_container: p.error.tone(m.on_c),
        background: p.neutral.tone(m.s),
        on_background: p.neutral.tone(m.on_s),
        surface: p.neutral.tone(m.s),
        on_surface: p.neutral.tone(m.on_s),
        surface_variant: p.neutral_variant.tone(m.sv),
        on_surface_variant: p.neutral_variant.tone(m.on_sv),
        outline: p.neutral_variant.tone(if mode == Mode::Light { 50.0 } else { 60.0 }),
        outline_variant: p.neutral_variant.tone(if mode == Mode::Light { 80.0 } else { 30.0 }),
        surface_container_lowest: p.neutral.tone(if mode == Mode::Light { 100.0 } else { 4.0 }),
        surface_container_low: p.neutral.tone(if mode == Mode::Light { 96.0 } else { 10.0 }),
        surface_container: p.neutral.tone(if mode == Mode::Light { 94.0 } else { 12.0 }),
        surface_container_high: p.neutral.tone(if mode == Mode::Light { 92.0 } else { 17.0 }),
        surface_container_highest: p.neutral.tone(if mode == Mode::Light { 90.0 } else { 22.0 }),
        inverse_surface: p.neutral.tone(m.inv),
        inverse_on_surface: p.neutral.tone(m.inv_on),
        surface_tint: p.primary.tone(m.p),
        scrim: p.neutral.tone(0.0),
    }
}

struct LightDark {
    p: f64,
    on: f64,
    c: f64,
    on_c: f64,
    s: f64,
    on_s: f64,
    sv: f64,
    on_sv: f64,
    inv: f64,
    inv_on: f64,
}

/// Convenience: scheme from a seed color + mode.
pub fn scheme_from_seed(seed: Argb, mode: Mode) -> Scheme {
    scheme(&Palettes::from_seed(seed), mode)
}

// ---------------------------------------------------------------------------
// Serialization (IPC `theme.get` / frontend re-derivation)
// ---------------------------------------------------------------------------

/// Hex map of every role — the JSON shape shared with all frontends:
/// `{"primary":"#6750a4","onPrimary":"#ffffff", ...}`.
pub fn scheme_to_hex_map(s: &Scheme) -> Vec<(&'static str, String)> {
    vec![
        ("primary", s.primary.to_hex()),
        ("onPrimary", s.on_primary.to_hex()),
        ("primaryContainer", s.primary_container.to_hex()),
        ("onPrimaryContainer", s.on_primary_container.to_hex()),
        ("secondary", s.secondary.to_hex()),
        ("onSecondary", s.on_secondary.to_hex()),
        ("secondaryContainer", s.secondary_container.to_hex()),
        ("onSecondaryContainer", s.on_secondary_container.to_hex()),
        ("tertiary", s.tertiary.to_hex()),
        ("onTertiary", s.on_tertiary.to_hex()),
        ("tertiaryContainer", s.tertiary_container.to_hex()),
        ("onTertiaryContainer", s.on_tertiary_container.to_hex()),
        ("error", s.error.to_hex()),
        ("onError", s.on_error.to_hex()),
        ("errorContainer", s.error_container.to_hex()),
        ("onErrorContainer", s.on_error_container.to_hex()),
        ("background", s.background.to_hex()),
        ("onBackground", s.on_background.to_hex()),
        ("surface", s.surface.to_hex()),
        ("onSurface", s.on_surface.to_hex()),
        ("surfaceVariant", s.surface_variant.to_hex()),
        ("onSurfaceVariant", s.on_surface_variant.to_hex()),
        ("outline", s.outline.to_hex()),
        ("outlineVariant", s.outline_variant.to_hex()),
        ("surfaceContainerLowest", s.surface_container_lowest.to_hex()),
        ("surfaceContainerLow", s.surface_container_low.to_hex()),
        ("surfaceContainer", s.surface_container.to_hex()),
        ("surfaceContainerHigh", s.surface_container_high.to_hex()),
        ("surfaceContainerHighest", s.surface_container_highest.to_hex()),
        ("inverseSurface", s.inverse_surface.to_hex()),
        ("inverseOnSurface", s.inverse_on_surface.to_hex()),
        ("surfaceTint", s.surface_tint.to_hex()),
        ("scrim", s.scrim.to_hex()),
    ]
}

/// M3 shape scale (corner radii, dp) and type scale — shared constants the
/// frontends apply so the "expressive" feel matches across platforms.
pub const SHAPE_EXTRA_SMALL: f32 = 4.0;
pub const SHAPE_SMALL: f32 = 8.0;
pub const SHAPE_MEDIUM: f32 = 12.0;
pub const SHAPE_LARGE: f32 = 16.0;
pub const SHAPE_EXTRA_LARGE: f32 = 28.0;

/// The default HoloNet seed (a Google-blue-ish "holo" tone).
pub const DEFAULT_SEED: Argb = Argb::rgb(0x67, 0x50, 0xA4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let c = Argb::rgb(0x67, 0x50, 0xa4);
        assert_eq!(c.to_hex(), "#6750a4");
        assert_eq!(Argb::from_hex("#6750a4"), Some(c));
        assert_eq!(Argb::from_hex("6750A4"), Some(c));
        assert_eq!(Argb::from_hex("#FF6750A4"), Some(Argb { a: 255, ..c }));
        assert_eq!(Argb::from_hex("#12345"), None);
        assert_eq!(Argb::from_hex("zzzzzz"), None);
        assert_eq!(Argb::from_u32(0xFF6750A4), Argb { a: 255, ..c });
    }

    #[test]
    fn lab_roundtrip() {
        // sRGB → Lab → sRGB must round-trip (clamped inputs are exact).
        for c in [
            Argb::rgb(0, 0, 0),
            Argb::rgb(255, 255, 255),
            Argb::rgb(0x67, 0x50, 0xA4),
            Argb::rgb(0xB3, 0x26, 0x1E),
            Argb::rgb(0x2D, 0xE0, 0xA5),
            Argb::rgb(128, 128, 128),
        ] {
            let lab = srgb_to_lab(c);
            let back = lab_to_srgb_exact(lab);
            assert!(
                (back.r as i16 - c.r as i16).abs() <= 1
                    && (back.g as i16 - c.g as i16).abs() <= 1
                    && (back.b as i16 - c.b as i16).abs() <= 1,
                "roundtrip failed for {:?}: got {:?}",
                c,
                back
            );
        }
    }

    #[test]
    fn tone_extremes() {
        let p = TonalPalette::new(260.0, 60.0);
        assert_eq!(p.tone(0.0), Argb::rgb(0, 0, 0));
        assert_eq!(p.tone(100.0), Argb::rgb(255, 255, 255));
    }

    #[test]
    fn palette_tone_monotonic_lightness() {
        let p = TonalPalette::new(260.0, 60.0);
        let mut prev = -1.0;
        for t in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0] {
            let lum = p.tone(t).luminance();
            assert!(lum > prev, "tone {} not lighter than previous", t);
            prev = lum;
        }
    }

    #[test]
    fn scheme_contrast_invariants() {
        // M3 requires ≥3:1 between component color and its "on" color.
        let palettes = Palettes::from_seed(DEFAULT_SEED);
        for mode in [Mode::Light, Mode::Dark] {
            let s = scheme(&palettes, mode);
            for (fg, bg) in [
                (s.on_primary, s.primary),
                (s.on_secondary, s.secondary),
                (s.on_tertiary, s.tertiary),
                (s.on_error, s.error),
                (s.on_primary_container, s.primary_container),
                (s.on_surface, s.surface),
            ] {
                let ratio = contrast_ratio(fg, bg);
                assert!(
                    ratio >= 3.0,
                    "{:?} on/on contrast {} < 3.0 (mode {:?})",
                    mode,
                    ratio,
                    mode
                );
            }
        }
    }

    #[test]
    fn dark_and_light_differ() {
        let palettes = Palettes::from_seed(DEFAULT_SEED);
        let light = scheme(&palettes, Mode::Light);
        let dark = scheme(&palettes, Mode::Dark);
        assert!(light.surface.luminance() > dark.surface.luminance());
        assert!(light.primary != dark.primary);
        // Dark primary is the light tone (80), light primary the deep tone (40).
        assert!(dark.primary.luminance() > light.primary.luminance());
    }

    #[test]
    fn seed_changes_roles() {
        let a = scheme_from_seed(Argb::rgb(0x67, 0x50, 0xA4), Mode::Light);
        let b = scheme_from_seed(Argb::rgb(0xB3, 0x26, 0x1E), Mode::Light);
        assert_ne!(a.primary, b.primary);
        assert_ne!(a.primary_container, b.primary_container);
    }

    #[test]
    fn golden_vectors_for_port_validation() {
        // Cross-platform contract: the Dart/Kotlin/C++ ports of this engine
        // must produce these exact hexes (verified against the Rust
        // reference; also observed live via holonetctl theme).
        let d = scheme_from_seed(Argb::rgb(0xB3, 0x26, 0x1E), Mode::Dark);
        assert_eq!(d.primary.to_hex(), "#ffb4a5");
        assert_eq!(d.surface.to_hex(), "#19110f");
        let p = scheme_from_seed(DEFAULT_SEED, Mode::Dark);
        assert_eq!(p.surface.to_hex(), "#151218");
        // Tertiary keeps the +60° rotation: visible in the container tones.
        let l = scheme_from_seed(DEFAULT_SEED, Mode::Light);
        assert_eq!(l.primary.to_hex(), "#6750a4"); // the seed itself at T40
    }

    #[test]
    fn hex_map_shape() {
        let s = scheme_from_seed(DEFAULT_SEED, Mode::Dark);
        let m = scheme_to_hex_map(&s);
        assert_eq!(m.len(), 33);
        assert!(m.iter().all(|(k, v)| {
            k.len() > 3 && v.starts_with('#') && v.len() == 7
        }));
    }

    #[test]
    fn tertiary_hue_rotation() {
        // The tertiary palette is the seed hue rotated +60°.
        let seed = Argb::rgb(0x00, 0x66, 0x9A);
        let p = Palettes::from_seed(seed);
        let seed_hue = srgb_to_lab(seed).hue_deg();
        let tert_hue = srgb_to_lab(p.tertiary.tone(50.0)).hue_deg();
        let delta = (tert_hue - seed_hue - 60.0).abs().min(360.0 - (tert_hue - seed_hue - 60.0).abs());
        assert!(delta < 25.0, "tertiary hue not +60°: {}", delta);
    }

    fn contrast_ratio(a: Argb, b: Argb) -> f64 {
        let (la, lb) = (a.luminance(), b.luminance());
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }
}
