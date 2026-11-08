// material_you.dart — HoloNet's Material You color engine (Dart port of
// engine/crates/holo-theme, the verified Rust reference). One seed →
// tonal palettes → all 33 M3 color roles for light/dark. Every platform
// (Flutter / KMP / Qt) ports the same math so themes render identically.
//
// Model (documented deviation from Google's HCT): CIELAB with tone = L*,
// hue = atan2(b*, a*), chroma = C*, gamut-mapped by chroma binary search.
// Role tone assignments follow the Material 3 spec exactly.

import 'dart:math' as math;

class Argb {
  final int a, r, g, b;
  const Argb._(this.a, this.r, this.g, this.b);
  const Argb.rgb(int r, int g, int b) : a = 255, r = r, g = g, b = b;

  static Argb? fromHex(String s) {
    var h = s.trim();
    if (h.startsWith('#')) h = h.substring(1);
    int a = 255;
    if (h.length == 8) {
      a = int.tryParse(h.substring(0, 2), radix: 16);
      h = h.substring(2);
      if (a == null) return null;
    }
    if (h.length != 6) return null;
    final r = int.tryParse(h.substring(0, 2), radix: 16);
    final g = int.tryParse(h.substring(2, 4), radix: 16);
    final b = int.tryParse(h.substring(4, 6), radix: 16);
    if (r == null || g == null || b == null) return null;
    return Argb._(a, r, g, b);
  }

  String get hex => '#${_h(r)}${_h(g)}${_h(b)}';
  String _h(int v) => v.toRadixString(16).padLeft(2, '0');

  /// WCAG relative luminance.
  double get luminance =>
      0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b);
  static double _lin(int c) {
    final v = c / 255.0;
    return v <= 0.04045 ? v / 12.92 : math.pow((v + 0.055) / 1.055, 2.4).toDouble();
  }

  bool operator ==(Object other) => other is Argb && other.r == r && other.g == g && other.b == b;
  int get hashCode => r * 65536 + g * 256 + b;
}

class _Lab {
  final double l, a, b;
  const _Lab(this.l, this.a, this.b);

  double get hueDeg {
    final h = math.atan2(b, a) * 180 / math.pi;
    return h < 0 ? h + 360 : h;
  }

  double get chroma => math.sqrt(a * a + b * b);

  _Lab atHueChroma(double hueDeg, double chroma) {
    final rad = hueDeg * math.pi / 180;
    return _Lab(l, chroma * math.cos(rad), chroma * math.sin(rad));
  }
}

const List<double> _whitePoint = [0.95047, 1.0, 1.08883]; // D65

_Lab _srgbToLab(Argb c) {
  double lin(int v) {
    final x = v / 255.0;
    return x <= 0.04045 ? x / 12.92 : math.pow((x + 0.055) / 1.055, 2.4).toDouble();
  }

  final r = lin(c.r), g = lin(c.g), b = lin(c.b);
  final x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b;
  final y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b;
  final z = 0.0193339 * r + 0.1191920 * g + 0.9503041 * b;
  double f(double t) {
    const e = 216.0 / 24389.0, k = 24389.0 / 27.0;
    return t > e ? _cbrt(t) : (k * t + 16.0) / 116.0;
  }

  final fx = f(x / _whitePoint[0]);
  final fy = f(y / _whitePoint[1]);
  final fz = f(z / _whitePoint[2]);
  return _Lab(116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz));
}

(double, double, double)? _labToLinear(_Lab lab) {
  final fy = (lab.l + 16.0) / 116.0;
  final fx = fy + lab.a / 500.0;
  final fz = fy - lab.b / 200.0;
  double finv(double t) {
    const e = 6.0 / 29.0, k = 3.0 * e * e;
    return t > e ? t * t * t : k * (t - 4.0 / 29.0);
  }

  final x = finv(fx) * _whitePoint[0];
  final y = finv(fy) * _whitePoint[1];
  final z = finv(fz) * _whitePoint[2];
  return (
    3.2404542 * x - 1.5371385 * y - 0.4985314 * z,
    -0.9692660 * x + 1.8760108 * y + 0.0415560 * z,
    0.0556434 * x - 0.2040259 * y + 1.0572252 * z,
  );
}

bool _inGamut(_Lab lab) {
  final rgb = _labToLinear(lab);
  if (rgb == null) return false;
  return rgb.$1 >= 0 && rgb.$1 <= 1 && rgb.$2 >= 0 && rgb.$2 <= 1 && rgb.$3 >= 0 && rgb.$3 <= 1;
}

Argb _labToSrgbExact(_Lab lab) {
  final rgb = _labToLinear(lab) ?? (0.0, 0.0, 0.0);
  int enc(double v) {
    final c = v.clamp(0.0, 1.0);
    final s = c <= 0.0031308 ? c * 12.92 : 1.055 * math.pow(c, 1 / 2.4) - 0.055;
    return (s.clamp(0.0, 1.0) * 255).round();
  }

  return Argb.rgb(enc(rgb.$1), enc(rgb.$2), enc(rgb.$3));
}

Argb _labToSrgbClamped(_Lab lab) {
  if (_inGamut(lab)) return _labToSrgbExact(lab);
  var lo = 0.0, hi = 1.0;
  var best = _Lab(lab.l, 0.0, 0.0);
  for (var i = 0; i < 24; i++) {
    final mid = (lo + hi) / 2;
    final cand = _Lab(lab.l, lab.a * mid, lab.b * mid);
    if (_inGamut(cand)) {
      best = cand;
      lo = mid;
    } else {
      hi = mid;
    }
  }
  return _labToSrgbExact(best);
}

/// One Material tonal palette: fixed hue+chroma rendered at tones 0–100.
class TonalPalette {
  final double hue, chroma;
  const TonalPalette(this.hue, this.chroma);

  Argb tone(double t) => _labToSrgbClamped(_Lab(t, 0, 0).atHueChroma(hue, chroma));
}

/// The six M3 palettes derived from one seed.
class MaterialYouPalettes {
  final TonalPalette primary, secondary, tertiary, neutral, neutralVariant, error;
  const MaterialYouPalettes(this.primary, this.secondary, this.tertiary, this.neutral, this.neutralVariant, this.error);

  static MaterialYouPalettes fromSeed(Argb seed) {
    final lab = _srgbToLab(seed);
    final hue = lab.hueDeg;
    final chroma = lab.chroma;
    return MaterialYouPalettes(
      TonalPalette(hue, chroma.clamp(48.0, 120.0)),
      TonalPalette(hue, 16.0),
      TonalPalette((hue + 60) % 360, 24.0),
      TonalPalette(hue, 4.0),
      TonalPalette(hue, 8.0),
      TonalPalette(25.0, 84.0),
    );
  }
}

enum MaterialYouMode { light, dark }

/// All Material 3 color roles for one mode.
class MaterialYouScheme {
  final Argb primary, onPrimary, primaryContainer, onPrimaryContainer;
  final Argb secondary, onSecondary, secondaryContainer, onSecondaryContainer;
  final Argb tertiary, onTertiary, tertiaryContainer, onTertiaryContainer;
  final Argb error, onError, errorContainer, onErrorContainer;
  final Argb background, onBackground, surface, onSurface;
  final Argb surfaceVariant, onSurfaceVariant, outline, outlineVariant;
  final Argb surfaceContainerLowest, surfaceContainerLow, surfaceContainer, surfaceContainerHigh, surfaceContainerHighest;
  final Argb inverseSurface, inverseOnSurface, surfaceTint, scrim;

  const MaterialYouScheme({
    required this.primary, required this.onPrimary, required this.primaryContainer, required this.onPrimaryContainer,
    required this.secondary, required this.onSecondary, required this.secondaryContainer, required this.onSecondaryContainer,
    required this.tertiary, required this.onTertiary, required this.tertiaryContainer, required this.onTertiaryContainer,
    required this.error, required this.onError, required this.errorContainer, required this.onErrorContainer,
    required this.background, required this.onBackground, required this.surface, required this.onSurface,
    required this.surfaceVariant, required this.onSurfaceVariant, required this.outline, required this.outlineVariant,
    required this.surfaceContainerLowest, required this.surfaceContainerLow, required this.surfaceContainer, required this.surfaceContainerHigh, required this.surfaceContainerHighest,
    required this.inverseSurface, required this.inverseOnSurface, required this.surfaceTint, required this.scrim,
  });

  static MaterialYouScheme of(MaterialYouPalettes p, MaterialYouMode mode) {
    final dark = mode == MaterialYouMode.dark;
    final t = dark ? (80.0, 20.0, 30.0, 90.0, 6.0, 90.0, 30.0, 80.0) : (40.0, 100.0, 90.0, 10.0, 98.0, 10.0, 90.0, 30.0);
    return MaterialYouScheme(
      primary: p.primary.tone(t.$1), onPrimary: p.primary.tone(t.$2),
      primaryContainer: p.primary.tone(t.$3), onPrimaryContainer: p.primary.tone(t.$4),
      secondary: p.secondary.tone(t.$1), onSecondary: p.secondary.tone(t.$2),
      secondaryContainer: p.secondary.tone(t.$3), onSecondaryContainer: p.secondary.tone(t.$4),
      tertiary: p.tertiary.tone(t.$1), onTertiary: p.tertiary.tone(t.$2),
      tertiaryContainer: p.tertiary.tone(t.$3), onTertiaryContainer: p.tertiary.tone(t.$4),
      error: p.error.tone(t.$1), onError: p.error.tone(t.$2),
      errorContainer: p.error.tone(t.$3), onErrorContainer: p.error.tone(t.$4),
      background: p.neutral.tone(t.$5), onBackground: p.neutral.tone(t.$6),
      surface: p.neutral.tone(t.$5), onSurface: p.neutral.tone(t.$6),
      surfaceVariant: p.neutralVariant.tone(t.$7), onSurfaceVariant: p.neutralVariant.tone(t.$8),
      outline: p.neutralVariant.tone(dark ? 60.0 : 50.0),
      outlineVariant: p.neutralVariant.tone(dark ? 30.0 : 80.0),
      surfaceContainerLowest: p.neutral.tone(dark ? 4.0 : 100.0),
      surfaceContainerLow: p.neutral.tone(dark ? 10.0 : 96.0),
      surfaceContainer: p.neutral.tone(dark ? 12.0 : 94.0),
      surfaceContainerHigh: p.neutral.tone(dark ? 17.0 : 92.0),
      surfaceContainerHighest: p.neutral.tone(dark ? 22.0 : 90.0),
      inverseSurface: p.neutral.tone(dark ? 90.0 : 20.0),
      inverseOnSurface: p.neutral.tone(dark ? 20.0 : 95.0),
      surfaceTint: p.primary.tone(t.$1),
      scrim: p.neutral.tone(0.0),
    );
  }

  static MaterialYouScheme fromSeed(Argb seed, MaterialYouMode mode) =>
      of(MaterialYouPalettes.fromSeed(seed), mode);

  /// Map of role name → hex (matches the daemon's `theme.get` shape).
  Map<String, String> toHexMap() => {
        'primary': primary.hex, 'onPrimary': onPrimary.hex,
        'primaryContainer': primaryContainer.hex, 'onPrimaryContainer': onPrimaryContainer.hex,
        'secondary': secondary.hex, 'onSecondary': onSecondary.hex,
        'secondaryContainer': secondaryContainer.hex, 'onSecondaryContainer': onSecondaryContainer.hex,
        'tertiary': tertiary.hex, 'onTertiary': onTertiary.hex,
        'tertiaryContainer': tertiaryContainer.hex, 'onTertiaryContainer': onTertiaryContainer.hex,
        'error': error.hex, 'onError': onError.hex,
        'errorContainer': errorContainer.hex, 'onErrorContainer': onErrorContainer.hex,
        'background': background.hex, 'onBackground': onBackground.hex,
        'surface': surface.hex, 'onSurface': onSurface.hex,
        'surfaceVariant': surfaceVariant.hex, 'onSurfaceVariant': onSurfaceVariant.hex,
        'outline': outline.hex, 'outlineVariant': outlineVariant.hex,
        'surfaceContainerLowest': surfaceContainerLowest.hex,
        'surfaceContainerLow': surfaceContainerLow.hex,
        'surfaceContainer': surfaceContainer.hex,
        'surfaceContainerHigh': surfaceContainerHigh.hex,
        'surfaceContainerHighest': surfaceContainerHighest.hex,
        'inverseSurface': inverseSurface.hex, 'inverseOnSurface': inverseOnSurface.hex,
        'surfaceTint': surfaceTint.hex, 'scrim': scrim.hex,
      };
}

/// The default HoloNet seed.
const defaultSeed = Argb.rgb(0x67, 0x50, 0xA4);
