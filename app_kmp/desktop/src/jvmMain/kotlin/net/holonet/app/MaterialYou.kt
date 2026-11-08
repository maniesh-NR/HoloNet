// MaterialYou.kt — HoloNet's Material You color engine (Kotlin port of
// engine/crates/holo-theme, the verified Rust reference). One seed →
// tonal palettes → all 33 M3 color roles for light/dark. The macOS
// Compose frontend and the Flutter/Qt frontends render identical themes.
//
// Model (documented deviation from Google's HCT): CIELAB with tone = L*,
// hue = atan2(b*, a*), chroma = C*, gamut-mapped by chroma binary search.
package net.holonet.app

import kotlin.math.atan2
import kotlin.math.cbrt
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

data class Argb(val a: Int, val r: Int, val g: Int, val b: Int) {
    companion object {
        fun rgb(r: Int, g: Int, b: Int) = Argb(255, r, g, b)

        fun fromHex(s: String): Argb? {
            var h = s.trim().removePrefix("#")
            var a = 255
            if (h.length == 8) {
                a = h.substring(0, 2).toIntOrNull(16) ?: return null
                h = h.substring(2)
            }
            if (h.length != 6) return null
            val r = h.substring(0, 2).toIntOrNull(16) ?: return null
            val g = h.substring(2, 4).toIntOrNull(16) ?: return null
            val b = h.substring(4, 6).toIntOrNull(16) ?: return null
            return Argb(a, r, g, b)
        }

        val DEFAULT = rgb(0x67, 0x50, 0xA4)
    }

    val hex: String get() = "#%02x%02x%02x".format(r, g, b)

    // WCAG relative luminance
    val luminance: Double
        get() = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)

    private fun lin(c: Int): Double {
        val v = c / 255.0
        return if (v <= 0.04045) v / 12.92 else ((v + 0.055) / 1.055).pow(2.4)
    }
}

private val WHITE_POINT = doubleArrayOf(0.95047, 1.0, 1.08883) // D65

private data class Lab(val l: Double, val a: Double, val b: Double) {
    val hueDeg: Double
        get() {
            val h = atan2(b, a) * 180 / Math.PI
            return if (h < 0) h + 360 else h
        }
    val chroma: Double get() = sqrt(a * a + b * b)

    fun atHueChroma(hueDeg: Double, chroma: Double): Lab {
        val rad = hueDeg * Math.PI / 180
        return Lab(l, chroma * cos(rad), chroma * sin(rad))
    }
}

private fun srgbToLab(c: Argb): Lab {
    fun lin(v: Int): Double {
        val x = v / 255.0
        return if (x <= 0.04045) x / 12.92 else ((x + 0.055) / 1.055).pow(2.4)
    }
    val r = lin(c.r); val g = lin(c.g); val b = lin(c.b)
    val x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b
    val y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b
    val z = 0.0193339 * r + 0.1191920 * g + 0.9503041 * b
    fun f(t: Double): Double {
        val e = 216.0 / 24389.0; val k = 24389.0 / 27.0
        return if (t > e) cbrt(t) else (k * t + 16.0) / 116.0
    }
    val fx = f(x / WHITE_POINT[0]); val fy = f(y / WHITE_POINT[1]); val fz = f(z / WHITE_POINT[2])
    return Lab(116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz))
}

private fun labToLinear(lab: Lab): Triple<Double, Double, Double> {
    val fy = (lab.l + 16.0) / 116.0
    val fx = fy + lab.a / 500.0
    val fz = fy - lab.b / 200.0
    fun finv(t: Double): Double {
        val e = 6.0 / 29.0; val k = 3.0 * e * e
        return if (t > e) t * t * t else k * (t - 4.0 / 29.0)
    }
    val x = finv(fx) * WHITE_POINT[0]
    val y = finv(fy) * WHITE_POINT[1]
    val z = finv(fz) * WHITE_POINT[2]
    return Triple(
        3.2404542 * x - 1.5371385 * y - 0.4985314 * z,
        -0.9692660 * x + 1.8760108 * y + 0.0415560 * z,
        0.0556434 * x - 0.2040259 * y + 1.0572252 * z
    )
}

private fun inGamut(lab: Lab): Boolean {
    val (r, g, b) = labToLinear(lab)
    return r in 0.0..1.0 && g in 0.0..1.0 && b in 0.0..1.0
}

private fun labToSrgbExact(lab: Lab): Argb {
    val (r, g, b) = labToLinear(lab)
    fun enc(v: Double): Int {
        val c = v.coerceIn(0.0, 1.0)
        val s = if (c <= 0.0031308) c * 12.92 else 1.055 * c.pow(1.0 / 2.4) - 0.055
        return (s.coerceIn(0.0, 1.0) * 255).toInt()
    }
    return Argb.rgb(enc(r), enc(g), enc(b))
}

private fun labToSrgbClamped(lab: Lab): Argb {
    if (inGamut(lab)) return labToSrgbExact(lab)
    var lo = 0.0; var hi = 1.0
    var best = Lab(lab.l, 0.0, 0.0)
    repeat(24) {
        val mid = (lo + hi) / 2
        val cand = Lab(lab.l, lab.a * mid, lab.b * mid)
        if (inGamut(cand)) { best = cand; lo = mid } else hi = mid
    }
    return labToSrgbExact(best)
}

/** One Material tonal palette: fixed hue+chroma rendered at tones 0–100. */
class TonalPalette(val hue: Double, val chroma: Double) {
    fun tone(t: Double): Argb = labToSrgbClamped(Lab(t, 0.0, 0.0).atHueChroma(hue, chroma))
}

/** The six M3 palettes derived from one seed. */
class MaterialYouPalettes(
    val primary: TonalPalette, val secondary: TonalPalette, val tertiary: TonalPalette,
    val neutral: TonalPalette, val neutralVariant: TonalPalette, val error: TonalPalette,
) {
    companion object {
        fun fromSeed(seed: Argb): MaterialYouPalettes {
            val lab = srgbToLab(seed)
            val hue = lab.hueDeg
            val chroma = lab.chroma
            return MaterialYouPalettes(
                TonalPalette(hue, chroma.coerceIn(48.0, 120.0)),
                TonalPalette(hue, 16.0),
                TonalPalette((hue + 60) % 360, 24.0),
                TonalPalette(hue, 4.0),
                TonalPalette(hue, 8.0),
                TonalPalette(25.0, 84.0),
            )
        }
    }
}

enum class MaterialYouMode { LIGHT, DARK }

/** All Material 3 color roles for one mode. */
data class MaterialYouScheme(
    val primary: Argb, val onPrimary: Argb, val primaryContainer: Argb, val onPrimaryContainer: Argb,
    val secondary: Argb, val onSecondary: Argb, val secondaryContainer: Argb, val onSecondaryContainer: Argb,
    val tertiary: Argb, val onTertiary: Argb, val tertiaryContainer: Argb, val onTertiaryContainer: Argb,
    val error: Argb, val onError: Argb, val errorContainer: Argb, val onErrorContainer: Argb,
    val background: Argb, val onBackground: Argb, val surface: Argb, val onSurface: Argb,
    val surfaceVariant: Argb, val onSurfaceVariant: Argb, val outline: Argb, val outlineVariant: Argb,
    val surfaceContainerLowest: Argb, val surfaceContainerLow: Argb, val surfaceContainer: Argb,
    val surfaceContainerHigh: Argb, val surfaceContainerHighest: Argb,
    val inverseSurface: Argb, val inverseOnSurface: Argb, val surfaceTint: Argb, val scrim: Argb,
) {
    companion object {
        fun of(p: MaterialYouPalettes, mode: MaterialYouMode): MaterialYouScheme {
            val dark = mode == MaterialYouMode.DARK
            val tp = if (dark) 80.0 else 40.0
            val to = if (dark) 20.0 else 100.0
            val tc = if (dark) 30.0 else 90.0
            val toc = if (dark) 90.0 else 10.0
            val ts = if (dark) 6.0 else 98.0
            val tos = if (dark) 90.0 else 10.0
            val tsv = if (dark) 30.0 else 90.0
            val tosv = if (dark) 80.0 else 30.0
            return MaterialYouScheme(
                primary = p.primary.tone(tp), onPrimary = p.primary.tone(to),
                primaryContainer = p.primary.tone(tc), onPrimaryContainer = p.primary.tone(toc),
                secondary = p.secondary.tone(tp), onSecondary = p.secondary.tone(to),
                secondaryContainer = p.secondary.tone(tc), onSecondaryContainer = p.secondary.tone(toc),
                tertiary = p.tertiary.tone(tp), onTertiary = p.tertiary.tone(to),
                tertiaryContainer = p.tertiary.tone(tc), onTertiaryContainer = p.tertiary.tone(toc),
                error = p.error.tone(tp), onError = p.error.tone(to),
                errorContainer = p.error.tone(tc), onErrorContainer = p.error.tone(toc),
                background = p.neutral.tone(ts), onBackground = p.neutral.tone(tos),
                surface = p.neutral.tone(ts), onSurface = p.neutral.tone(tos),
                surfaceVariant = p.neutralVariant.tone(tsv), onSurfaceVariant = p.neutralVariant.tone(tosv),
                outline = p.neutralVariant.tone(if (dark) 60.0 else 50.0),
                outlineVariant = p.neutralVariant.tone(if (dark) 30.0 else 80.0),
                surfaceContainerLowest = p.neutral.tone(if (dark) 4.0 else 100.0),
                surfaceContainerLow = p.neutral.tone(if (dark) 10.0 else 96.0),
                surfaceContainer = p.neutral.tone(if (dark) 12.0 else 94.0),
                surfaceContainerHigh = p.neutral.tone(if (dark) 17.0 else 92.0),
                surfaceContainerHighest = p.neutral.tone(if (dark) 22.0 else 90.0),
                inverseSurface = p.neutral.tone(if (dark) 90.0 else 20.0),
                inverseOnSurface = p.neutral.tone(if (dark) 20.0 else 95.0),
                surfaceTint = p.primary.tone(tp), scrim = p.neutral.tone(0.0),
            )
        }

        fun fromSeed(seed: Argb, mode: MaterialYouMode) = of(MaterialYouPalettes.fromSeed(seed), mode)
    }

    /** Map of role name → hex (matches the daemon's `theme.get` shape). */
    fun toHexMap(): Map<String, String> = linkedMapOf(
        "primary" to primary.hex, "onPrimary" to onPrimary.hex,
        "primaryContainer" to primaryContainer.hex, "onPrimaryContainer" to onPrimaryContainer.hex,
        "secondary" to secondary.hex, "onSecondary" to onSecondary.hex,
        "secondaryContainer" to secondaryContainer.hex, "onSecondaryContainer" to onSecondaryContainer.hex,
        "tertiary" to tertiary.hex, "onTertiary" to onTertiary.hex,
        "tertiaryContainer" to tertiaryContainer.hex, "onTertiaryContainer" to onTertiaryContainer.hex,
        "error" to error.hex, "onError" to onError.hex,
        "errorContainer" to errorContainer.hex, "onErrorContainer" to onErrorContainer.hex,
        "background" to background.hex, "onBackground" to onBackground.hex,
        "surface" to surface.hex, "onSurface" to onSurface.hex,
        "surfaceVariant" to surfaceVariant.hex, "onSurfaceVariant" to onSurfaceVariant.hex,
        "outline" to outline.hex, "outlineVariant" to outlineVariant.hex,
        "surfaceContainerLowest" to surfaceContainerLowest.hex,
        "surfaceContainerLow" to surfaceContainerLow.hex,
        "surfaceContainer" to surfaceContainer.hex,
        "surfaceContainerHigh" to surfaceContainerHigh.hex,
        "surfaceContainerHighest" to surfaceContainerHighest.hex,
        "inverseSurface" to inverseSurface.hex, "inverseOnSurface" to inverseOnSurface.hex,
        "surfaceTint" to surfaceTint.hex, "scrim" to scrim.hex,
    )
}
