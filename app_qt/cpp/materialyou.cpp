// materialyou.cpp — implementation of the C++ port of holo-theme (the
// verified Rust reference). Kept header-light and Qt-free in the math so
// the algorithm reads identically across Rust/Dart/Kotlin/C++.
#include "materialyou.h"

#include <QtGlobal>
#include <cmath>

namespace holonet {
namespace {

constexpr double WHITE_POINT[3] = {0.95047, 1.0, 1.08883}; // D65

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

double srgbChannelToLinear(double c) {
    return c <= 0.04045 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
}

double encodeChannel(double v) {
    v = clamp01(v);
    const double s = v <= 0.0031308 ? v * 12.92 : 1.055 * std::pow(v, 1.0 / 2.4) - 0.055;
    return clamp01(s);
}

Lab srgbToLab(const Argb &c) {
    const double r = srgbChannelToLinear(c.r / 255.0);
    const double g = srgbChannelToLinear(c.g / 255.0);
    const double b = srgbChannelToLinear(c.b / 255.0);
    const double x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b;
    const double y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b;
    const double z = 0.0193339 * r + 0.1191920 * g + 0.9503041 * b;
    auto f = [](double t) {
        constexpr double E = 216.0 / 24389.0, K = 24389.0 / 27.0;
        return t > E ? std::cbrt(t) : (K * t + 16.0) / 116.0;
    };
    const double fx = f(x / WHITE_POINT[0]);
    const double fy = f(y / WHITE_POINT[1]);
    const double fz = f(z / WHITE_POINT[2]);
    return {116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz)};
}

struct Linear { double r, g, b; };

Linear labToLinear(const Lab &lab) {
    const double fy = (lab.l + 16.0) / 116.0;
    const double fx = fy + lab.a / 500.0;
    const double fz = fy - lab.b / 200.0;
    auto finv = [](double t) {
        constexpr double E = 6.0 / 29.0, K = 3.0 * E * E;
        return t > E ? t * t * t : K * (t - 4.0 / 29.0);
    };
    const double x = finv(fx) * WHITE_POINT[0];
    const double y = finv(fy) * WHITE_POINT[1];
    const double z = finv(fz) * WHITE_POINT[2];
    return {
        3.2404542 * x - 1.5371385 * y - 0.4985314 * z,
        -0.9692660 * x + 1.8760108 * y + 0.0415560 * z,
        0.0556434 * x - 0.2040259 * y + 1.0572252 * z,
    };
}

bool inGamut(const Lab &lab) {
    const Linear l = labToLinear(lab);
    return l.r >= 0.0 && l.r <= 1.0 && l.g >= 0.0 && l.g <= 1.0 && l.b >= 0.0 && l.b <= 1.0;
}

Argb labToSrgbExact(const Lab &lab) {
    const Linear l = labToLinear(lab);
    return Argb::rgb(
        static_cast<unsigned char>(std::lround(encodeChannel(l.r) * 255.0)),
        static_cast<unsigned char>(std::lround(encodeChannel(l.g) * 255.0)),
        static_cast<unsigned char>(std::lround(encodeChannel(l.b) * 255.0)));
}

Argb labToSrgbClamped(const Lab &lab) {
    if (inGamut(lab)) return labToSrgbExact(lab);
    double lo = 0.0, hi = 1.0;
    Lab best{lab.l, 0.0, 0.0};
    for (int i = 0; i < 24; ++i) {
        const double mid = (lo + hi) / 2.0;
        const Lab cand{lab.l, lab.a * mid, lab.b * mid};
        if (inGamut(cand)) { best = cand; lo = mid; } else { hi = mid; }
    }
    return labToSrgbExact(best);
}

Lab atHueChroma(double tone, double hueDeg, double chroma) {
    const double rad = hueDeg * M_PI / 180.0;
    return {tone, chroma * std::cos(rad), chroma * std::sin(rad)};
}

} // namespace

Argb Argb::fromHex(const QString &hex) {
    QString h = hex.trimmed();
    if (h.startsWith(QLatin1Char('#'))) h.remove(0, 1);
    unsigned char a = 255;
    if (h.size() == 8) {
        bool ok = false;
        a = static_cast<unsigned char>(h.left(2).toUInt(&ok, 16));
        if (!ok) return rgb(0, 0, 0);
        h = h.mid(2);
    }
    if (h.size() != 6) return rgb(0, 0, 0);
    bool ok = false;
    const unsigned int v = h.toUInt(&ok, 16);
    if (!ok) return rgb(0, 0, 0);
    return {a, static_cast<unsigned char>((v >> 16) & 0xff),
            static_cast<unsigned char>((v >> 8) & 0xff),
            static_cast<unsigned char>(v & 0xff)};
}

QString Argb::hex() const {
    static const char *digits = "0123456789abcdef";
    QString out;
    out.reserve(7);
    out.append(QLatin1Char('#'));
    for (unsigned char c : {r, g, b}) {
        out.append(QLatin1Char(digits[c >> 4]));
        out.append(QLatin1Char(digits[c & 0xf]));
    }
    return out;
}

Argb TonalPalette::tone(double t) const {
    return labToSrgbClamped(atHueChroma(t, hue_, chroma_));
}

MaterialYouPalettes MaterialYouPalettes::fromSeed(Argb seed) {
    const Lab lab = srgbToLab(seed);
    const double hue = std::fmod(std::atan2(lab.b, lab.a) * 180.0 / M_PI + 360.0, 360.0);
    const double chroma = std::sqrt(lab.a * lab.a + lab.b * lab.b);
    const double primaryChroma = std::fmax(48.0, std::fmin(120.0, chroma));
    return {
        TonalPalette(hue, primaryChroma),
        TonalPalette(hue, 16.0),
        TonalPalette(std::fmod(hue + 60.0, 360.0), 24.0),
        TonalPalette(hue, 4.0),
        TonalPalette(hue, 8.0),
        TonalPalette(25.0, 84.0),
    };
}

MaterialYouScheme MaterialYouScheme::of(const MaterialYouPalettes &p, Mode mode) {
    const bool dark = mode == Mode::Dark;
    const double tp = dark ? 80 : 40, to = dark ? 20 : 100;
    const double tc = dark ? 30 : 90, toc = dark ? 90 : 10;
    const double ts = dark ? 6 : 98, tos = dark ? 90 : 10;
    const double tsv = dark ? 30 : 90, tosv = dark ? 80 : 30;
    MaterialYouScheme s;
    s.primary = p.primary.tone(tp);            s.onPrimary = p.primary.tone(to);
    s.primaryContainer = p.primary.tone(tc);   s.onPrimaryContainer = p.primary.tone(toc);
    s.secondary = p.secondary.tone(tp);        s.onSecondary = p.secondary.tone(to);
    s.secondaryContainer = p.secondary.tone(tc); s.onSecondaryContainer = p.secondary.tone(toc);
    s.tertiary = p.tertiary.tone(tp);          s.onTertiary = p.tertiary.tone(to);
    s.tertiaryContainer = p.tertiary.tone(tc); s.onTertiaryContainer = p.tertiary.tone(toc);
    s.error = p.error.tone(tp);                s.onError = p.error.tone(to);
    s.errorContainer = p.error.tone(tc);       s.onErrorContainer = p.error.tone(toc);
    s.background = p.neutral.tone(ts);         s.onBackground = p.neutral.tone(tos);
    s.surface = p.neutral.tone(ts);            s.onSurface = p.neutral.tone(tos);
    s.surfaceVariant = p.neutralVariant.tone(tsv);
    s.onSurfaceVariant = p.neutralVariant.tone(tosv);
    s.outline = p.neutralVariant.tone(dark ? 60 : 50);
    s.outlineVariant = p.neutralVariant.tone(dark ? 30 : 80);
    s.surfaceContainerLowest = p.neutral.tone(dark ? 4 : 100);
    s.surfaceContainerLow = p.neutral.tone(dark ? 10 : 96);
    s.surfaceContainer = p.neutral.tone(dark ? 12 : 94);
    s.surfaceContainerHigh = p.neutral.tone(dark ? 17 : 92);
    s.surfaceContainerHighest = p.neutral.tone(dark ? 22 : 90);
    s.inverseSurface = p.neutral.tone(dark ? 90 : 20);
    s.inverseOnSurface = p.neutral.tone(dark ? 20 : 95);
    s.surfaceTint = p.primary.tone(tp);
    s.scrim = p.neutral.tone(0);
    return s;
}

QVariantMap MaterialYouScheme::toVariantMap() const {
    QVariantMap m;
    m.insert(QStringLiteral("primary"), primary.hex());
    m.insert(QStringLiteral("onPrimary"), onPrimary.hex());
    m.insert(QStringLiteral("primaryContainer"), primaryContainer.hex());
    m.insert(QStringLiteral("onPrimaryContainer"), onPrimaryContainer.hex());
    m.insert(QStringLiteral("secondary"), secondary.hex());
    m.insert(QStringLiteral("onSecondary"), onSecondary.hex());
    m.insert(QStringLiteral("secondaryContainer"), secondaryContainer.hex());
    m.insert(QStringLiteral("onSecondaryContainer"), onSecondaryContainer.hex());
    m.insert(QStringLiteral("tertiary"), tertiary.hex());
    m.insert(QStringLiteral("onTertiary"), onTertiary.hex());
    m.insert(QStringLiteral("tertiaryContainer"), tertiaryContainer.hex());
    m.insert(QStringLiteral("onTertiaryContainer"), onTertiaryContainer.hex());
    m.insert(QStringLiteral("error"), error.hex());
    m.insert(QStringLiteral("onError"), onError.hex());
    m.insert(QStringLiteral("errorContainer"), errorContainer.hex());
    m.insert(QStringLiteral("onErrorContainer"), onErrorContainer.hex());
    m.insert(QStringLiteral("background"), background.hex());
    m.insert(QStringLiteral("onBackground"), onBackground.hex());
    m.insert(QStringLiteral("surface"), surface.hex());
    m.insert(QStringLiteral("onSurface"), onSurface.hex());
    m.insert(QStringLiteral("surfaceVariant"), surfaceVariant.hex());
    m.insert(QStringLiteral("onSurfaceVariant"), onSurfaceVariant.hex());
    m.insert(QStringLiteral("outline"), outline.hex());
    m.insert(QStringLiteral("outlineVariant"), outlineVariant.hex());
    m.insert(QStringLiteral("surfaceContainerLowest"), surfaceContainerLowest.hex());
    m.insert(QStringLiteral("surfaceContainerLow"), surfaceContainerLow.hex());
    m.insert(QStringLiteral("surfaceContainer"), surfaceContainer.hex());
    m.insert(QStringLiteral("surfaceContainerHigh"), surfaceContainerHigh.hex());
    m.insert(QStringLiteral("surfaceContainerHighest"), surfaceContainerHighest.hex());
    m.insert(QStringLiteral("inverseSurface"), inverseSurface.hex());
    m.insert(QStringLiteral("inverseOnSurface"), inverseOnSurface.hex());
    m.insert(QStringLiteral("surfaceTint"), surfaceTint.hex());
    m.insert(QStringLiteral("scrim"), scrim.hex());
    return m;
}

} // namespace holonet

// ---------------------------------------------------------------------------
// Theme singleton
// ---------------------------------------------------------------------------

Theme::Theme(QObject *parent) : QObject(parent) {}

QVariantMap Theme::light() const {
    const holonet::Argb seed = holonet::Argb::fromHex(QString::fromLatin1(m_seedHex));
    return holonet::MaterialYouScheme::fromSeed(seed, holonet::Mode::Light).toVariantMap();
}

QVariantMap Theme::dark() const {
    const holonet::Argb seed = holonet::Argb::fromHex(QString::fromLatin1(m_seedHex));
    return holonet::MaterialYouScheme::fromSeed(seed, holonet::Mode::Dark).toVariantMap();
}

void Theme::setSeedHex(const QString &hex) {
    const holonet::Argb parsed = holonet::Argb::fromHex(hex);
    // Re-serialize for canonical form; invalid input keeps the current seed.
    const QByteArray canonical = parsed.hex().toLatin1();
    if (canonical == m_seedHex) return;
    m_seedHex = canonical;
    emit changed();
}
