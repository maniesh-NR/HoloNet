// materialyou.h — HoloNet's Material You color engine (C++ port of the
// verified Rust holo-theme crate). One seed → tonal palettes → all 33 M3
// color roles for light/dark. Registered as the QML singleton `Theme` so
// every QML component binds to identical tokens as the Flutter and KMP
// frontends.
//
// Model (documented deviation from Google's HCT): CIELAB with tone = L*,
// hue = atan2(b*, a*), chroma = C*, gamut-mapped by chroma binary search.
#pragma once
#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QColor>
#include <array>

namespace holonet {

struct Argb {
    unsigned char a = 255, r = 0, g = 0, b = 0;
    static Argb rgb(unsigned char r, unsigned char g, unsigned char b) { return {255, r, g, b}; }
    static Argb fromHex(const QString &hex);   // "#RRGGBB" or "#AARRGGBB"
    QString hex() const;                        // "#rrggbb"
    QColor toQColor() const { return QColor(r, g, b, a); }
};

struct Lab { double l, a, b; };

class TonalPalette {
public:
    TonalPalette(double hue, double chroma) : hue_(hue), chroma_(chroma) {}
    Argb tone(double t) const;
private:
    double hue_, chroma_;
};

struct MaterialYouPalettes {
    TonalPalette primary, secondary, tertiary, neutral, neutralVariant, error;
    static MaterialYouPalettes fromSeed(Argb seed);
};

enum class Mode { Light, Dark };

// The full M3 role set; toVariantMap() produces the QML-bindable
// {"primary": "#6750a4", "onPrimary": "#ffffff", ...} (33 roles).
struct MaterialYouScheme {
    Argb primary, onPrimary, primaryContainer, onPrimaryContainer;
    Argb secondary, onSecondary, secondaryContainer, onSecondaryContainer;
    Argb tertiary, onTertiary, tertiaryContainer, onTertiaryContainer;
    Argb error, onError, errorContainer, onErrorContainer;
    Argb background, onBackground, surface, onSurface;
    Argb surfaceVariant, onSurfaceVariant, outline, outlineVariant;
    Argb surfaceContainerLowest, surfaceContainerLow, surfaceContainer;
    Argb surfaceContainerHigh, surfaceContainerHighest;
    Argb inverseSurface, inverseOnSurface, surfaceTint, scrim;

    static MaterialYouScheme of(const MaterialYouPalettes &p, Mode mode);
    static MaterialYouScheme fromSeed(Argb seed, Mode mode) { return of(MaterialYouPalettes::fromSeed(seed), mode); }
    QVariantMap toVariantMap() const;
};

} // namespace holonet

// QML singleton — exposes roles + shape scale to every component.
class Theme : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantMap light READ light NOTIFY changed)
    Q_PROPERTY(QVariantMap dark READ dark NOTIFY changed)
    Q_PROPERTY(QString seedHex READ seedHex WRITE setSeedHex NOTIFY changed)
    Q_PROPERTY(int shapeSmall CONSTANT)
    Q_PROPERTY(int shapeMedium CONSTANT)
    Q_PROPERTY(int shapeLarge CONSTANT)
    Q_PROPERTY(int shapeExtraLarge CONSTANT)

public:
    explicit Theme(QObject *parent = nullptr);

    QVariantMap light() const;
    QVariantMap dark() const;
    QString seedHex() const { return QString::fromLatin1(m_seedHex); }
    void setSeedHex(const QString &hex);

    int shapeSmall() const { return 8; }
    int shapeMedium() const { return 12; }
    int shapeLarge() const { return 16; }
    int shapeExtraLarge() const { return 28; }

signals:
    void changed();
};
