// main.cpp — HoloNet Qt6/QML frontend entry (Windows 8.1+/Linux).
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QJsonObject>
#include <QPalette>
#include <QQuickStyle>
#include "materialyou.h"
#include "ipcclient.h"

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    QQuickStyle::setStyle("Material");

    Theme theme;
    IpcClient ipc;
    bool settingsLoaded = false;
    const bool systemDark = app.palette().color(QPalette::Window).lightness() < 128;

    qmlRegisterSingletonInstance("HoloNet", 1, 0, "Theme", &theme);
    qmlRegisterSingletonInstance("HoloNet", 1, 0, "Ipc", &ipc);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("systemDark", systemDark);

    QObject::connect(&theme, &Theme::changed, &app, [&ipc, &theme, &settingsLoaded]() {
        if (!settingsLoaded || !ipc.isConnected()) return;
        const QJsonObject values{
            {"theme_mode", theme.themeMode()},
            {"seed_color", theme.seedHex()},
            {"dynamic_color", theme.dynamicColor() ? "true" : "false"},
        };
        ipc.request("settings.set", {{"values", values}}, nullptr);
    });

    QString dataDir = qEnvironmentVariable("HOLONET_DATA");
    if (dataDir.isEmpty()) {
        QString home = qEnvironmentVariable("HOME");
        if (home.isEmpty()) home = qEnvironmentVariable("USERPROFILE");
        if (!home.isEmpty()) dataDir = QDir(home).filePath(".config/holonet");
    }
    QString token;
    if (!dataDir.isEmpty()) {
        QFile tokenFile(QDir(dataDir).filePath("ipc-token"));
        if (tokenFile.open(QIODevice::ReadOnly | QIODevice::Text))
            token = QString::fromUtf8(tokenFile.readAll()).trimmed();
    }

    if (!token.isEmpty()) {
        ipc.connectToDaemon(7977, token, [&ipc, &theme, &settingsLoaded, systemDark](bool connected) {
            if (!connected) return;
            ipc.request("theme.get", {{"osTheme", systemDark ? "dark" : "light"}},
                        [&theme, &settingsLoaded](QJsonObject response) {
                const QJsonObject result = response.value("result").toObject();
                const QString seed = result.value("_seed").toString();
                const QString mode = result.value("_mode").toString();
                const QString dynamic = result.value("_dynamic").toString();
                if (!seed.isEmpty()) theme.setSeedHex(seed);
                if (!mode.isEmpty()) theme.setThemeMode(mode);
                if (dynamic == "true" || dynamic == "false")
                    theme.setDynamicColor(dynamic == "true");
                settingsLoaded = true;
            });
        });
    }

    engine.load(QUrl("qrc:/qml/Main.qml"));
    if (engine.rootObjects().isEmpty()) return -1;
    return app.exec();
}
