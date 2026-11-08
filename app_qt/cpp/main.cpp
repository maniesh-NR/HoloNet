// main.cpp — HoloNet Qt6/QML frontend entry (Windows 8.1+/Linux).
// Registers the Material You Theme singleton (C++ port of holo-theme) so
// every QML component binds to the same M3 tokens as Flutter/KMP.
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include "materialyou.h"
#include "ipcclient.h"

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    QQuickStyle::setStyle("Material"); // M3-styled controls

    Theme theme; // seed defaults to #6750A4; settings.set syncs it daemon-wide
    IpcClient ipc;

    // Wire the Material You bridge: load the seed from the daemon on hello,
    // push seed changes back with settings.set (all OSes stay in sync).
    QObject::connect(&ipc, &IpcClient::response, &theme, [&theme](const QString &json) {
        const QJsonObject o = QJsonDocument::fromJson(json.toUtf8()).object();
        const QJsonObject r = o.value("result").toObject();
        const QString seed = r.value("_seed").toString();
        if (!seed.isEmpty()) theme.setSeedHex(seed);
    });

    qmlRegisterSingletonInstance("HoloNet", 1, 0, "Theme", &theme);
    qmlRegisterSingletonInstance("HoloNet", 1, 0, "Ipc", &ipc);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("themeSeedChanged",
                                             QVariant::fromValue(&theme));
    QObject::connect(&theme, &Theme::changed, [&ipc, &theme]() {
        if (ipc.isConnected()) {
            ipc.request("settings.set",
                        {{"values", QJsonObject{{"seed_color", theme.seedHex()}}}},
                        nullptr);
        }
    });

    engine.load(QUrl("qrc:/qml/Main.qml"));
    if (engine.rootObjects().isEmpty()) return -1;
    return app.exec();
}
