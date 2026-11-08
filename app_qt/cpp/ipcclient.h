// ipcclient.h — minimal NDJSON JSON-RPC client for holonetd (docs/IPC_API.md).
// The Material You contract: theme.get {osTheme} → the full M3 role map from
// the user's seed (kept in sync with the Flutter and KMP frontends).
#pragma once
#include <QObject>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <functional>

class IpcClient : public QObject {
    Q_OBJECT
public:
    explicit IpcClient(QObject *parent = nullptr);
    void connectToDaemon(quint16 port, const QString &token,
                         std::function<void(bool)> onDone = nullptr);
    void request(const QString &method, const QJsonObject &params,
                 std::function<void(QJsonObject)> onResult);
    bool isConnected() const { return helloed_; }

signals:
    void response(const QString &json);
    void event(const QString &name, const QString &payload);

private slots:
    void onReadyRead();

private:
    QTcpSocket socket_;
    QString buffer_;
    bool helloed_ = false;
    quint64 nextId_ = 2;
    QHash<int, std::function<void(QJsonObject)>> pending_;
};
