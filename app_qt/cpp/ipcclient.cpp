#include "ipcclient.h"

IpcClient::IpcClient(QObject *parent) : QObject(parent) {
    connect(&socket_, &QTcpSocket::readyRead, this, &IpcClient::onReadyRead);
}

void IpcClient::connectToDaemon(quint16 port, const QString &token,
                                std::function<void(bool)> onDone) {
    socket_.connectToHost("127.0.0.1", port);
    connect(&socket_, &QTcpSocket::connected, this, [this, token, onDone] {
        request("hello", {{"token", token}}, [this, onDone](QJsonObject r) {
            helloed_ = r.contains("result");
            if (onDone) onDone(helloed_);
        });
    });
    connect(&socket_, &QTcpSocket::errorOccurred, this, [onDone](QAbstractSocket::SocketError) {
        if (onDone) onDone(false);
    });
}

void IpcClient::request(const QString &method, const QJsonObject &params,
                        std::function<void(QJsonObject)> onResult) {
    const int id = static_cast<int>(nextId_++);
    QJsonObject o{{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}};
    pending_.insert(id, onResult);
    socket_.write(QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n");
}

void IpcClient::onReadyRead() {
    buffer_ += socket_.readAll();
    int nl;
    while ((nl = buffer_.indexOf('\n')) >= 0) {
        const QByteArray line = buffer_.left(nl).trimmed();
        buffer_.remove(0, nl + 1);
        if (line.isEmpty()) continue;
        const QJsonObject o = QJsonDocument::fromJson(line).object();
        if (o.value("method").toString() == "event") {
            const QJsonObject p = o.value("params").toObject();
            emit event(p.value("name").toString(),
                       QJsonDocument(p.value("payload").toObject()).toJson(QJsonDocument::Compact));
        } else {
            const int id = o.value("id").toInt();
            if (pending_.contains(id)) {
                auto cb = pending_.take(id);
                if (cb) cb(o);
            }
        }
    }
}
