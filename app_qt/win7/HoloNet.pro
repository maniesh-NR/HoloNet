# HoloNet — Windows 7 build (Qt 5.15 LTS; same QML UI, shared C++ sources).
QT += quick network widgets
CONFIG += c++17
SOURCES += ../cpp/main.cpp ../cpp/materialyou.cpp ../cpp/ipcclient.cpp
HEADERS += ../cpp/materialyou.h ../cpp/ipcclient.h
# Qt 5.15: register the Theme singleton via qmlRegisterSingletonInstance in main.cpp.
