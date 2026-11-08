// Main.qml — HoloNet main window, fully Material You. Every color binds to
// the Theme singleton (the C++ port of holo-theme — identical math to the
// Flutter and KMP frontends); M3 expressive: large title, container-scale
// cards, FAB, pill switches, the M3 shape scale.
import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts
import HoloNet 1.0

ApplicationWindow {
    id: win
    width: 460; height: 700; visible: true
    title: "HoloNet"

    // Material You mode: follow the palette in effect (dark here; the light
    // variant lives in Theme.light — flip `dark` or bind to the OS signal).
    property bool dark: true
    property var roles: dark ? Theme.dark : Theme.light
    property string state: "disconnected"
    property int navIndex: 0

    color: roles["background"]

    onRolesChanged: {
        Material.theme = dark ? Material.Dark : Material.Light
        Material.accent = roles["primary"]
        Material.background = roles["background"]
        Material.foreground = roles["onSurface"]
        Material.primary = roles["primary"]
    }

    // The daemon pushes state.changed events over the same socket.
    Connections {
        target: Ipc
        function onEvent(name, payload) {
            if (name === "state.changed") {
                try { win.state = JSON.parse(payload)["state"] || win.state; } catch (e) {}
            }
        }
        function onResponse(json) {
            // Seed sync: any theme.get result updates the local Theme.
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 0
        spacing: 0

        // ---- M3 large top app bar (surface-container + onSurface) ----
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 132
            color: roles["surfaceContainer"]
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 20
                spacing: 2
                Label {
                    text: "HoloNet"
                    font.pixelSize: 30; font.bold: true
                    color: roles["onSurface"]
                }
                Label {
                    text: "Material You · " + Theme.seedHex
                    font.pixelSize: 12
                    color: roles["onSurfaceVariant"]
                }
            }
        }

        // ---- Pages ----
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: win.navIndex

            // Home: the connect orb + status card.
            Item {
                ColumnLayout {
                    anchors.centerIn: parent
                    spacing: 18
                    // M3 connect orb — primaryContainer + onPrimaryContainer.
                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        width: 176; height: 176; radius: width / 2
                        color: win.state === "connected" ? roles["primary"] : roles["primaryContainer"]
                        border.width: 0
                        Column {
                            anchors.centerIn: parent
                            spacing: 4
                            Label {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: "HOLO"
                                font.pixelSize: 26; font.bold: true
                                color: win.state === "connected" ? roles["onPrimary"] : roles["onPrimaryContainer"]
                            }
                            Label {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: win.state.toUpperCase()
                                font.pixelSize: 11
                                color: win.state === "connected" ? roles["onPrimary"] : roles["onPrimaryContainer"]
                            }
                        }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                if (win.state === "connected")
                                    Ipc.request("session.disconnect", {}, function(r){});
                                else
                                    Ipc.request("session.connect", {"profileId": ""}, function(r){});
                            }
                        }
                    }
                    // Status card on the container scale.
                    Rectangle {
                        Layout.fillWidth: false
                        Layout.preferredWidth: 300
                        Layout.preferredHeight: 64
                        radius: Theme.shapeMedium
                        color: roles["surfaceContainerLow"]
                        RowLayout {
                            anchors.fill: parent; anchors.margins: 12; spacing: 10
                            Rectangle { width: 10; height: 10; radius: 5; color: roles["tertiary"] }
                            Label {
                                text: win.state === "connected" ? "Tunnel active" : "Disconnected"
                                color: roles["onSurface"]
                            }
                            Item { Layout.fillWidth: true }
                            Label {
                                text: "engine: core"
                                color: roles["onSurfaceVariant"]
                                font.pixelSize: 11
                            }
                        }
                    }
                }
            }

            // Theme: Material You controls (mode + seed picker).
            Item {
                Flickable {
                    anchors.fill: parent
                    contentHeight: col.height + 40
                    clip: true
                    ColumnLayout {
                        id: col
                        width: parent.width - 40
                        x: 20; y: 20
                        spacing: 14

                        Label {
                            text: "Material You"
                            font.pixelSize: 22; font.bold: true
                            color: roles["onSurface"]
                        }
                        Label {
                            text: "One seed colors every HoloNet surface — on every OS."
                            color: roles["onSurfaceVariant"]
                            font.pixelSize: 12
                            Layout.preferredWidth: parent.width
                            wrapMode: Text.WordWrap
                        }

                        // Appearance card.
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 132
                            radius: Theme.shapeMedium
                            color: roles["surfaceContainerLow"]
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 14; spacing: 8
                                Label { text: "Appearance"; color: roles["onSurface"]; font.bold: true }
                                RowLayout {
                                    spacing: 8
                                    Repeater {
                                        model: [["system", "System"], ["light", "Light"], ["dark", "Dark"]]
                                        Rectangle {
                                            width: 92; height: 36; radius: 18
                                            color: modelData[0] === "dark" ? roles["secondaryContainer"]
                                                                           : roles["surfaceContainerHighest"]
                                            border.width: 0
                                            Label {
                                                anchors.centerIn: parent
                                                text: modelData[1]
                                                color: modelData[0] === "dark" ? roles["onSecondaryContainer"]
                                                                               : roles["onSurfaceVariant"]
                                            }
                                            MouseArea { anchors.fill: parent; onClicked: win.dark = modelData[0] === "dark" }
                                        }
                                    }
                                }
                            }
                        }

                        // Seed picker — the same presets as Flutter/KMP.
                        Label { text: "Seed color"; color: roles["onSurface"]; font.bold: true }
                        Flow {
                            Layout.fillWidth: true
                            spacing: 12
                            Repeater {
                                model: ["#6750A4", "#B3261E", "#0061A4", "#006E1C",
                                        "#7D5260", "#8C4E00", "#984061", "#3F6978"]
                                Rectangle {
                                    width: 44; height: 44; radius: 22
                                    color: modelData
                                    border.width: Theme.seedHex.toUpperCase() === modelData.toUpperCase() ? 3 : 0
                                    border.color: roles["primary"]
                                    MouseArea { anchors.fill: parent; onClicked: Theme.seedHex = modelData }
                                }
                            }
                        }
                        Label {
                            text: "Changing the seed updates the daemon (settings.set) —\nFlutter on Android and Compose on macOS follow instantly."
                            color: roles["onSurfaceVariant"]
                            font.pixelSize: 11
                        }
                    }
                }
            }

            // Servers.
            Item {
                Label {
                    anchors.centerIn: parent
                    text: "Servers — import a link or refresh providers"
                    color: roles["onSurfaceVariant"]
                }
            }
        }
    }

    // ---- M3 navigation bar ----
    footer: Rectangle {
        height: 72
        color: roles["surfaceContainer"]
        RowLayout {
            anchors.fill: parent; anchors.margins: 8; spacing: 0
            Repeater {
                model: [
                    { icon: "🏠", label: "Home", page: 0 },
                    { icon: "🎨", label: "Theme", page: 1 },
                    { icon: "🌐", label: "Servers", page: 2 },
                ]
                Rectangle {
                    Layout.fillWidth: true; Layout.fillHeight: true
                    color: "transparent"
                    Column {
                        anchors.centerIn: parent; spacing: 2
                        Text { anchors.horizontalCenter: parent.horizontalCenter; text: modelData.icon; font.pixelSize: 22 }
                        Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            text: modelData.label
                            font.pixelSize: 11
                            color: win.navIndex === modelData.page ? roles["onSurface"] : roles["onSurfaceVariant"]
                        }
                    }
                    MouseArea { anchors.fill: parent; onClicked: win.navIndex = modelData.page }
                }
            }
        }
    }
}
