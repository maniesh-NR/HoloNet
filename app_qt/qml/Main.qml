// Main.qml — HoloNet main window, fully Material You.
import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import HoloNet 1.0

ApplicationWindow {
    id: win
    width: 460
    height: 700
    minimumWidth: 360
    minimumHeight: 520
    visible: true
    title: "HoloNet"

    property bool dark: Theme.themeMode === "dark" ||
                       (Theme.themeMode === "system" && systemDark)
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

    Connections {
        target: Ipc
        function onEvent(name, payload) {
            if (name === "state.changed") {
                try { win.state = JSON.parse(payload)["state"] || win.state; } catch (e) {}
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 104
            color: roles["surfaceContainer"]
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 20
                spacing: 2
                Label {
                    text: "HoloNet"
                    font.pixelSize: 30
                    font.bold: true
                    color: roles["onSurface"]
                }
                Label {
                    text: "Material You · " + Theme.seedHex
                    font.pixelSize: 12
                    color: roles["onSurfaceVariant"]
                }
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: win.navIndex

            Item {
                ColumnLayout {
                    anchors.centerIn: parent
                    width: Math.min(parent.width - 32, 420)
                    spacing: 18

                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        width: 176
                        height: 176
                        radius: width / 2
                        color: win.state === "connected" ? roles["primary"] : roles["primaryContainer"]
                        Column {
                            anchors.centerIn: parent
                            spacing: 4
                            Label {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: "HOLO"
                                font.pixelSize: 26
                                font.bold: true
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
                            Accessible.name: "Toggle connection"
                            Accessible.role: Accessible.Button
                            onClicked: {
                                if (win.state === "connected")
                                    Ipc.request("session.disconnect", {}, function(r){})
                                else
                                    Ipc.request("session.connect", {"profileId": ""}, function(r){})
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.maximumWidth: 420
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredHeight: 64
                        radius: Theme.shapeMedium
                        color: roles["surfaceContainerLow"]
                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 10
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

            Item {
                Flickable {
                    anchors.fill: parent
                    contentWidth: width
                    contentHeight: settingsColumn.implicitHeight + 40
                    clip: true

                    ColumnLayout {
                        id: settingsColumn
                        x: Math.max(20, (parent.width - width) / 2)
                        y: 20
                        width: Math.min(Math.max(0, parent.width - 40), 720)
                        spacing: 14

                        Label {
                            text: "Settings"
                            font.pixelSize: 26
                            font.bold: true
                            color: roles["onSurface"]
                        }
                        Label {
                            text: "Appearance"
                            font.pixelSize: 20
                            font.bold: true
                            color: roles["onSurface"]
                        }
                        Label {
                            text: "Choose how HoloNet looks. Your seed color is shared across platforms."
                            color: roles["onSurfaceVariant"]
                            font.pixelSize: 13
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 126
                            radius: Theme.shapeMedium
                            color: roles["surfaceContainerLow"]
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 8
                                Label {
                                    text: "Theme mode"
                                    color: roles["onSurface"]
                                    font.bold: true
                                }
                                ButtonGroup { id: modeGroup }
                                RowLayout {
                                    Layout.fillWidth: true
                                    RadioButton {
                                        Layout.fillWidth: true
                                        text: "System"
                                        ButtonGroup.group: modeGroup
                                        checked: Theme.themeMode === "system"
                                        onClicked: Theme.themeMode = "system"
                                    }
                                    RadioButton {
                                        Layout.fillWidth: true
                                        text: "Light"
                                        ButtonGroup.group: modeGroup
                                        checked: Theme.themeMode === "light"
                                        onClicked: Theme.themeMode = "light"
                                    }
                                    RadioButton {
                                        Layout.fillWidth: true
                                        text: "Dark"
                                        ButtonGroup.group: modeGroup
                                        checked: Theme.themeMode === "dark"
                                        onClicked: Theme.themeMode = "dark"
                                    }
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 82
                            radius: Theme.shapeMedium
                            color: roles["surfaceContainerLow"]
                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 12
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    Label {
                                        text: "Dynamic color"
                                        color: roles["onSurface"]
                                        font.bold: true
                                    }
                                    Label {
                                        text: "Android 12+ wallpaper colors when available."
                                        color: roles["onSurfaceVariant"]
                                        font.pixelSize: 11
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                    }
                                }
                                Switch {
                                    checked: Theme.dynamicColor
                                    onToggled: Theme.dynamicColor = checked
                                }
                            }
                        }

                        Label {
                            text: "Seed color"
                            color: roles["onSurface"]
                            font.bold: true
                        }
                        Flow {
                            Layout.fillWidth: true
                            spacing: 12
                            Repeater {
                                model: ["#6750A4", "#B3261E", "#0061A4", "#006E1C",
                                        "#7D5260", "#8C4E00", "#984061", "#3F6978"]
                                Rectangle {
                                    width: 44
                                    height: 44
                                    radius: 22
                                    color: modelData
                                    border.width: Theme.seedHex.toUpperCase() === modelData.toUpperCase() ? 3 : 0
                                    border.color: roles["primary"]
                                    MouseArea {
                                        anchors.fill: parent
                                        Accessible.name: "Choose seed color " + modelData
                                        Accessible.role: Accessible.Button
                                        onClicked: Theme.seedHex = modelData
                                    }
                                }
                            }
                        }
                        Label {
                            text: "Or enter a custom hex color"
                            color: roles["onSurfaceVariant"]
                            font.pixelSize: 12
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            TextField {
                                id: customSeed
                                Layout.fillWidth: true
                                placeholderText: "#RRGGBB"
                                text: Theme.seedHex
                                property bool validHex: /^#?[0-9a-fA-F]{6}$/.test(text)
                            }
                            Button {
                                text: "Apply"
                                enabled: customSeed.validHex
                                onClicked: Theme.seedHex = customSeed.text
                            }
                        }
                        Label {
                            text: "Changes apply to HoloNet on every platform."
                            color: roles["onSurfaceVariant"]
                            font.pixelSize: 11
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                        }
                    }
                }
            }

            Item {
                Label {
                    anchors.centerIn: parent
                    width: parent.width - 40
                    text: "Servers\nImport a link or refresh providers."
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    color: roles["onSurfaceVariant"]
                }
            }
        }
    }

    footer: TabBar {
        currentIndex: win.navIndex
        onCurrentIndexChanged: win.navIndex = currentIndex
        TabButton { text: "Home" }
        TabButton { text: "Settings" }
        TabButton { text: "Servers" }
    }
}
