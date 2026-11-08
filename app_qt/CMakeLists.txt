cmake_minimum_required(VERSION 3.21)
project(HoloNet LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 COMPONENTS Quick Network REQUIRED)

qt_add_executable(holonet
    cpp/main.cpp
    cpp/materialyou.cpp cpp/materialyou.h
    cpp/ipcclient.cpp cpp/ipcclient.h
)
qt_add_qml_module(holonet URI HoloNet VERSION 1.0 QML_FILES qml/Main.qml)
target_link_libraries(holonet PRIVATE Qt6::Quick Qt6::Network)
target_compile_definitions(holonet PRIVATE QT_DEPRECATED_WARNINGS)
install(TARGETS holonet RUNTIME DESTINATION bin)
