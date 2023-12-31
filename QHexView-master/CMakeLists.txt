cmake_minimum_required(VERSION 3.12)

project(QHexView
    LANGUAGES CXX
)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

add_library(qhexview-lib STATIC
    document/buffer/qfilebuffer.cpp
    document/buffer/qhexbuffer.cpp
    document/buffer/qmemorybuffer.cpp
    document/buffer/qmemoryrefbuffer.cpp
    document/commands/hexcommand.cpp
    document/commands/insertcommand.cpp
    document/commands/removecommand.cpp
    document/commands/replacecommand.cpp
    document/qhexcursor.cpp
    document/qhexdocument.cpp
    document/qhexmetadata.cpp
    document/qhexrenderer.cpp
    qhexview.cpp
)

set_target_properties(qhexview-lib PROPERTIES
    AUTOMOC ON
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(qhexview-lib PRIVATE Qt5::Widgets)
target_include_directories(qhexview-lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
