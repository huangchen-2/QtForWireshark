QT       += core gui network concurrent

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17
CONFIG += console
msvc{
    QMAKE_CFLAGS += /utf-8
    QMAKE_CXXFLAGS += /utf-8
}



QMAKE_CXXFLAGS_RELEASE = $$QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO
QMAKE_LFLAGS_RELEASE = $$QMAKE_LFLAGS_RELEASE_WITH_DEBUGINFO

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    about.cpp \
    main.cpp \
    mainwindow.cpp \
    tcpclient.cpp \
    tcpserver.cpp \
    udpclient.cpp \
    wireshark.cpp \
    wiresharkselectui.cpp

HEADERS += \
    Stuct.h \
    about.h \
    mainwindow.h \
    tcpclient.h \
    tcpserver.h \
    udpclient.h \
    wireshark.h \
    wiresharkselectui.h

FORMS += \
    about.ui \
    mainwindow.ui \
    tcpclient.ui \
    tcpserver.ui \
    udpclient.ui \
    wireshark.ui \
    wiresharkselectui.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target



INCLUDEPATH += ./include
win32: LIBS += -L$$PWD/./ -lwpcap -lPacket

INCLUDEPATH += $$PWD/.
DEPENDPATH += $$PWD/.

include  ($$PWD/QHexView-master/QHexView.pri)

INCLUDEPATH += $$PWD/QHexView-master
