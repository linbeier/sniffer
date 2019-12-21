#-------------------------------------------------
#
# Project created by QtCreator 2019-05-04T14:26:17
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app




# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += WPCAP
DEFINES += HAVE_REMOTE
# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        capthread.cpp \
        main.cpp \
        mainwindow.cpp \
        utility.cpp \
    arpthread.cpp

HEADERS += \
        WpdPack_4_1_2/WpdPack/Include/pcap.h \
        capthread.h \
        mainwindow.h \
        packet_format.h \
        utility.h \
    arpthread.h

FORMS += \
        mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

#LIBS += -L $$PWD/WpdPack_4_1_2/WpdPack/Lib/wpcap.lib
INCLUDEPATH += C:\Users\linxb\Documents\sniffer\WpdPack_4_1_2\WpdPack\Include

LIBS +=C:\Users\linxb\Documents\sniffer\WpdPack_4_1_2\WpdPack\Lib\wpcap.lib

LIBS +=C:\Users\linxb\Documents\sniffer\WpdPack_4_1_2\WpdPack\Lib\Packet.lib

LIBS +=C:\Users\linxb\Documents\sniffer\WpdPack_4_1_2\WpdPack\Lib\WS2_32.lib

DISTFILES += \
    WpdPack_4_1_2/WpdPack/Lib/Packet.lib \
    WpdPack_4_1_2/WpdPack/Lib/wpcap.lib
