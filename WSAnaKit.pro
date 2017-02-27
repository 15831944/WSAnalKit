#-------------------------------------------------
#
# Project created by QtCreator 2016-12-19T15:12:25
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets  printsupport

TARGET = WSAnaKit
TEMPLATE = app

INCLUDEPATH += ./analyzer \
                ./common

SOURCES += main.cpp\
        mainwindow.cpp \
    anakit.cpp \
    analyzer/LibpCapFileMnger.cpp \
    common/XJErrorID.cpp \
    common/XJFile.cpp \
    analyzer/CapPackagesMnger.cpp \
    analyzer/CapPackageStatic.cpp \
    analyzer/PackageCovertWrapper.cpp \
    common/LogFile.cpp \
    common/xjlib.cpp \
    common/Msg2SmvPdu.cpp \
    common/ParseASN1.cpp \
    analyzer/CapTransformer.cpp \
    analyzer/Packet2Message.cpp \
    analyzer/ScanDissectPacketer.cpp \
    common/Lock.cpp \
    common/globalfun.cpp \
    common/XJString.cpp \
    qcustomplot.cpp \
    WaveWidget.cpp

HEADERS  += mainwindow.h \
    anakit.h \
    analyzer/LibpCapFileMnger.h \
    common/define_scan.h \
    common/Scan_Dissect_Pkt_Struct.h \
    common/XJErrorID.h \
    common/XJFile.h \
    analyzer/CapPackagesMnger.h \
    analyzer/CapPackageStatic.h \
    analyzer/PackageCovertWrapper.h \
    common/LogFile.h \
    common/xjlib.h \
    common/AT_STRUCT.h \
    common/Msg2SmvPdu.h \
    common/ParseASN1.h \
    analyzer/CapTransformer.h \
    analyzer/Packet2Message.h \
    analyzer/ScanDissectPacketer.h \
    common/Lock.h \
    qcustomplot.h \
    WaveWidget.h

win32{
    DEFINES += OS_WINDOWS
    DEFINES -= UNICODE
}

FORMS    += mainwindow.ui