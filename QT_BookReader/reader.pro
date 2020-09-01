#-------------------------------------------------
#
# Project created by QtCreator 2016-11-28T17:03:23
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = reader
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    dialog.cpp \
    tree.cpp \
    filename.cpp \
    mark.cpp

HEADERS  += mainwindow.h \
    dialog.h \
    tree.h \
    filename.h \
    mark.h

FORMS    += mainwindow.ui \
    dialog.ui \
    filename.ui \
    mark.ui
