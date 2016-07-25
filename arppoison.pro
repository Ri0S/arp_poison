TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap
SOURCES += main.c \
    networkinfo.c \
    arp.c

HEADERS += \
    networkinfo.h \
    arp.h

