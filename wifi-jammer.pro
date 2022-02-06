TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap  \
    -lpthread

SOURCES += \
    main.cpp    \
    iwlib.c

DESTDIR = $${PWD}/bin

HEADERS += \
    beacon.h \
    deauth.h \
    dot11.h \
    mac.h   \
    iwlib.h \
    wireless.h
