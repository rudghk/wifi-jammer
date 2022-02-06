#ifndef DOT11_H
#define DOT11_H

#include <stdint.h>
#include "mac.h"

struct RadiotapHdr{ // 8 bytes
    uint8_t revision;
    uint8_t pad;
    uint16_t len;   // radiotap total size
    uint32_t present;
};

struct Dot11Hdr{
    uint8_t version:2;    // 2bit
    uint8_t type:2;       // 2bit
    uint8_t subtype:4;    // 4bit
    uint8_t flag;
    uint16_t duration;
    Mac addr1;
    Mac addr2;
    Mac addr3;
    uint16_t seqControl;
};

#endif
