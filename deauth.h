#ifndef DEAUTH_H
#define DEAUTH_H

#include "dot11.h"

#pragma pack(push, 1)
struct DeauthPacket{
    RadiotapHdr radiotapHdr;    // 8 bytes
    uint32_t radiotapData;  // 4 bytes
    Dot11Hdr dot11Hdr;      // 24 bytes
    uint16_t fixedParm;     // 2 bytes

    DeauthPacket() {}
    DeauthPacket(Mac ap, Mac station){
        radiotapHdr.revision = 0x00;
        radiotapHdr.pad = 0x00;
        radiotapHdr.len = 0x000c;
        radiotapHdr.present = 0x00008004;
        radiotapData = 0x00180002;

        dot11Hdr.version = 0x00;
        dot11Hdr.type = 0x00;
        dot11Hdr.subtype = 0x0c;
        dot11Hdr.flag = 0x00;
        dot11Hdr.duration = 0x0000;
        if(station.compare(Mac("00:00:00:00:00:00"))) // station이 NULL인 경우
            dot11Hdr.addr1 = Mac("FF:FF:FF:FF:FF:FF");    // ra는 broadcast
        else    // station이 특정되어 있는 경우
            dot11Hdr.addr1 = station;  //ra는 특정 station
        dot11Hdr.addr2 = ap;    // ta
        dot11Hdr.addr3 = ap;    // bssid
        dot11Hdr.seqControl = 0x0000;

        fixedParm = 0x0007;
    }
};
#pragma pack(pop)

#endif
