#include <cstdint>
#include "mac.h"

#ifndef SRC_IEEEHDR_H
#define SRC_IEEEHDR_H

#define IEEE_SIZE 24
#define BEACON_SUBTYPE 0x80
#define PROBE_SUBTYPE 0x50

struct ieeeHdr {
    uint8_t subtype;
    uint8_t flag;
    uint16_t dur;
    Mac dMac;
    Mac sMac;
    Mac bssid;
    uint16_t seq;
};

#define SSID_SIZE 2

struct ssidField {
    uint8_t num;
    uint8_t len;
};

#endif //SRC_IEEEHDR_H
