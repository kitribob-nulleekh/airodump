#include <cstdint>

#ifndef SRC_RADIOTAPHDR_H
#define SRC_RADIOTAPHDR_H

#define RADIOTAP_SIZE 18

struct radHdr {
    uint8_t rev;
    uint8_t pad;
    uint16_t len;
    uint32_t preFlag;
    uint8_t flag;
    uint8_t rate;
    uint16_t freq;
    uint16_t chnFlag;
    uint8_t atnSig;
    uint8_t atn;
    uint16_t rFlag;
};

#endif //SRC_RADIOTAPHDR_H
