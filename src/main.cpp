#include <cstdio>
#include <pcap.h>
#include <string>
#include <map>
#include <set>
#include "mac.h"
#include "radiotaphdr.h"
#include "ieeehdr.h"

struct PacketData {
    int power;
    int packets;
    std::string ssid;
};

std::map<Mac, PacketData> beaconMap;
std::set<Mac> beaconKey;
std::map<Mac, PacketData> probeMap;
std::set<Mac> probeKey;

void Usage(char* arg) {
    printf("syntax: %s <interface>\n", arg);
    printf("sample: %s wlan1\n", arg);
}

void AirodumpLoop(pcap_t* handle) {
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        Usage(argv[0]);
        return -1;
    }

    char* dev = argv[1];
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errBuf);
    if (handle == nullptr) {
        printf("FATAL: Couldn't open device %s(%s)\n", dev, errBuf);
        return -1;
    }

    pcap_close(handle);
}