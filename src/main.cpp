#include <cstdio>
#include <pcap.h>
#include <string>
#include <map>
#include <set>
#include <utility>
#include <iostream>
#include "mac.h"
#include "radiotaphdr.h"
#include "ieeehdr.h"

#define FIX_SIZE 12

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

void Render() {
    system("cls");
    printf("\nnulLeeKH's airodump\n");
    printf("\n[Beacon] BSSID\t\t\tPWR\tBeacons\tESSID\n");
    for (auto temp = beaconKey.begin(); beaconKey.end() != temp; ++temp) {
        std::cout << (Mac)(*temp) << "\t\t\t" << beaconMap[(Mac)(*temp)].power << "\t" << beaconMap[(Mac)(*temp)].packets << "\t" << beaconMap[(Mac)(*temp)].ssid << std::endl;
    }
    printf("\n[Probe]  BSSID\t\t\tPWR\tBeacons\tESSID\n");
    for (auto temp = probeKey.begin(); probeKey.end() != temp; ++temp) {
        std::cout << (Mac)(*temp) << "\t\t\t" << probeMap[(Mac)(*temp)].power << "\t" << probeMap[(Mac)(*temp)].packets << "\t" << probeMap[(Mac)(*temp)].ssid << std::endl;
    }
}

void InsertPacketData(Mac macAddr, uint8_t antPwr, std::string ssid, bool isProbe) {
    PacketData newData{0, 0, ""};

    if (isProbe) {
        probeKey.insert(macAddr);
        auto insertPosition = probeMap.find(macAddr);
        if (probeMap.end() == insertPosition) probeMap[macAddr] = newData;
        probeMap[macAddr].power = antPwr;
        probeMap[macAddr].packets++;
        probeMap[macAddr].ssid = std::move(ssid);
    } else {
        beaconKey.insert(macAddr);
        auto insertPosition = beaconMap.find(macAddr);
        if (beaconMap.end() == insertPosition) beaconMap[macAddr] = newData;
        beaconMap[macAddr].power = antPwr;
        beaconMap[macAddr].packets++;
        beaconMap[macAddr].ssid = std::move(ssid);
    }
}

void AirodumpLoop(pcap_t* handle) {
    struct pcap_pkthdr* hdr;
    const u_char* pkt;
    u_int ip, tcp, payload;
    int res;

    res = pcap_next_ex(handle, &hdr, &pkt);

    if (0 == res) return;
    else if (-1 == res || -2 == res) {
        printf("FATAL: pcap_next_ex | res=%d", res);
    }

    auto* radiotapH = (radHdr*)(pkt);
    auto* ieeeH = (ieeeHdr*)(pkt+RADIOTAP_SIZE);

    if (PROBE_SUBTYPE != ieeeH->subtype && BEACON_SUBTYPE != ieeeH->subtype) return;

    auto* ssidF = (ssidField*)(pkt+RADIOTAP_SIZE+IEEE_SIZE+FIX_SIZE);

    uint8_t ssidLen = ssidF->len;
    char* ssid = (char*)malloc(sizeof(char)*(ssidLen+1));
    char* ssidTemp = (char*)(pkt+RADIOTAP_SIZE+IEEE_SIZE+FIX_SIZE+SSID_SIZE);
    memcpy(ssid, ssidTemp, sizeof(char)*(ssidLen+1));
    ssid[ssidLen]=0;

    InsertPacketData(ieeeH->bssid, radiotapH->atnSig, ssid, PROBE_SUBTYPE == ieeeH->subtype);
    Render();
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