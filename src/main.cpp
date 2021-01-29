#include <cstdio>
#include <pcap.h>

void Usage(char* arg) {
    printf("syntax: %s <interface>\n", arg);
    printf("sample: %s wlan1\n", arg);
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