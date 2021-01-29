#include <cstdio>

void Usage(char* arg) {
    printf("syntax: %s <interface>\n", arg);
    printf("sample: %s wlan1\n", arg);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        Usage(argv[0]);
        return -1;
    }
}