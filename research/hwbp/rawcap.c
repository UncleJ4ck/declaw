// Minimal AF_PACKET sniffer -> pcap file. Self-contained so the rig needs no
// tcpdump. Runs as root in redroid, captures an interface for N seconds, writes a
// standard little-endian pcap (LINKTYPE_ETHERNET) that tshark/wireshark read.
// Used to prove --hwbp-capture keys are real: capture the encrypted traffic here,
// decrypt it with the HWBP NSS keylog.
// Build (arm64): aarch64-linux-gnu-gcc -O2 -static -o rawcap rawcap.c
// Usage: rawcap <iface|any> <seconds> <out.pcap>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <poll.h>

static void wr(FILE *f, const void *p, size_t n) { fwrite(p, 1, n, f); }

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s <iface|any> <seconds> <out.pcap>\n", argv[0]); return 2; }
    const char *iface = argv[1];
    int secs = atoi(argv[2]);
    FILE *out = fopen(argv[3], "wb");
    if (!out) { perror("fopen"); return 1; }

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) { perror("socket(AF_PACKET)"); return 1; }
    if (strcmp(iface, "any") != 0) {
        struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFINDEX, &ifr) == 0) {
            struct sockaddr_ll sll; memset(&sll, 0, sizeof sll);
            sll.sll_family = AF_PACKET; sll.sll_protocol = htons(ETH_P_ALL);
            sll.sll_ifindex = ifr.ifr_ifindex;
            if (bind(s, (struct sockaddr *)&sll, sizeof sll) < 0) perror("bind");
        } else perror("SIOCGIFINDEX (capturing all)");
    }

    // pcap global header (LE): magic, ver 2.4, tz 0, sig 0, snaplen, net=1 (ethernet)
    uint32_t gh[] = {0xa1b2c3d4, 0, 0, 65535, 1};
    uint16_t ver[] = {2, 4};
    fwrite(&gh[0], 4, 1, out); fwrite(ver, 2, 2, out);
    fwrite(&gh[1], 4, 1, out); fwrite(&gh[2], 4, 1, out);
    fwrite(&gh[3], 4, 1, out); fwrite(&gh[4], 4, 1, out);
    fflush(out);

    struct timeval start; gettimeofday(&start, NULL);
    unsigned char buf[65536];
    long pkts = 0;
    struct pollfd pfd = { .fd = s, .events = POLLIN };
    for (;;) {
        struct timeval now; gettimeofday(&now, NULL);
        if (now.tv_sec - start.tv_sec >= secs) break;
        if (poll(&pfd, 1, 300) <= 0) continue;
        ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) continue;
        gettimeofday(&now, NULL);
        uint32_t rec[4] = { (uint32_t)now.tv_sec, (uint32_t)now.tv_usec, (uint32_t)n, (uint32_t)n };
        wr(out, rec, sizeof rec);
        wr(out, buf, (size_t)n);
        pkts++;
    }
    fflush(out); fclose(out); close(s);
    fprintf(stderr, "rawcap: %ld packets -> %s\n", pkts, argv[3]);
    return 0;
}
