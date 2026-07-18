// declaw mempatch: write the return-ssl_verify_ok stub into a RUNNING app's loaded
// BoringSSL via /proc/<pid>/mem. No file change (native integrity / PairIP passes), no
// frida (frida-detection blind), no PTRACE_ATTACH (anti-debug blind): /proc/pid/mem
// write uses FOLL_FORCE in the kernel, so it writes read-only executable .text and only
// needs PTRACE_MODE_ATTACH *permission* (root / CAP_SYS_PTRACE), never an actual attach.
//
// Usage: hwbp_mempatch <pid> <lib-substr> <hex-file-offset>
//   <lib-substr>       basename fragment of the mapped .so (e.g. libssl.so)
//   <hex-file-offset>  ssl_verify_peer_cert's file offset in that .so (ground truth from
//                      utils/find_ssl_verify.js / BoringSecretHunter), like --patch-boringssl.
// Exit 0 on a verified write, nonzero otherwise. arm64 stub (`mov w0,#0 ; ret`).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

static const unsigned char STUB[8] = {0x00,0x00,0x80,0x52,0xc0,0x03,0x5f,0xd6};

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pid> <lib-substr> <hex-file-offset> [hex-bytes]\n"
                        "  no [hex-bytes]: write the return-ssl_verify_ok stub (default).\n"
                        "  [hex-bytes]:    write those bytes instead (e.g. restore originals to revert).\n",
                argv[0]);
        return 2;
    }
    int pid = atoi(argv[1]);
    const char *sub = argv[2];
    uint64_t foff = strtoull(argv[3], NULL, 16);

    // payload: the fixed stub by default, or arbitrary bytes from argv[4] (revert/poke).
    const unsigned char *payload = STUB;
    int plen = 8;
    unsigned char custom[64];
    if (argc >= 5) {
        const char *h = argv[4];
        int n = 0;
        for (const char *p = h; p[0] && p[1] && n < (int)sizeof custom; p += 2) {
            char b[3] = {p[0], p[1], 0};
            custom[n++] = (unsigned char)strtoul(b, NULL, 16);
        }
        if (n == 0) { fprintf(stderr, "mempatch: empty/odd hex-bytes\n"); return 2; }
        payload = custom;
        plen = n;
    }

    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *m = fopen(path, "r");
    if (!m) { perror("open maps"); return 3; }

    // find the executable (r-x) mapping of <sub> whose file range covers foff, so we can
    // turn the .so file offset into the live virtual address: addr = start + (foff - mapoff)
    uint64_t start = 0, mapoff = 0;
    int found = 0;
    char line[1024];
    while (fgets(line, sizeof line, m)) {
        if (!strstr(line, sub)) continue;
        uint64_t s, e, o;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64, &s, &e, perms, &o) != 4)
            continue;
        if (perms[2] != 'x') continue;                 // must be the executable segment
        if (foff >= o && foff < o + (e - s)) { start = s; mapoff = o; found = 1; break; }
    }
    fclose(m);
    if (!found) {
        fprintf(stderr, "mempatch: no exec mapping of '%s' covering file off 0x%" PRIx64
                " (in-APK lib or wrong offset?)\n", sub, foff);
        return 3;
    }
    uint64_t addr = start + (foff - mapoff);

    snprintf(path, sizeof path, "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd < 0) { perror("open mem"); return 4; }

    unsigned char before[64] = {0}, after[64] = {0};
    pread(fd, before, plen, (off_t)addr);
    ssize_t w = pwrite(fd, payload, plen, (off_t)addr);  // FOLL_FORCE writes the r-x page
    if (w != plen) { perror("pwrite mem"); close(fd); return 5; }
    pread(fd, after, plen, (off_t)addr);                 // read-back verification
    close(fd);

    int ok = memcmp(after, payload, plen) == 0;
    int already = memcmp(before, payload, plen) == 0;
    printf("MEMPATCH pid=%d %s foff=0x%" PRIx64 " addr=0x%" PRIx64 " before=",
           pid, sub, foff, addr);
    for (int i = 0; i < plen; i++) printf("%02x", before[i]);
    printf(" %s%s\n", ok ? "OK" : "VERIFY-FAIL", already ? " (was already this)" : "");
    return ok ? 0 : 6;
}
