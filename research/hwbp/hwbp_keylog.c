// Standalone no-frida TLS key extractor.
// Sets a hardware execute-breakpoint on ssl_log_secret in a TARGET process from
// the OUTSIDE (perf_event_open cross-process, PERF_SAMPLE_REGS_USER). Nothing is
// injected into the target: no frida, no ptrace-attach, no code patch, no LD
// preload. At the breakpoint, x0=SSL*, x1=label, x2=secret ptr, x3=len; the
// secret bytes and label string are read out of the target with /proc/pid/mem.
//
// This is the architecture that defeats PairIP / anti-frida for key extraction:
// their ptrace and code-integrity checks and their frida-spawn detector never
// see an external HW breakpoint set via the CPU debug registers.
//
// HW breakpoints are PER-TASK (the CPU debug registers are swapped per-thread at
// context switch), so perf_event_open(pid) only covers the ONE thread whose
// tid==pid. Real apps run TLS on worker threads, so we arm EVERY tid in
// /proc/<pid>/task and rescan periodically to catch threads spawned later.
//
// Usage: hwbp_keylog <pid> <lib-substr> <hex-offset-of-ssl_log_secret> [seconds]
// Build (arm64): aarch64-linux-gnu-gcc -O0 -static -o hwbp_keylog hwbp_keylog.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <poll.h>

#define MAXT 2048
#define MAXEV 8192   // events = threads * breakpoints

static long perf_open(struct perf_event_attr *a, pid_t pid, int cpu, int grp, unsigned long fl) {
    return syscall(SYS_perf_event_open, a, pid, cpu, grp, fl);
}

static int g_mem = -1;
// Android tags heap pointers in the top byte (TBI / Scudo memory tagging); the
// CPU ignores it on access but /proc/pid/mem needs the untagged VA.
#define UNTAG(a) ((uint64_t)(a) & 0x00ffffffffffffffULL)
static int rd(pid_t pid, uint64_t addr, void *buf, size_t n) {
    if (g_mem < 0) {
        char p[64]; snprintf(p, sizeof p, "/proc/%d/mem", pid);
        g_mem = open(p, O_RDONLY);
    }
    if (g_mem < 0) return -1;
    ssize_t r = pread(g_mem, buf, n, (off_t)UNTAG(addr));
    return r == (ssize_t)n ? 0 : -1;
}

typedef struct {
    int fd, tid;
    struct perf_event_mmap_page *meta;
    unsigned char *data;
    size_t dsz;
} ev_t;

static ev_t evs[MAXEV];
static int nev;
static int seen_tid[MAXT];   // tids we've already tried to arm
static int nseen;
#define MAXBP 16
static uint64_t g_bps[MAXBP]; static int g_nbps;   // absolute breakpoint addresses
static size_t g_pg;

static int already(int tid) { for (int i=0;i<nseen;i++) if (seen_tid[i]==tid) return 1; return 0; }

static void arm_one(int tid, uint64_t bp) {
    if (nev >= MAXEV) return;
    struct perf_event_attr a; memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_BREAKPOINT; a.size = sizeof a;
    a.bp_type = HW_BREAKPOINT_X; a.bp_addr = bp; a.bp_len = HW_BREAKPOINT_LEN_4;
    a.sample_period = 1; a.sample_type = PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL<<0)|(1ULL<<1)|(1ULL<<2)|(1ULL<<3);   // x0..x3
    a.wakeup_events = 1; a.disabled = 0; a.exclude_kernel = 1; a.exclude_hv = 1;
    int fd = (int)perf_open(&a, tid, -1, -1, 0);
    if (fd < 0) return;                       // thread may have exited between scan and open
    size_t npages = 1 + 4;
    void *rb = mmap(NULL, npages*g_pg, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (rb == MAP_FAILED) { close(fd); return; }
    ev_t *e = &evs[nev++];
    e->fd = fd; e->tid = tid; e->meta = rb;
    e->data = (unsigned char*)rb + g_pg; e->dsz = npages*g_pg - g_pg;
}

// arm every breakpoint on this thread (HW breakpoints are per-task).
static void arm_tid(int tid) {
    if (nseen >= MAXT || already(tid)) return;
    seen_tid[nseen++] = tid;                 // mark seen even on failure (no retry storm)
    for (int b = 0; b < g_nbps; b++) arm_one(tid, g_bps[b]);
}

static void rescan(pid_t pid) {
    char p[64]; snprintf(p, sizeof p, "/proc/%d/task", pid);
    DIR *d = opendir(p); if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        arm_tid(atoi(de->d_name));
    }
    closedir(d);
}

// SSL struct layout offsets for THIS BoringSSL build, RE'd from ssl_log_secret's
// own keylog formatter (ldr x23,[ssl,0x30] -> s3; client_random = s3+0x30, 32B).
// Per-build; re-derive from the disasm for a different libssl (e.g. cronet's).
// Overridable via env DECLAW_S3_OFF / DECLAW_CR_OFF (hex or dec).
// DECLAW_PTR32=1 for a 32-bit (armv7/Thumb) target: the SSL->s3 pointer is 4 bytes,
// not 8. arg regs x0..x3 already alias r0..r3, so only the pointer size changes.
// 32-bit Android system libssl: ssl_log_secret@0x1f13c, s3=0x18, cr=0x30, ptr32=1.
static uint64_t OFF_S3 = 0x30, OFF_CR = 0x30;
static int PTR32 = 0;

static FILE *g_keylog;
static int g_hits;
static void hexcat(char *dst, const unsigned char *b, int n) {
    static const char *H = "0123456789abcdef";
    for (int i=0;i<n;i++){ dst[2*i]=H[b[i]>>4]; dst[2*i+1]=H[b[i]&0xf]; }
    dst[2*n]=0;
}
// dedup on client_random+label so pooled re-reads don't spam the keylog
#define MAXSEEN 4096
static char seen_line[MAXSEEN][160]; static int nseen_line;
static int seen_add(const char *s){ for(int i=0;i<nseen_line;i++) if(!strcmp(seen_line[i],s)) return 0;
    if(nseen_line<MAXSEEN){ strncpy(seen_line[nseen_line],s,159); seen_line[nseen_line][159]=0; nseen_line++; } return 1; }

// Copy n bytes from ring offset `off` into dst, wrapping at the ring boundary. A perf
// record (or its fields) can straddle the mmap wrap; reading it linearly past
// e->data + e->dsz runs off the end of the mmap (OOB read / SIGSEGV).
static void ring_read(ev_t *e, uint64_t off, void *dst, size_t n) {
    off %= e->dsz;
    size_t first = e->dsz - off;
    if (first >= n) {
        memcpy(dst, e->data + off, n);
    } else {
        memcpy(dst, e->data + off, first);
        memcpy((unsigned char*)dst + first, e->data, n - first);
    }
}

static void drain(ev_t *e, pid_t pid) {
    uint64_t head = e->meta->data_head; __sync_synchronize();
    uint64_t tail = e->meta->data_tail;
    while (tail < head) {
        struct perf_event_header h;
        ring_read(e, tail, &h, sizeof h);              // wrap-aware header read
        if (h.type == PERF_RECORD_SAMPLE && h.size >= sizeof h + 40) {
            unsigned char pl[40];                      // abi(8) + x0..x3(32), wrap-aware
            ring_read(e, tail + sizeof h, pl, sizeof pl);
            uint64_t abi; memcpy(&abi, pl, 8); (void)abi;
            uint64_t x[4]; for (int k=0;k<4;k++) memcpy(&x[k], pl + 8 + 8*k, 8);
            char label[64]={0}; rd(pid, x[1], label, sizeof label - 1); label[sizeof label -1]=0;
            uint64_t slen = x[3]; if (slen > 64) slen = 64;
            unsigned char secret[64]; int sok = (slen && rd(pid, x[2], secret, slen)==0);
            // client_random from SSL* (x0): s3 = *(ssl+OFF_S3); cr = s3+OFF_CR, 32 bytes
            unsigned char cr[32]; uint64_t s3 = 0; int crok = 0;
            if (rd(pid, x[0]+OFF_S3, &s3, PTR32?4:8)==0 && s3) crok = (rd(pid, s3+OFF_CR, cr, 32)==0);
            g_hits++;
            if (sok && crok) {
                char crhex[65], sxhex[129], line[220];
                hexcat(crhex, cr, 32); hexcat(sxhex, secret, (int)slen);
                snprintf(line, sizeof line, "%s %s %s", label, crhex, sxhex);
                // dedup key is label+client_random only: the full line (up to 234B)
                // overruns seen_line[160] and never re-matches, so it would never dedup.
                char key[160]; snprintf(key, sizeof key, "%s %s", label, crhex);
                if (seen_add(key) && g_keylog) { fprintf(g_keylog, "%s\n", line); fflush(g_keylog); }
                printf("HIT tid=%d %s\n", e->tid, line);
            } else {
                printf("HIT tid=%d label=%.40s len=%llu %s%s\n", e->tid, label,
                       (unsigned long long)x[3], sok?"":"[secret-fail]", crok?"":"[cr-fail]");
            }
        }
        if (h.size == 0) break;   // malformed record guard: avoid an infinite loop
        tail += h.size;
    }
    e->meta->data_tail = tail;
}

// Resolve a lib substring + file offset to an absolute breakpoint address and add
// it to the list. '@abs' means off is already absolute. Unmapped lib is skipped.
static void add_bp(pid_t pid, const char *sub, uint64_t off) {
    if (g_nbps >= MAXBP) return;
    uint64_t addr;
    if (strcmp(sub, "@abs") == 0) addr = off;
    else {
        // off is a FILE offset (both the finder and find_verify return file offsets).
        // Resolve it exactly like hwbp_mempatch: find the r-x mapping of <sub> whose file
        // range covers off, then addr = start + (off - mapoff). The old base+off only
        // holds when the exec segment has p_vaddr==p_offset (delta 0, e.g. conscrypt); it
        // mislands on libflutter (delta 0x10000) and the frida gadget (delta 0x1000),
        // where the verify breakpoint then never fires and a correct patch gets reverted.
        char path[64]; snprintf(path, sizeof path, "/proc/%d/maps", pid);
        FILE *f = fopen(path, "r");
        if (!f) { fprintf(stderr, "hwbp: cannot open maps for pid %d\n", pid); return; }
        uint64_t start = 0, mapoff = 0; int found = 0; char line[1024];
        while (fgets(line, sizeof line, f)) {
            if (!strstr(line, sub)) continue;
            uint64_t s, e, o; char perms[8] = {0};
            if (sscanf(line, "%lx-%lx %7s %lx", &s, &e, perms, &o) != 4) continue;
            if (perms[2] != 'x') continue;              // executable segment only
            if (off >= o && off < o + (e - s)) { start = s; mapoff = o; found = 1; break; }
        }
        fclose(f);
        if (!found) {
            fprintf(stderr, "hwbp: lib '%s' has no exec mapping covering file off 0x%lx "
                    "in pid %d, skipping\n", sub, (unsigned long)off, pid);
            return;
        }
        addr = start + (off - mapoff);
    }
    g_bps[g_nbps++] = addr;
    printf("bp[%d] %s off=0x%lx -> 0x%lx\n", g_nbps - 1, sub, (unsigned long)off, (unsigned long)addr);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc < 4) { fprintf(stderr, "usage: %s <pid> <lib-substr|@abs> <hex-off> [seconds] [keylog] [lib2@off2 ...]\n", argv[0]); return 2; }
    pid_t pid = atoi(argv[1]);
    const char *sub = argv[2];
    uint64_t off = strtoull(argv[3], NULL, 16);
    int secs = (argc >= 5) ? atoi(argv[4]) : 20;
    const char *keylog_path = (argc >= 6) ? argv[5] : "/data/local/tmp/hwbp_keys.log";
    g_keylog = fopen(keylog_path, "w");
    { const char *e;
      if ((e = getenv("DECLAW_S3_OFF"))) OFF_S3 = strtoull(e, NULL, 0);
      if ((e = getenv("DECLAW_CR_OFF"))) OFF_CR = strtoull(e, NULL, 0);
      if ((e = getenv("DECLAW_PTR32"))) PTR32 = atoi(e); }

    g_pg = sysconf(_SC_PAGESIZE);

    // Breakpoint list: first from the positional (lib, off); extra ones from argv[6+]
    // as "lib@offset". Lets one run catch system libssl AND cronet AND any bundled
    // BoringSSL at once. A lib not mapped yet is skipped (warn), not fatal.
    add_bp(pid, sub, off);
    for (int i = 6; i < argc; i++) {
        char *at = strchr(argv[i], '@');
        if (!at) { fprintf(stderr, "hwbp: skip '%s' (want lib@offset)\n", argv[i]); continue; }
        *at = 0;
        add_bp(pid, argv[i], strtoull(at + 1, NULL, 16));
    }
    if (g_nbps == 0) { fprintf(stderr, "no breakpoint libs mapped in pid %d\n", pid); return 1; }

    rescan(pid);
    printf("target pid=%d breakpoints=%d armed_events=%d\n", pid, g_nbps, nev);
    if (nev == 0) { fprintf(stderr, "no threads armed (perf_event_open failed on all)\n"); return 1; }

    // Signal a cooperating self-test target that the breakpoint is armed.
    close(open("/data/local/tmp/hwbp_go", O_CREAT|O_WRONLY, 0644));

    int ticks = secs * 5;   // 200ms polls
    for (int t = 0; t < ticks; t++) {
        static struct pollfd pfds[MAXEV];
        for (int i = 0; i < nev; i++) { pfds[i].fd = evs[i].fd; pfds[i].events = POLLIN; }
        poll(pfds, nev, 200);
        for (int i = 0; i < nev; i++) drain(&evs[i], pid);
        if ((t % 5) == 0) rescan(pid);   // catch new threads ~1/s
    }
    if (g_keylog) fclose(g_keylog);
    printf("RESULT: ssl_log_secret hits=%d bps=%d threads=%d events=%d nss_lines=%d keylog=%s\n",
           g_hits, g_nbps, nseen, nev, nseen_line, keylog_path);
    return g_hits > 0 ? 0 : 3;
}
