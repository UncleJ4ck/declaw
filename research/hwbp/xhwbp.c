// Cross-process hardware-breakpoint + register-capture feasibility test.
// The single load-bearing unknown for the PairIP path: can a separate root
// process set a HW execute-breakpoint on ANOTHER task's code and read that
// task's user registers out of the perf sample ring buffer -- with NOTHING
// injected into the target (no frida, no ptrace attach, no code patch)?
//
// pe_test.c already proved the self-process path (pid=0, signal delivery).
// This tests the DIFFERENT kernel path the target requires: per-task debug-register
// load at context switch + PERF_SAMPLE_REGS_USER capture, cross-process, and
// whether TCG emulates that per-task DR swap at all.
//
// Model of the target: monitor (this parent) breakpoints the entry of a function the
// target (child) calls with a known magic in x0. At an execute breakpoint on
// the function entry, x0 holds the first argument. If we recover magic from
// the ring buffer, the mechanism that would read BoringSSL ssl_log_secret's
// (x0=SSL*, x1=label, x2=secret, x3=len) is proven on this kernel.
//
// Build (in the arm64 guest): gcc -O0 -o xhwbp xhwbp.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <poll.h>
#include <signal.h>

// Breakpoint lands at this entry. x0 = magic at that point. noinline + a real
// side effect so the compiler cannot fold/inline/const-propagate it away.
__attribute__((noinline)) long target_fn(long magic) {
    __asm__ __volatile__("" : "+r"(magic) :: "memory");
    return magic ^ 0x55;
}

static long perf_open(struct perf_event_attr *a, pid_t pid, int cpu, int grp, unsigned long fl) {
    return syscall(SYS_perf_event_open, a, pid, cpu, grp, fl);
}

int main(void) {
    setbuf(stdout, NULL);
    unsigned long bp_addr = (unsigned long)&target_fn;
    printf("target_fn @ %p\n", (void*)bp_addr);

    pid_t child = fork();
    if (child == 0) {
        // TARGET. Wait for the parent to arm, then call with distinctive x0.
        usleep(400000);
        for (int i = 0; i < 5; i++) {
            volatile long r = target_fn(0xC0DE00 + i);
            (void)r;
            usleep(120000);
        }
        _exit(0);
    }

    // MONITOR. Per-task event on the child, all CPUs (cpu = -1).
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_X;
    a.bp_addr = bp_addr;
    a.bp_len = HW_BREAKPOINT_LEN_4;              // arm64 insn length for a target bp
    a.sample_period = 1;                         // sample on every hit
    a.sample_type = PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL<<0)|(1ULL<<1)|(1ULL<<2)|(1ULL<<3); // x0..x3
    a.wakeup_events = 1;
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;

    int fd = (int)perf_open(&a, child, -1, -1, 0);
    printf("perf_event_open(cross-proc pid=%d) fd=%d errno=%d (%s)\n",
           child, fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "ok");
    if (fd < 0) { kill(child, 9); waitpid(child, 0, 0); return 1; }

    size_t pg = sysconf(_SC_PAGESIZE);
    size_t npages = 1 + 8;                       // 1 metadata + 8 data pages
    void *base = mmap(NULL, npages * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("mmap ring failed errno=%d (%s)\n", errno, strerror(errno));
        kill(child, 9); waitpid(child, 0, 0); return 1;
    }
    struct perf_event_mmap_page *meta = base;
    unsigned char *data = (unsigned char *)base + pg;
    size_t dsz = (npages - 1) * pg;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int samples = 0, good = 0, status, budget = 30;   // ~6s of 200ms polls
    while (budget-- > 0) {
        poll(&pfd, 1, 200);
        uint64_t head = meta->data_head;
        __sync_synchronize();
        uint64_t tail = meta->data_tail;
        while (tail < head) {
            struct perf_event_header *h = (void *)(data + (tail % dsz));
            if (h->type == PERF_RECORD_SAMPLE) {
                unsigned char *p = (unsigned char *)h + sizeof(*h);
                uint64_t abi;   memcpy(&abi, p, 8); p += 8;
                uint64_t x[4];
                for (int k = 0; k < 4; k++) { memcpy(&x[k], p, 8); p += 8; }
                samples++;
                int ok = (x[0] & 0xffff00) == 0xC0DE00;
                if (ok) good++;
                printf("SAMPLE #%d abi=%llu x0=0x%llx%s x1=0x%llx x2=0x%llx x3=0x%llx\n",
                       samples, (unsigned long long)abi, (unsigned long long)x[0],
                       ok ? " [magic OK]" : " [x0 mismatch]",
                       (unsigned long long)x[1], (unsigned long long)x[2],
                       (unsigned long long)x[3]);
            }
            tail += h->size;
        }
        meta->data_tail = tail;
        if (waitpid(child, &status, WNOHANG) == child) { budget = budget < 3 ? budget : 3; }
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    kill(child, 9); waitpid(child, 0, WNOHANG);
    printf("RESULT: cross-proc samples=%d magic-verified=%d -> CROSS-PROC HWBP %s\n",
           samples, good, (samples > 0 && good > 0) ? "WORKS" :
                           samples > 0 ? "FIRES but reg-capture wrong" : "did NOT fire");
    return (samples > 0 && good > 0) ? 0 : 2;
}
