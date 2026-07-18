#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

static volatile int hits = 0;
static void handler(int s, siginfo_t *si, void *uc) {
    hits++;
    ioctl(si->si_fd, PERF_EVENT_IOC_DISABLE, 0); /* one-shot, avoid signal storm */
}

int target_fn(int x) { return x + 1; }

int main(void) {
    setbuf(stdout, NULL); /* unbuffered so output shows even if we hang */
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_X;
    a.bp_addr = (unsigned long)&target_fn;
    a.bp_len = sizeof(long);
    a.sample_period = 1;
    a.wakeup_events = 1;
    a.disabled = 1;

    int fd = (int)syscall(SYS_perf_event_open, &a, 0 /*self*/, -1, -1, 0);
    printf("perf_event_open(BREAKPOINT_X) fd=%d errno=%d (%s)\n",
           fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "ok");
    if (fd < 0) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGIO, &sa, NULL);
    fcntl(fd, F_SETFL, O_ASYNC);
    fcntl(fd, F_SETSIG, SIGIO);
    fcntl(fd, F_SETOWN, getpid());
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    volatile int r = target_fn(41);  /* should trip the HW breakpoint */
    (void)r;
    usleep(50000);
    printf("breakpoint hits=%d -> HWBP %s\n", hits, hits > 0 ? "WORKS" : "did NOT fire");
    return hits > 0 ? 0 : 2;
}
