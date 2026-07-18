// Discriminator target: an independent, already-running process that calls a
// known function in a loop. Used to prove the external HWBP fires when attaching
// to a PRE-EXISTING separate process (not a forked child), which is the exact
// scenario a real app presents. Prints its pid and the absolute address of the
// hot function so the monitor can be pointed at it with the @abs mode.
// Build (arm64): aarch64-linux-gnu-gcc -O0 -static -o busy busy.c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) long hotfn(long x) {
    __asm__ __volatile__("" : "+r"(x) :: "memory");
    return x * 3 + 1;
}

int main(void) {
    setbuf(stdout, NULL);
    printf("PID %d\n", getpid());
    printf("HOTADDR %p\n", (void*)&hotfn);
    long acc = 0;
    for (long i = 0; ; i++) {
        acc += hotfn(0xBEEF0000 + (i & 0xff));
        usleep(100000);           // ~10 calls/sec, easy to catch
    }
    return (int)acc;
}
