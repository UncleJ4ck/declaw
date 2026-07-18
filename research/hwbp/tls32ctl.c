/* tls32ctl.c - controlled 32-bit (AArch32) target for the HWBP monitor.
 *
 * Purpose: prove the PTR32 path end-to-end with negative-control ground truth.
 * It mimics BoringSSL's ssl_log_secret(SSL*, label, secret, len) ABI exactly:
 * at the call, r0=ssl, r1=label, r2=secret, r3=len. A HW execute-breakpoint on
 * the function entry must let the arm64 monitor recover ALL of:
 *   - label      (from r1)                       -> tests r1 aliasing
 *   - secret     (from r2, len from r3)          -> tests r2/r3 aliasing
 *   - client_random (r0 -> *(ssl+0x18) 4B -> +0x30, 32B) -> tests r0 + PTR32 read
 * Every byte is a known sentinel, so a correct capture is unambiguous and a
 * wrong one (bad compat-task reg aliasing, or 8-byte s3 read on a 32-bit target)
 * cannot masquerade as success.
 *
 * Build (in the arm64 guest): arm-linux-gnueabihf-gcc -marm -O0 -static -no-pie
 * Run: ./tls32ctl   (prints its pid + &ssl_log_secret, then loops calling it)
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* Real ABI, non-inlined, args touched so nothing is optimized away even at -O0. */
__attribute__((noinline, used))
void ssl_log_secret(void *ssl, const char *label,
                    const unsigned char *secret, unsigned int len) {
    static volatile unsigned int sink;
    sink = (unsigned int)(uintptr_t)ssl ^ (unsigned int)(uintptr_t)label
         ^ (unsigned int)(uintptr_t)secret ^ len;
}

/* decoy: never called. Arming a breakpoint here must yield 0 hits. */
__attribute__((noinline, used))
void never(void) { static volatile int x; x++; }

int main(void) {
    static unsigned char ssl[0x40];      /* fake SSL object */
    static unsigned char s3buf[0x60];    /* fake ssl->s3 target */
    static unsigned char secret[32];
    const char *label = "SENTINEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET";

    /* known client_random: 0xA0..0xBF at s3buf+0x30 */
    for (int i = 0; i < 32; i++) s3buf[0x30 + i] = (unsigned char)(0xA0 + i);
    /* known secret: 0xC0..0xDF */
    for (int i = 0; i < 32; i++) secret[i] = (unsigned char)(0xC0 + i);

    /* ssl->s3 is a 4-byte pointer at offset 0x18 on a 32-bit build */
    void *s3 = s3buf;
    memcpy(ssl + 0x18, &s3, sizeof(void *));   /* sizeof(void*)==4 here */
    /* non-zero guard right after s3: a wrong 8-byte read (no DECLAW_PTR32) picks
     * up 0xEEEEEEEE in the high word -> bogus s3 -> clean PTR32 negative control */
    memset(ssl + 0x1c, 0xEE, 4);

    fprintf(stderr, "tls32ctl pid=%d sizeof_ptr=%zu ssl=%p s3=%p log=%p\n",
            (int)getpid(), sizeof(void *), (void *)ssl, s3, (void *)&ssl_log_secret);
    fflush(stderr);

    for (;;) {
        ssl_log_secret(ssl, label, secret, 32);
        usleep(200000);   /* ~5 armed calls/sec, plenty for the monitor window */
    }
    return 0;
}
