/* tls64ctl.c - controlled arm64 target for the HWBP monitor self-test.
 *
 * Mirrors the arm64 BoringSSL layout: ssl->s3 is an 8-byte pointer at ssl+0x30,
 * client_random at s3+0x30. Same sentinel bytes as tls32ctl.c. Two modes:
 *   ./tls64ctl          -> call ssl_log_secret from the main thread
 *   ./tls64ctl thread   -> call it ONLY from a worker thread (main blocks in join)
 * The thread mode proves the monitor arms every tid + rescans: if it armed only
 * the main pid it would capture nothing here. never() is a decoy for the
 * wrong-offset negative control (armed but never executed -> must be 0 hits).
 *
 * Build (arm64): gcc -O0 -static -no-pie -pthread -o tls64ctl tls64ctl.c
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

__attribute__((noinline, used))
void ssl_log_secret(void *ssl, const char *label,
                    const unsigned char *secret, unsigned int len) {
    static volatile unsigned long sink;
    sink = (unsigned long)ssl ^ (unsigned long)label
         ^ (unsigned long)secret ^ len;
}

/* second entry point (stands in for a second TLS lib): identical ABI, distinct
 * address, so the monitor can arm two breakpoints in one process (system libssl
 * + cronet + bundled BoringSSL is the real case). */
__attribute__((noinline, used))
void ssl_log_secret_b(void *ssl, const char *label,
                      const unsigned char *secret, unsigned int len) {
    static volatile unsigned long sink;
    sink = (unsigned long)ssl ^ (unsigned long)label
         ^ (unsigned long)secret ^ len;
}

/* decoy: same shape, never called. Arming here must yield 0 hits. */
__attribute__((noinline, used))
void never(void) { static volatile int x; x++; }

static unsigned char ssl[0x40];
static unsigned char s3buf[0x60];
static unsigned char secret[32];
static const char *label = "SENTINEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET";

/* second lib's distinct sentinels: client_random 0x10..0x2f, secret 0x30..0x4f */
static unsigned char ssl2[0x40];
static unsigned char s3buf2[0x60];
static unsigned char secret2[32];
static const char *label2 = "SENTINEL_SERVER_HANDSHAKE_TRAFFIC_SECRET";

static void setup(void) {
    for (int i = 0; i < 32; i++) s3buf[0x30 + i] = (unsigned char)(0xA0 + i);
    for (int i = 0; i < 32; i++) secret[i] = (unsigned char)(0xC0 + i);
    void *s3 = s3buf;
    memcpy(ssl + 0x30, &s3, sizeof(void *));   /* 8-byte s3 pointer on arm64 */
    for (int i = 0; i < 32; i++) s3buf2[0x30 + i] = (unsigned char)(0x10 + i);
    for (int i = 0; i < 32; i++) secret2[i] = (unsigned char)(0x30 + i);
    void *s3b = s3buf2;
    memcpy(ssl2 + 0x30, &s3b, sizeof(void *));
}

static void *worker(void *a) {
    (void)a;
    for (;;) { ssl_log_secret(ssl, label, secret, 32); usleep(200000); }
    return 0;
}

int main(int argc, char **argv) {
    setup();
    fprintf(stderr, "tls64ctl pid=%d sizeof_ptr=%zu log=%p never=%p mode=%s\n",
            (int)getpid(), sizeof(void *), (void *)&ssl_log_secret,
            (void *)&never, argc > 1 ? argv[1] : "single");
    fflush(stderr);
    if (argc > 1 && !strcmp(argv[1], "thread")) {
        pthread_t t;
        pthread_create(&t, 0, worker, 0);
        pthread_join(t, 0);          /* main never calls ssl_log_secret */
    } else if (argc > 1 && !strcmp(argv[1], "latethread")) {
        /* spawn the worker AFTER the monitor has already armed existing tids, so
         * only the periodic rescan can catch it (what real apps do: TLS on a
         * thread that appears mid-capture). */
        sleep(4);
        pthread_t t;
        pthread_create(&t, 0, worker, 0);
        pthread_join(t, 0);
    } else if (argc > 1 && !strcmp(argv[1], "multi")) {
        /* call BOTH entry points so two independent breakpoints in one process
         * each fire and emit their own sentinel line. */
        for (;;) {
            ssl_log_secret(ssl, label, secret, 32);
            ssl_log_secret_b(ssl2, label2, secret2, 32);
            usleep(200000);
        }
    } else if (argc > 1 && !strcmp(argv[1], "tag")) {
        /* Android TBI/Scudo tags heap pointers in the top byte. Pass tagged
         * pointers in r0/r1/r2 AND store a tagged s3 in memory; the monitor must
         * UNTAG every /proc/mem read or all of them fail. */
        #define TAGV(p) ((void *)((uintptr_t)(p) | (0xB4ULL << 56)))
        void *s3t = TAGV(s3buf);
        memcpy(ssl + 0x30, &s3t, sizeof(void *));
        for (;;) {
            ssl_log_secret(TAGV(ssl), (const char *)TAGV((void *)label),
                           (const unsigned char *)TAGV(secret), 32);
            usleep(200000);
        }
    } else {
        for (;;) { ssl_log_secret(ssl, label, secret, 32); usleep(200000); }
    }
    return 0;
}
