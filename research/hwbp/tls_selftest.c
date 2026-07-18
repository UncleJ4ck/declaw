// Control target for the no-frida HWBP keylogger.
// Drives a REAL BoringSSL handshake through the system libssl (dlopen'd, the
// same /system/lib64/libssl.so an app's conscrypt uses) and logs the true TLS
// secrets via its OWN SSL_CTX_set_keylog_callback -> ground truth. A separate
// monitor (hwbp_keylog) breakpoints ssl_log_secret in THIS process with zero
// injection and must recover the identical secrets. Byte-match => real
// extraction, not a smoke test.
//
// Build (arm64): aarch64-linux-gnu-gcc -O0 -static-libgcc -o tls_selftest tls_selftest.c -ldl
// (dynamic; links host libdl only. Runs in redroid where /system/lib64 exists.)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>

static void *SSL_L, *CR_L;
#define S(sym) dlsym(SSL_L, sym)
#define C(sym) dlsym(CR_L, sym)

typedef void SSL, SSL_CTX, SSL_METHOD, BIO, X509, EVP_PKEY;

static char *slurp(const char *p, long *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(*n + 1);
    if (fread(b, 1, *n, f) != (size_t)*n) { fclose(f); return NULL; }
    b[*n] = 0; fclose(f); return b;
}

static FILE *g_gt;
// keylog_callback: line is the NSS format "LABEL <client_random_hex> <secret_hex>"
static void keylog_cb(const SSL *ssl, const char *line) {
    (void)ssl;
    if (g_gt) { fprintf(g_gt, "%s\n", line); fflush(g_gt); }
}

int main(void) {
    setbuf(stdout, NULL);
    SSL_L = dlopen("/system/lib64/libssl.so", RTLD_NOW | RTLD_GLOBAL);
    CR_L = dlopen("/system/lib64/libcrypto.so", RTLD_NOW | RTLD_GLOBAL);
    if (!SSL_L || !CR_L) { printf("dlopen failed: %s\n", dlerror()); return 1; }

    // resolve
    const SSL_METHOD *(*TLS_method)(void) = S("TLS_method");
    SSL_CTX *(*SSL_CTX_new)(const SSL_METHOD *) = S("SSL_CTX_new");
    int (*SSL_CTX_use_certificate)(SSL_CTX *, X509 *) = S("SSL_CTX_use_certificate");
    int (*SSL_CTX_use_PrivateKey)(SSL_CTX *, EVP_PKEY *) = S("SSL_CTX_use_PrivateKey");
    void (*SSL_CTX_set_keylog_callback)(SSL_CTX *, void (*)(const SSL *, const char *)) = S("SSL_CTX_set_keylog_callback");
    SSL *(*SSL_new)(SSL_CTX *) = S("SSL_new");
    void (*SSL_set_connect_state)(SSL *) = S("SSL_set_connect_state");
    void (*SSL_set_accept_state)(SSL *) = S("SSL_set_accept_state");
    void (*SSL_set_bio)(SSL *, BIO *, BIO *) = S("SSL_set_bio");
    int (*SSL_do_handshake)(SSL *) = S("SSL_do_handshake");
    int (*SSL_get_error)(const SSL *, int) = S("SSL_get_error");
    int (*SSL_is_init_finished)(const SSL *) = S("SSL_is_init_finished");

    BIO *(*BIO_new_mem_buf)(const void *, int) = C("BIO_new_mem_buf");
    X509 *(*PEM_read_bio_X509)(BIO *, X509 **, void *, void *) = C("PEM_read_bio_X509");
    EVP_PKEY *(*PEM_read_bio_PrivateKey)(BIO *, EVP_PKEY **, void *, void *) = C("PEM_read_bio_PrivateKey");
    int (*BIO_new_bio_pair)(BIO **, size_t, BIO **, size_t) = C("BIO_new_bio_pair");

    if (!TLS_method || !SSL_CTX_new || !BIO_new_bio_pair || !PEM_read_bio_X509 || !SSL_is_init_finished) {
        printf("symbol resolve failed\n"); return 1;
    }

    long nc, nk;
    char *crt = slurp("/data/local/tmp/hk.crt", &nc);
    char *key = slurp("/data/local/tmp/hk.key", &nk);
    if (!crt || !key) { printf("cert/key read failed\n"); return 1; }

    X509 *cert = PEM_read_bio_X509(BIO_new_mem_buf(crt, (int)nc), NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(BIO_new_mem_buf(key, (int)nk), NULL, NULL, NULL);
    if (!cert || !pkey) { printf("PEM parse failed\n"); return 1; }

    g_gt = fopen("/data/local/tmp/gt_keys.txt", "w");

    SSL_CTX *sctx = SSL_CTX_new(TLS_method());   // server
    SSL_CTX *cctx = SSL_CTX_new(TLS_method());   // client
    SSL_CTX_use_certificate(sctx, cert);
    SSL_CTX_use_PrivateKey(sctx, pkey);
    SSL_CTX_set_keylog_callback(sctx, keylog_cb);
    SSL_CTX_set_keylog_callback(cctx, keylog_cb);

    printf("PID %d\n", getpid());

    // Wait for the monitor to arm the breakpoint (it drops this flag file).
    for (int i = 0; i < 400; i++) {         // up to ~20s
        struct stat st;
        if (stat("/data/local/tmp/hwbp_go", &st) == 0) break;
        usleep(50000);
    }
    usleep(200000);

    // Three handshakes so several ssl_log_secret calls fire.
    int handshakes_ok = 0;
    for (int h = 0; h < 3; h++) {
        SSL *srv = SSL_new(sctx), *cli = SSL_new(cctx);
        BIO *sb, *cb2;
        BIO_new_bio_pair(&sb, 65536, &cb2, 65536);
        SSL_set_bio(srv, sb, sb);
        SSL_set_bio(cli, cb2, cb2);
        SSL_set_accept_state(srv);
        SSL_set_connect_state(cli);
        for (int i = 0; i < 100; i++) {
            SSL_do_handshake(cli);
            SSL_do_handshake(srv);
            if (SSL_is_init_finished(cli) && SSL_is_init_finished(srv)) { handshakes_ok++; break; }
        }
        usleep(150000);
    }
    printf("handshakes_ok %d\n", handshakes_ok);
    if (g_gt) fclose(g_gt);
    // Ground-truth lines already on disk; count them.
    long n; char *gt = slurp("/data/local/tmp/gt_keys.txt", &n);
    int lines = 0; if (gt) for (long i = 0; i < n; i++) if (gt[i] == '\n') lines++;
    printf("ground_truth_keylog_lines %d\n", lines);
    usleep(500000);
    return 0;
}
