/* BoringSSL client that loops real TLS 1.3 handshakes against a local server and
 * writes BoringSSL's OWN keylog (via SSL_CTX_set_keylog_callback) as ground truth.
 * The HWBP monitor armed on this process must extract the SAME label+secret bytes
 * with zero injection. Looping defeats the arm-before-handshake race.
 * Build: cc -o tls_keylog_loop tls_keylog_loop.c -I<inc> -L<dir> -lssl -lcrypto
 */
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static FILE *g_kl;
static void keylog_cb(const SSL *ssl, const char *line) {
    (void)ssl;
    if (g_kl) { fprintf(g_kl, "%s\n", line); fflush(g_kl); }
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 443;
    const char *klf = (argc > 2) ? argv[2] : "client_keys.log";
    const char *ip = (argc > 3) ? argv[3] : "127.0.0.1";
    g_kl = fopen(klf, "w");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);      /* we only want handshakes */
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);         /* BoringSSL's own keylog */
    fprintf(stderr, "keylog_loop pid=%d\n", (int)getpid());
    fflush(stderr);

    for (int i = 0; i < 100000; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(port);
        inet_pton(AF_INET, ip, &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, "one.one.one.one");   /* SNI */
            if (SSL_connect(ssl) == 1) { char b[64]; SSL_read(ssl, b, sizeof b); }
            SSL_shutdown(ssl); SSL_free(ssl);
        }
        close(fd);
        usleep(150000);
    }
    return 0;
}
