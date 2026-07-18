/* BoringSSL-linked TLS client that ENFORCES certificate verification.
 * Connects to 127.0.0.1:<port>, verifies the server cert against the system CA
 * store (which does NOT contain our self-signed test cert). So:
 *   unpatched libssl.so         -> SSL_connect fails (verify rejects bad cert)   [baseline]
 *   ssl_verify_peer_cert patched -> SSL_connect succeeds (bypass)                [declaw MITM]
 * The difference is the whole proof; nothing else changes between the two runs.
 *
 * Build: cc -o tls_verify_client tls_verify_client.c -I<bssl>/include -L<dir> -lssl -lcrypto
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 4433;
    const char *castore = (argc > 2) ? argv[2] : "/etc/ssl/certs/ca-certificates.crt";

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 2; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);      /* enforce verification */
    if (SSL_CTX_load_verify_locations(ctx, castore, NULL) != 1)
        fprintf(stderr, "warn: could not load CA store %s\n", castore);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "connect failed\n"); return 2;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    int r = SSL_connect(ssl);
    long vr = SSL_get_verify_result(ssl);
    if (r == 1) {
        printf("HANDSHAKE_OK cipher=%s verify_result=%ld\n", SSL_get_cipher(ssl), vr);
        SSL_shutdown(ssl); return 0;               /* handshake completed */
    } else {
        int e = SSL_get_error(ssl, r);
        printf("HANDSHAKE_FAIL ssl_err=%d verify_result=%ld (%s)\n",
               e, vr, X509_verify_cert_error_string(vr));
        return 1;
    }
}
