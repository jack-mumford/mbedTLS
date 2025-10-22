
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "tls_utils.h"
#include "proto.h"

int main(int argc, char** argv) {
    const char* host = (argc > 1) ? argv[1] : APP_HOST_DEFAULT;
    const char* port = (argc > 2) ? argv[2] : APP_PORT_DEFAULT;
    const char* ca   = (argc > 3) ? argv[3] : "../certs/server.crt.pem";

    int fd;
    mbedtls_ssl_context ssl;
    if (tls_client_connect(host, port, ca, &fd, &ssl) != 0) {
        fprintf(stderr, "client connect failed\n");
        return 1;
    }

    // -------- Baseline: send an echo message --------
    // TODO: Replace this to build and send your PT time message.
    char line[MAX_LINE];
    proto_build_client_message(line, sizeof line);
    if (tls_send_line(&ssl, line) < 0) {
        fprintf(stderr, "send failed\n");
        goto cleanup;
    }

    // Receive server's response (echo for now)
    char resp[MAX_LINE];
    int n = tls_recv_line(&ssl, resp, sizeof resp);
    if (n <= 0) { fprintf(stderr, "recv failed (%d)\n", n); goto cleanup; }

    // -------- Baseline: print the echoed content --------
    // TODO: Replace this to parse ET message and print readable ET time + offset.
    printf("Server replied: %s\n", resp);

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    close(fd);
    mbedtls_ssl_free(&ssl);
    return 0;
}
