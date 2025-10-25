
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "tls_utils.h"
#include "proto.h"

int main(int argc, char** argv) {
    const char* bind_ip = (argc > 1) ? argv[1] : APP_HOST_DEFAULT;
    const char* port    = (argc > 2) ? argv[2] : APP_PORT_DEFAULT;
    const char* cert    = (argc > 3) ? argv[3] : "../certs/server.crt.pem";
    const char* key     = (argc > 4) ? argv[4] : "../certs/server.key.pem";

    int lfd;
    if (tls_server_listen(bind_ip, port, cert, key, &lfd) != 0) {
        fprintf(stderr, "server listen failed\n");
        return 1;
    }
    fprintf(stderr, "Server listening on %s:%s (TLS)\n", bind_ip, port);

    while (1) {
        mbedtls_ssl_context ssl;
        int cfd;
        if (tls_server_accept(lfd, &ssl, &cfd) != 0) { continue; }
        fprintf(stderr, "Client connected over TLS\n");

        char line[MAX_LINE];
        int n = tls_recv_line(&ssl, line, sizeof line);
        if (n <= 0) { fprintf(stderr, "recv failed (%d)\n", n); goto cleanup; }

        // -------- Baseline: echo --------
        // TODO: Replace with PT->ET conversion in your final solution.
        char resp[MAX_LINE];
        proto_handle_server_request(line, resp, sizeof resp);
        if (tls_send_line(&ssl, resp) < 0) { fprintf(stderr, "send failed\n"); }

    cleanup:
        mbedtls_ssl_close_notify(&ssl);
        close(cfd);
        mbedtls_ssl_free(&ssl);
    }
    return 0;
}
