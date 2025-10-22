
#pragma once
#include <mbedtls/ssl.h>

int tls_client_connect(const char* host, const char* port,
                       const char* ca_pem_path,
                       int* out_fd, mbedtls_ssl_context* out_ssl);

int tls_server_listen(const char* bind_ip, const char* port,
                      const char* cert_path, const char* key_path,
                      int* out_listen_fd);

int tls_server_accept(int listen_fd, mbedtls_ssl_context* out_ssl, int* out_client_fd);

// Robust line I/O
int tls_send_all(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
int tls_send_line(mbedtls_ssl_context* ssl, const char* line);
int tls_recv_line(mbedtls_ssl_context* ssl, char* buf, size_t buflen);
