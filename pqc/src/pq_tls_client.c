// client.c
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/provider.h>

#define SERVER_ADDR "172.24.0.3"
#define SERVER_PORT 1316


void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "oqsprovider");
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_client_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void communicate_with_server(SSL *ssl) {
    char buffer[1024];
    SSL_write(ssl, "Hello from PQC-TLS Client", 25);
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        printf("Server response: %s\n", buffer);
    }
}

void run_client() {
    int sock;
    struct sockaddr_in server_addr;
    
    init_openssl();
    SSL_CTX *ctx = create_client_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    } else {
        communicate_with_server(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int main() {
    run_client();
    return 0;
}
