
// client.c
#include "pq_client.h"

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
