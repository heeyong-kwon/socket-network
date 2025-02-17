// server.c
#include "pq_tls_server.h"

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "oqsprovider");
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_server_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // PQC 인증서 및 키 로드
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void handle_client(SSL *ssl) {
    char buffer[1024] = {0};
    for (int i = 0; i < 256; i++){
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            printf("Client message: %s\n", buffer);
            SSL_write(ssl, "Hello from PQC-TLS Server", 26);
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void run_server() {
    int sock;
    struct sockaddr_in addr;
    
    init_openssl();
    SSL_CTX *ctx = create_server_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 5);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handle_client(ssl);
        }
        close(client_sock);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int main() {
    run_server();
    return 0;
}
