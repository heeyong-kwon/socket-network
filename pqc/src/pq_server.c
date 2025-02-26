
// server.c
#include "pq_server.h"

void run_server() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx = create_server_context();

    // 소켓 생성
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 바인딩
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 클라이언트 대기
    if (listen(server_fd, 5) == -1) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("PQC-TLS Server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        printf("New client connected.\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        printf("Starting TLS handshake with client...\n");
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            printf("TLS handshake failed.\n");
            close(client_fd);
            continue;
        }
        printf("TLS handshake successful!\n");

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void *)ssl) != 0) {
            perror("Failed to create thread");
            // SSL_shutdown(ssl);
            // SSL_free(ssl);
            close(client_fd);
        }

        pthread_detach(thread); // 스레드 종료 후 자동 정리
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    // int sock;
    // struct sockaddr_in addr;
    
    // init_openssl();
    // SSL_CTX *ctx = create_server_context();

    // sock = socket(AF_INET, SOCK_STREAM, 0);
    // addr.sin_family = AF_INET;
    // addr.sin_port = htons(PORT);
    // addr.sin_addr.s_addr = INADDR_ANY;

    // bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    // listen(sock, 5);

    // while (1) {
    //     struct sockaddr_in client_addr;
    //     socklen_t client_len = sizeof(client_addr);
    //     int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);

    //     SSL *ssl = SSL_new(ctx);
    //     SSL_set_fd(ssl, client_sock);
    //     if (SSL_accept(ssl) <= 0) {
    //         ERR_print_errors_fp(stderr);
    //     } else {
    //         handle_client(ssl);
    //     }
    //     close(client_sock);
    // }

    // close(sock);
    // SSL_CTX_free(ctx);
    // cleanup_openssl();
}

int main() {
    run_server();
    return 0;
}
