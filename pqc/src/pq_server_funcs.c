
#include "pq_server_funcs.h"

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

void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) {
            printf("Client disconnected or error occurred.\n");
            break;
        }

        buffer[bytes] = '\0';
        printf("Client message: %s\n", buffer);

        if (strncmp(buffer, "exit", 4) == 0) {
            printf("Client requested termination.\n");
            break;
        }

        char response[] = "Message received by PQC-TLS Server";
        SSL_write(ssl, response, strlen(response));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
    // char buffer[1024] = {0};
    // // for (int i = 0; i < 256; i++){
    // while(1){
    //     int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    //     if (bytes <= 0) {
    //         printf("Client disconnected or error occurred.\n");
    //         break;
    //     }
    //     buffer[bytes] = '\0';   // 문자열 긑 처리
    //     printf("Client message: %s\n", buffer);

    //     // "exit" 입력 시 클라이언트 연결 종료
    //     if (strncmp(buffer, "exit", 4) == 0) {
    //         printf("Client requested termination.\n");
    //         break;
    //     }

    //     // 서버 응답 메시지
    //     char response[] = "Message received by PQC-TLS Server";
    //     SSL_write(ssl, response, strlen(response));
    // }
    // // }
    // SSL_shutdown(ssl);
    // SSL_free(ssl);
}