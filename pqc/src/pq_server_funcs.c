
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
    char response[BUFFER_SIZE];

    data_t parsed_message;

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

        if ( 0 == safe_strton(buffer, &parsed_message) ) {
            #if (DATA_TYPE == TYPE_INTEGER)
                sprintf(response, "Message received by PQC-TLS Server %d", parsed_message + 1);
            #elif (DATA_TYPE == TYPE_FLOAT)
                sprintf(response, "Message received by PQC-TLS Server %.7f", parsed_message + 1);
            #elif (DATA_TYPE == TYPE_DOUBLE)
                sprintf(response, "Message received by PQC-TLS Server %.15f", parsed_message + 1);
            #endif
            SSL_write(ssl, response, strlen(response));
        } else {
            printf("Message received by Client is not number\n");
            sprintf(response, "Message received by PQC-TLS Client is not number: %s", buffer);
            SSL_write(ssl, response, strlen(response));
            fflush(stdout);
        }
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

int is_valid_number(const char *str) {
    int dot_count = 0;
    
    for (int i = 0; str[i] != '\0'; i++) {
        // Continue if digit or '.'
        if ((str[i] >= '0' && str[i] <= '9') || str[i] == '.') {
            if (str[i] == '.') {
                dot_count++;
            }
        } else {
            return 0;  // return 0 if not a digit or '.'
        }
    }
    
    // str variable has to include only one or no dot
    return dot_count == 1 || dot_count == 0;
}

int safe_strton(const char *str, data_t *out) {
    // Check if the string is a valid number
    if (0 == is_valid_number(str)){
        return -1;  // return -1 if string is not a valid number or out of range of data type
    }
    
    char *endptr;
    errno = 0;

    #if (DATA_TYPE == TYPE_INTEGER)
        data_t val  = STR_TO_NUM(str, &endptr, 10); // 10 is base
    #else
        data_t val  = STR_TO_NUM(str, &endptr);
    #endif

    if (errno == ERANGE || val > NUM_MAX|| val < NUM_MIN) {
        return -1;
    }

    if (endptr == str) {
        return -1;
    }

    *out = val;
    return 0;
}