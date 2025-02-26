
#include "pq_client_funcs.h"

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
    char buffer[BUFFER_SIZE];

    printf("Connected to PQC-TLS Server. Type messages to send. Type 'exit' to quit.\n");

    while (1) {
        printf("Enter message: ");
        do{
            fgets(buffer, sizeof(buffer), stdin);
            buffer[strcspn(buffer, "\n")] = '\0';
            // 🔥 If an empty input is given, prompt the user to enter a message again.
            if (strlen(buffer) == 0) {
                printf("Empty input. Please enter a message.\nEnter message: ");
                continue;
            }
        } while(strlen(buffer) == 0);

        SSL_write(ssl, buffer, strlen(buffer));

        if (strncmp(buffer, "exit", 4) == 0) {
            printf("Closing connection...\n");
            break;
        }

        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Server response: %s\n", buffer);
        } else {
            printf("Server closed connection.\n");
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    // for (int i = 0; i < NUM_MESSAGES; i++) {
    //     sprintf(buffer, "Message %d", i);
    //     SSL_write(ssl, buffer, strlen(buffer));
    //     int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    //     if (bytes > 0) {
    //         printf("Server response: %s\n", buffer);
    //     }
    // }
    // SSL_write(ssl, "Hello from PQC-TLS Client", 25);
    // int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    // if (bytes > 0) {
    //     printf("Server response: %s\n", buffer);
    // }
}