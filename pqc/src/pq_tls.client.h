#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/provider.h>

// Server's IP address
#define SERVER_ADDR "172.24.0.3"
#define SERVER_PORT 1316

#define NUM_MESSAGES 256

void init_openssl();
void cleanup_openssl();
SSL_CTX* create_client_context();
void communicate_with_server(SSL *);
void run_client();
int main();