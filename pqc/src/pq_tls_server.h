#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/provider.h>

#define SERVER_CERT "/socket/pqc/src/build/falcon1024_srv.crt"
#define SERVER_KEY "/socket/pqc/src/build/falcon1024_srv.key"
#define PORT 1316

void init_openssl();
void cleanup_openssl();
SSL_CTX* create_server_context();
void handle_client(SSL *);
void run_server();
int main();