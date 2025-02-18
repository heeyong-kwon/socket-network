
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

void init_openssl();
void cleanup_openssl();
