#ifndef PQ_OPENSSL_H
#define PQ_OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <float.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

void init_openssl();
void cleanup_openssl();

#endif