#ifndef CERT_TEST_PARAMS_H
#define CERT_TEST_PARAMS_H

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define true 1
#define false 0

#define TEST_MODE           true
#define REMOVE_TEST_FILE    false

extern char* SUPPORTED_SIG_ALGS[];

// Path for directores used in the test
#define DIR_ROOT            "/"
#define DIR_PROJECT_ROOT    DIR_ROOT "socket/"
#define DIR_PQC_ROOT        DIR_PROJECT_ROOT "pqc/"
#define DIR_PQC_SRC         DIR_PQC_ROOT "src/"
#define DIR_PQC_TEST        DIR_PQC_SRC "test/"

#define DIR_KEYS            DIR_PQC_TEST "keys/"
#define DIR_CSRS            DIR_PQC_TEST "csrs/"
#define DIR_CERTS           DIR_PQC_TEST "certs/"

#endif