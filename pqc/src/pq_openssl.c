
#include "pq_openssl.h"

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "oqsprovider");
}

void cleanup_openssl() {
    EVP_cleanup();
}
