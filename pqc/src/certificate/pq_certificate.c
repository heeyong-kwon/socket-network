
#include "pq_certificate.h"

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("🔹 Generating P-256_Falcon-512 Hybrid Key...\n");
    EVP_PKEY *pkey = generate_hybrid_key();
    if (!pkey) {
        fprintf(stderr, "❌ Failed to generate hybrid key\n");
        return -1;
    }

    printf("🔹 Generating X.509 v3 Hybrid Certificate...\n");
    X509 *x509 = generate_hybrid_x509_certificate(pkey);
    if (!x509) {
        fprintf(stderr, "❌ Failed to generate hybrid certificate\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    save_hybrid_key_and_cert(pkey, x509);

    EVP_PKEY_free(pkey);
    X509_free(x509);

    printf("✅ Hybrid X.509 v3 Certificate generated successfully!\n");

    return 0;
}

