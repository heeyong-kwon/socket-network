
#include "cert_test.h"

#if TEST_MODE == false
    char* SUPPORTED_SIG_ALGS[]  = {
        "mldsa44", "p256_mldsa44", "rsa3072_mldsa44", "mldsa44_pss2048", "mldsa44_rsa2048", "mldsa44_ed25519", "mldsa44_p256", "mldsa44_bp256", 
        "mldsa65", "p384_mldsa65", "mldsa65_pss3072", "mldsa65_rsa3072", "mldsa65_p256", "mldsa65_bp256", "mldsa65_ed25519", 
        "mldsa87", "p521_mldsa87", "mldsa87_p384", "mldsa87_bp384", "mldsa87_ed448", 
        "falcon512", "p256_falcon512", "rsa3072_falcon512", "falconpadded512", "p256_falconpadded512", "rsa3072_falconpadded512", 
        "falcon1024", "p521_falcon1024", "falconpadded1024", "p521_falconpadded1024", 
        "sphincssha2128fsimple", "p256_sphincssha2128fsimple", "rsa3072_sphincssha2128fsimple", "sphincssha2128ssimple", "p256_sphincssha2128ssimple", "rsa3072_sphincssha2128ssimple", 
        "sphincssha2192fsimple", "p384_sphincssha2192fsimple", 
        "sphincsshake128fsimple", "p256_sphincsshake128fsimple", "rsa3072_sphincsshake128fsimple", 
        "mayo1", "p256_mayo1", 
        "mayo2", "p256_mayo2", 
        "mayo3", "p384_mayo3", 
        "mayo5", "p521_mayo5", 
        "CROSSrsdp128balanced"
    };
#else
    char* SUPPORTED_SIG_ALGS[]  = {"p521_falcon1024"};
#endif


/* Main function */
int main() {
    int num_supported_sig_algs  = sizeof(SUPPORTED_SIG_ALGS) / sizeof(SUPPORTED_SIG_ALGS[0]);

    // Iterate for all supported signature algorithms
    for (int i = 0; i < num_supported_sig_algs; i++){
        printf("Generating %s certificate...\n", SUPPORTED_SIG_ALGS[i]);

        // Replace "p521_falcon1024" with the supported signature algorithm
        char *sig_alg   = SUPPORTED_SIG_ALGS[i];

        // Generate key, CSR, and certificate for the specified signature algorithm
        EVP_PKEY *pkey  = generate_certificate_key(sig_alg);
        if (!pkey) {
            fprintf(stderr, "Key generation failed.\n");
            return 1;
        }

        X509_REQ *csr   = generate_csr(sig_alg, pkey);
        if (!csr) {
            fprintf(stderr, "CSR generation failed.\n");
            EVP_PKEY_free(pkey);
            return 1;
        }

        X509 *cert = generate_cert(pkey, csr);
        if (!cert) {
            fprintf(stderr, "Certificate generation failed.\n");
            EVP_PKEY_free(pkey);
            X509_REQ_free(csr);
            return 1;
        }

        // Save the key, CSR, and certificate to files
        save_to_file(sig_alg, pkey, csr, cert);

        EVP_PKEY_free(pkey);
        X509_REQ_free(csr);
        X509_free(cert);

        // printf("%s certificate generated successfully.\n", sig_alg);
        printf("[%s] PQC Key, CSR, and Self-Signed Certificate generated successfully.\n", sig_alg);
    }

    #if REMOVE_TEST_FILE == true
        delete_files_in_directory(DIR_KEYS);
        delete_files_in_directory(DIR_CSRS);
        delete_files_in_directory(DIR_CERTS);
    #endif    

    return 0;
}
