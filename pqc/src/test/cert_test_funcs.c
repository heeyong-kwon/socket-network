
#include "cert_test_funcs.h"

/* Create a directory */
void make_directory(const char *path){
    struct stat st;
    // Check if the directory exists
    if (stat(path, &st) == 0 && (st.st_mode & S_IFDIR)) {
        printf("The directory '%s' already exists\n", path);
    } else {
        // Create the directory
        if (MKDIR(path) == 0) {
            printf("The directory '%s' was created\n", path);
        } else {
            printf("Failed to create directory '%s'\n", path);
        }
    }
}

/* Remove a directory */
void delete_files_in_directory(const char *path) {
    struct dirent *entry;
    DIR *dp = opendir(path);
    
    if (dp == NULL) {
        printf("Can't open the directory: %s\n", path);
        return;
    }
    
    char *filepath;
    while ((entry = readdir(dp)) != NULL) {
        // Except current directory(.) and upper directory (..)
        if (entry->d_name[0] == '.') {
            continue;
        }

        size_t len_filepath = strlen(path) + strlen(entry->d_name) + 2;
        filepath = malloc(len_filepath);
        snprintf(filepath, len_filepath, "%s/%s", path, entry->d_name);
        
        // Remove files
        if (REMOVE(filepath) == 0) {
            printf("File removal: %s\n", filepath);
        } else {
            printf("Failed to remove the file: %s\n", filepath);
        }
        free(filepath);
    }

    closedir(dp);
    
    // Remove directory
    if (RMDIR(path) == 0) {
        printf("The directory was removed: %s\n", path);
    } else {
        printf("Failed to remove the directory!: %s\n", path);
    }
}

/* Generate certificate key */
EVP_PKEY *generate_certificate_key(char *sig_alg) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, sig_alg, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate failed\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Generate a certificate signing request (CSR) */
X509_REQ *generate_csr(char *sig_alg, EVP_PKEY *pkey) {
    // Make a name for csr
    char *csr_name_suffix   = " PQC Cert";
    size_t len_csr_name     = strlen(sig_alg) + strlen(csr_name_suffix) + 1;
    char *csr_name          = malloc(len_csr_name);
    if (!csr_name) {
        printf("Memory allocation failed!\n");
        return NULL;
    }
    snprintf(csr_name, len_csr_name, "%s%s", sig_alg, csr_name_suffix);

    X509_REQ *req = X509_REQ_new();
    if (!req) return NULL;

    X509_REQ_set_version(req, 1);
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)csr_name, -1, -1, 0);

    if (!X509_REQ_set_pubkey(req, pkey)) {
        X509_REQ_free(req);
        free(csr_name);
        return NULL;
    }

    if (!X509_REQ_sign(req, pkey, NULL)) {  // 서명
        X509_REQ_free(req);
        free(csr_name);
        return NULL;
    }

    printf("Certificate name set to: %s\n", csr_name);
    free(csr_name);
    return req;
}

/* Generate an X.509 certificate */
X509 *generate_cert(EVP_PKEY *pkey, X509_REQ *csr) {
    X509 *cert = X509_new();
    if (!cert) return NULL;

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1년 (365일)

    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(cert, X509_REQ_get_subject_name(csr));  // Self-Signed
    X509_set_pubkey(cert, pkey);

    if (!X509_sign(cert, pkey, NULL)) {  // 서명
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Save the key, CSR, and certificate to files */
void save_to_file(char *sig_alg, EVP_PKEY *pkey, X509_REQ *csr, X509 *cert) {
    char *key_suffix    = "_key.pem";
    char *csr_suffix    = "_csr.pem";
    char *cert_suffix   = "_cert.pem";

    make_directory(DIR_KEYS);
    size_t len_key_name = strlen(DIR_KEYS) + strlen(sig_alg) + strlen(key_suffix) + 1;
    char *path_key      = malloc(len_key_name);
    if (!path_key) {
        printf("Memory allocation failed!\n");
        return;
    }
    snprintf(path_key, len_key_name, "%s%s%s", DIR_KEYS, sig_alg, key_suffix);

    FILE *pkey_file = fopen(path_key, "wb");
    PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);


    make_directory(DIR_CSRS);
    size_t len_csr_name = strlen(DIR_CSRS) + strlen(sig_alg) + strlen(csr_suffix) + 1;
    char *path_csr      = malloc(len_csr_name);
    if (!path_csr) {
        printf("Memory allocation failed!\n");
        return;
    }
    snprintf(path_csr, len_csr_name, "%s%s%s", DIR_CSRS, sig_alg, csr_suffix);

    FILE *csr_file = fopen(path_csr, "wb");
    PEM_write_X509_REQ(csr_file, csr);
    fclose(csr_file);


    make_directory(DIR_CERTS);
    size_t len_cert_name    = strlen(DIR_CERTS) + strlen(sig_alg) + strlen(cert_suffix) + 1;
    char *path_cert         = malloc(len_cert_name);
    if (!path_cert) {
        printf("Memory allocation failed!\n");
        return;
    }
    snprintf(path_cert, len_cert_name, "%s%s%s", DIR_CERTS, sig_alg, cert_suffix);

    FILE *cert_file = fopen(path_cert, "wb");
    PEM_write_X509(cert_file, cert);
    fclose(cert_file);
    

    free(path_key);
    free(path_csr);
    free(path_cert);
}
