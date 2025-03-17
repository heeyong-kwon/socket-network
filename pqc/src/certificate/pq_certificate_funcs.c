
#include "pq_certificate_funcs.h"




// ✅ OpenSSL 3.x 호환 Serial Number 생성
// ✅ 160-bit 난수로 Serial Number 생성 (20 bytes)
ASN1_INTEGER *generate_serial_number() {
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BIGNUM *bn = BN_new();

    if (!serial || !bn) {
        fprintf(stderr, "❌ Failed to allocate memory for Serial Number\n");
        ASN1_INTEGER_free(serial);
        BN_free(bn);
        return NULL;
    }

    // ✅ 160-bit (20 bytes) 난수 생성
    if (!BN_rand(bn, 160, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
        fprintf(stderr, "❌ Failed to generate random serial number\n");
        ASN1_INTEGER_free(serial);
        BN_free(bn);
        return NULL;
    }

    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);

    return serial;
}

// EVP_PKEY *generate_ecdsa_key() {
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    
//     if (!ctx) {
//         fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed for EC\n");
//         return NULL;
//     }

//     // 키 생성 초기화
//     if (EVP_PKEY_keygen_init(ctx) <= 0) {
//         fprintf(stderr, "EVP_PKEY_keygen_init failed for EC\n");
//         EVP_PKEY_CTX_free(ctx);
//         return NULL;
//     }

//     // ✅ 커브 이름 명시적으로 설정 (P-256)
//     if (EVP_PKEY_CTX_set_group_name(ctx, "P-256") <= 0) {
//         fprintf(stderr, "EVP_PKEY_CTX_set_group_name failed for P-256\n");
//         EVP_PKEY_CTX_free(ctx);
//         return NULL;
//     }

//     // 키 생성 수행
//     if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
//         fprintf(stderr, "ECDSA key generation failed\n");
//         EVP_PKEY_free(pkey);
//         pkey = NULL;
//     }

//     EVP_PKEY_CTX_free(ctx);
//     return pkey;
// }

// EVP_PKEY *generate_falcon_key() {
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "falcon512", NULL);

//     if (!ctx) {
//         fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed for Falcon-512\n");
//         return NULL;
//     }

//     if (EVP_PKEY_keygen_init(ctx) <= 0) {
//         fprintf(stderr, "EVP_PKEY_keygen_init failed for Falcon-512\n");
//         EVP_PKEY_CTX_free(ctx);
//         return NULL;
//     }

//     if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
//         fprintf(stderr, "Falcon-512 key generation failed\n");
//         EVP_PKEY_free(pkey);
//         pkey = NULL;
//     }

//     EVP_PKEY_CTX_free(ctx);
//     return pkey;
// }

EVP_PKEY *generate_hybrid_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "p256_falcon512", NULL);

    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed for p256_falcon512\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed for p256_falcon512\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        fprintf(stderr, "Hybrid key generation (P-256 + Falcon-512) failed\n");
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509 *generate_hybrid_x509_certificate(EVP_PKEY *pkey) {
    X509 *x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "X509_new failed\n");
        return NULL;
    }

    // ✅ X.509 Version 3 설정 (0-based index이므로 2로 설정)
    X509_set_version(x509, 2);

    // ✅ Serial Number 설정 (128-bit 난수로 확장)
    ASN1_INTEGER *serial = generate_serial_number();
    if (!serial) {
        fprintf(stderr, "❌ Failed to generate serial number\n");
        X509_free(x509);
        return NULL;
    }
    X509_set_serialNumber(x509, serial);
    ASN1_INTEGER_free(serial);

    // ✅ 유효 기간 설정 (현재부터 +1년)
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    // ✅ 공개 키 설정 (P-256_Falcon-512)
    X509_set_pubkey(x509, pkey);

    // ✅ 주체명 및 발급자 정보 설정
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"Hybrid Security Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"hybrid.example.com", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // ✅ X.509 v3 확장 필드 추가
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);

    X509_EXTENSION *ext;

    // 🔹 Basic Constraints: CA가 아님
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // 🔹 Key Usage (디지털 서명 및 키 암호화)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature, keyEncipherment");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // 🔹 Extended Key Usage (TLS 클라이언트 & 서버 인증)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth, clientAuth");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // 🔹 Subject Key Identifier (공개 키 식별자)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    /*
    // 🔹 Authority Key Identifier (발급자 식별자)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid,issuer");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    */

    // For Self-signed certificates
    // ✅ Authority Key Identifier (Self-Signed 대응)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);


    // ✅ P-256_Falcon-512로 서명
    if (!X509_sign(x509, pkey, NULL)) {
        fprintf(stderr, "❌ Hybrid (P-256 + Falcon-512) signing failed\n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

void save_hybrid_key_and_cert(EVP_PKEY *pkey, X509 *x509) {
    FILE *key_file = fopen("p256_falcon512_key.pem", "wb");
    FILE *cert_file = fopen("p256_falcon512_cert.pem", "wb");

    if (key_file && PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL))
        printf("✅ Hybrid Private Key (P-256 + Falcon-512) saved.\n");
    if (cert_file && PEM_write_X509(cert_file, x509))
        printf("✅ Hybrid Certificate (P-256 + Falcon-512) saved.\n");

    if (key_file) fclose(key_file);
    if (cert_file) fclose(cert_file);
}

