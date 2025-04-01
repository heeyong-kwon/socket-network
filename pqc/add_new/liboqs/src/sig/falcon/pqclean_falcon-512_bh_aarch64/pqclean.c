/*
 * Wrapper for implementing the PQClean API.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#define NONCELEN   40

#include "randombytes.h"

#include <stdio.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
// #include <openssl/types.h>

/*
 * Encoding formats (nnnn = log of degree, 9 for Falcon-512, 10 for Falcon-1024)
 *
 *   private key:
 *      header byte: 0101nnnn
 *      private f  (6 or 5 bits by element, depending on degree)
 *      private g  (6 or 5 bits by element, depending on degree)
 *      private F  (8 bits by element)
 *
 *   public key:
 *      header byte: 0000nnnn
 *      public h   (14 bits by element)
 *
 *   signature:
 *      header byte: 0011nnnn
 *      nonce (r)  40 bytes
 *      value (s)  compressed format
 *
 *   message + signature:
 *      signature length   (2 bytes, big-endian)
 *      nonce              40 bytes
 *      message
 *      header byte:       0010nnnn
 *      value              compressed format
 *      (signature length is 1+len(value), not counting the nonce)
 */

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk) {
    union {
        uint8_t b[28 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[FALCON_N], g[FALCON_N], F[FALCON_N];
    uint16_t h[FALCON_N];
    unsigned char seed[48];
    inner_shake256_context rng;
    size_t u, v;

    /*
     * Generate key pair.
     */
    randombytes(seed, sizeof seed);
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof seed);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON512_BH_AARCH64_keygen(&rng, f, g, F, NULL, h, FALCON_LOGN, tmp.b);
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    sk[0] = 0x50 + FALCON_LOGN;
    u = 1;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            f, PQCLEAN_FALCON512_BH_AARCH64_max_fg_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            g, PQCLEAN_FALCON512_BH_AARCH64_max_fg_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            F, PQCLEAN_FALCON512_BH_AARCH64_max_FG_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + FALCON_LOGN;
    v = PQCLEAN_FALCON512_BH_AARCH64_modq_encode(
            pk + 1, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_PUBLICKEYBYTES - 1,
            h, FALCON_LOGN);
    if (v != PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}

/*
 * Compute the signature. nonce[] receives the nonce and must have length
 * NONCELEN bytes. sigbuf[] receives the signature value (without nonce
 * or header byte), with *sigbuflen providing the maximum value length and
 * receiving the actual value length.
 *
 * If a signature could be computed but not encoded because it would
 * exceed the output buffer size, then an error is returned.
 *
 * Return value: 0 on success, -1 on error.
 */
static int
do_sign(uint8_t *sigbuf, uint8_t *unused, size_t *sigbuflen,
        const uint8_t *m, size_t mlen, const uint8_t *sk, 
        //
        void *ctx_classical, size_t *signature_len_classical) {

    union {
        uint8_t b[72 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[FALCON_N], g[FALCON_N], F[FALCON_N], G[FALCON_N];
    struct {
        int16_t sig[FALCON_N];
        uint16_t hm[FALCON_N];
    } r;
    unsigned char seed[48];
    inner_shake256_context sc;
    size_t u, v;

    /*
     * Decode the private key.
     */
    if (sk[0] != 0x50 + FALCON_LOGN) {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_decode(
            f, PQCLEAN_FALCON512_BH_AARCH64_max_fg_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_decode(
            g, PQCLEAN_FALCON512_BH_AARCH64_max_fg_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_BH_AARCH64_trim_i8_decode(
            F, PQCLEAN_FALCON512_BH_AARCH64_max_FG_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }
    if (!PQCLEAN_FALCON512_BH_AARCH64_complete_private(G, f, g, F, tmp.b)) {
        return -1;
    }



    // (Mizzou, 2025)
    // Algorithm 20 in "A Note on Hybrid Signature Schemes", Bindel and Britta Hale

    /* 
     * Prepare for Falcon
     */
    uint8_t nonce[NONCELEN];

    /* 
     * Prepare for ECDSA
     */
    EVP_PKEY_CTX *ctx_ecdsa = (EVP_PKEY_CTX *) ctx_classical;
    const EVP_PKEY *pkey    = EVP_PKEY_CTX_get0_pkey(ctx_ecdsa);
    // const EC_KEY *ec_key    = EVP_PKEY_get1_EC_KEY(pkey);
    // if (!ec_key) return 0;
    // const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    // const EC_GROUP *group = EVP_PKEY_get_params(pkey, NULL);
    BIGNUM *order = NULL;
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_ORDER, &order);
    EC_GROUP *group = NULL;
    char curve_name[80];
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name)),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_get_params(pkey, params)) {
        int nid = OBJ_sn2nid(curve_name);
        if (nid != NID_undef) {
            group = EC_GROUP_new_by_curve_name(nid);
        }
    }
    if (!group) {
        printf("Failed to retrieve EC_GROUP\n");
        return 0;
    }
    // BN_CTX *ctx = BN_CTX_new_ex(ctx_ecdsa->libctx);
    BN_CTX *ctx = BN_CTX_new_ex(NULL);

    size_t size_r2;
    size_t size_s;
    uint8_t *tmp_sig    = malloc(*sigbuflen);
    // uint8_t size_classical;
    // uint8_t size_new_sig_r2;
    // uint8_t size_new_sig_s;

    /*
     * Line 1, r_2 <- 0, s <- 0 ((r_2, s) : the signature of ECDSA)
     */
    BIGNUM *r2	= BN_new();
    BIGNUM *s	= BN_new();

    /*
     * Line 2, k <- Z^*_q
     */
    BIGNUM *k	= BN_new();
    // BN_rand_range(k, EC_GROUP_get0_order(group));
    BN_rand_range(k, order);

    /*
     * Line 3, r_1 (nonce) <- Rand (r_1 : A part of Falcon signature)
     */
    /* Original comment
     * Create a random nonce (40 bytes).
     */
    randombytes(nonce, NONCELEN);

    /*
     * Line 4, while r_2 = 0 or s = 0 do
     */
	do {
		/*
		 * Line 5, r_2 <- ( f_2(g^k) mod p ) mod q
		 * In ECDSA, r = (kG).x mod n
		 */
        EC_POINT *kp = EC_POINT_new(group);
        EC_POINT_mul(group, kp, k, NULL, NULL, ctx);
        EC_POINT_get_affine_coordinates(group, kp, r2, NULL, ctx);
        // BN_mod(r2, r2, EC_GROUP_get0_order(group), ctx);
        BN_mod(r2, r2, order, ctx);

		/*
		 * Line 6, c <- F( (r_2, r_1) || m )
		 */
		/* Original comment
		 * Hash message nonce + message into a vector.
		 */
		inner_shake256_init(&sc);

		size_r2         = BN_num_bytes(r2);
        uint8_t *bin_r2 = malloc(size_r2);
		BN_bn2bin(r2, bin_r2);
		inner_shake256_inject(&sc, bin_r2, size_r2);

		inner_shake256_inject(&sc, nonce, NONCELEN);
		inner_shake256_inject(&sc, m, mlen);
		inner_shake256_flip(&sc);
		PQCLEAN_FALCON512_BH_AARCH64_hash_to_point_ct(&sc, r.hm, FALCON_LOGN, tmp.b);
		inner_shake256_ctx_release(&sc);

		/*
		 * Line 7, (z_1, z_2) <- f_1(c, sk_1) such that z_1 + z_2h = c mod q
		 */
        /* Original comment
         * Initialize a RNG.
         */
        randombytes(seed, sizeof seed);
        inner_shake256_init(&sc);
        inner_shake256_inject(&sc, seed, sizeof seed);
        inner_shake256_flip(&sc);
        /* Original comment
         * Compute and return the signature.
         */
        PQCLEAN_FALCON512_BH_AARCH64_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, tmp.b);
        v = PQCLEAN_FALCON512_BH_AARCH64_comp_encode(tmp_sig, *sigbuflen, r.sig);

		/*
		 * Line 8, s <- k^-1 (c + (sk_2) r_2) mod q
         * s = k^(-1) * (hash + sk2*r2) mod n
		 */
        BIGNUM *sk2     = NULL;
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &sk2);
        // EC_KEY_get0_private_key(ec_key);
        BN_mod_mul(s, sk2, r2, order, ctx);
        BIGNUM *hash_bn = BN_bin2bn((unsigned char *) (&(r.hm)), FALCON_N, NULL);
        BN_mod_add(s, s, hash_bn, order, ctx);
        BN_mod_inverse(k, k, order, ctx);
        BN_mod_mul(s, s, k, order, ctx);

        BN_free(hash_bn);
        BN_free(sk2);
        free(bin_r2);
        EC_POINT_free(kp);
    } while (BN_is_zero(r2) || BN_is_zero(s));


    // Make a hybrid signature (r_1, z_2, r_2, s)
    size_t size_ecdsa   = 0;
    size_s          = BN_num_bytes(s);
    uint8_t *bin_s  = malloc(size_s);
    uint8_t *bin_r2 = malloc(size_r2);
    BN_bn2bin(s, bin_s);
    BN_bn2bin(r2, bin_r2);
    bool flag_r2 = 0, flag_s = 0;
    if (bin_r2[0] & 0x80) {
        size_r2 += 1;
        flag_r2 = true;
    }
    if (bin_s[0] & 0x80){
        size_s  += 1;
        flag_s  = true;
    }
    size_ecdsa      = size_r2 + size_s + 6;

    // Copy the calculated signature to the hybrid signature pointer

    // ^ ECDSA
    // First 4 bytes (The total length of the ECDSA signature)
    size_t new_sig_idx  = 0;
    for(int i=0; i < 3; i++){
        sigbuf[new_sig_idx++]   = 0x00;
    }
    sigbuf[new_sig_idx++]   = size_ecdsa;

    // 2 bytes (The length of the ECDSA r and s)
    sigbuf[new_sig_idx++]   = 0x30;
    sigbuf[new_sig_idx++]   = (size_ecdsa - 2);

    // ^ r : ECDSA r
    // 2 bytes (The length of the ECDSA r)
    sigbuf[new_sig_idx++]   = 0x02;
    sigbuf[new_sig_idx++]   = size_r2;

    // size(r) + optional 1 bytes (the part of the ECDSA signature r)
    if (flag_r2) {
        sigbuf[new_sig_idx++]   = 0x00;
        memcpy(sigbuf + new_sig_idx, bin_r2, size_r2 - 1);
        new_sig_idx += (size_r2 - 1);
    } else {
        memcpy(sigbuf + new_sig_idx, bin_r2, size_r2);
        new_sig_idx += size_r2;
    }

    //^ s : ECDSA s
    // 2 bytes (The length of the ECDSA s)
    sigbuf[new_sig_idx++]   = 0x02;
    sigbuf[new_sig_idx++]   = size_r2;
    if (flag_s) {
        sigbuf[new_sig_idx++]   = 0x00;
        memcpy(sigbuf + new_sig_idx, bin_s, size_s - 1);
        new_sig_idx += (size_s - 1);
    } else {
        memcpy(sigbuf + new_sig_idx, bin_s, size_s);
        new_sig_idx += size_s;
    }

    // ^ Falcon
    // First 1 byte
    sigbuf[new_sig_idx++] = 0x30 + FALCON_LOGN;

    // Nonce bytes
    memcpy(sigbuf + new_sig_idx, nonce, NONCELEN);
    new_sig_idx += NONCELEN;

    // Falcon signature bytes
    memcpy(sigbuf + new_sig_idx, tmp_sig, v);
    new_sig_idx += v;

    // Memory free
    BN_free(k);
    BN_free(s);
    BN_free(r2);
    BN_CTX_free(ctx);
    free(tmp_sig);
    free(bin_s);
    free(bin_r2);
    // EC_KEY_free(ec_key);
    EC_GROUP_free(group);

    // Falcon finalize routine
    if (v != 0) {
        inner_shake256_ctx_release(&sc);
        *sigbuflen                  = v;
        // ^ ecdsa 도 길이 줘야 되는거 아닌가? -> signature에 들어 있으니 상관 없을듯 -> Anyway, I gave the classical signature length to signature_len_classical
        *signature_len_classical    = size_ecdsa;
        return 0;
    }
    return -1;

    // TODO: Length 관련 챙겨야 함
    // e.g., classical length -> This information in the signature
    // 현재 서명은 대충 만들었고, Certificate form에 맞춘 다음에,
    // Verify까지 구현해야 끝날듯
    // 이거 sig, siglen 파라미터로 넘겨 받는데, 크기가 부족하지는 않나? 일단 해보고.. siglen에 따라 동작하는 걸 수도 있으니까
}

/*
 * Verify a sigature. The nonce has size NONCELEN bytes. sigbuf[]
 * (of size sigbuflen) contains the signature value, not including the
 * header byte or nonce. Return value is 0 on success, -1 on error.
 */
static int
do_verify(
    const uint8_t *sigbuf, const uint8_t *unused, size_t sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *pk, 
    // 
    void *ctx_classical) {
    union {
        uint8_t b[2 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int16_t h[FALCON_N];
    int16_t hm[FALCON_N];
    int16_t sig[FALCON_N];
    inner_shake256_context sc;
    size_t v;

    /*
     * Decode public key.
     */
    if (pk[0] != 0x00 + FALCON_LOGN) {
        return -1;
    }
    if (PQCLEAN_FALCON512_BH_AARCH64_modq_decode( (uint16_t *) h,
            pk + 1, PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_PUBLICKEYBYTES - 1, FALCON_LOGN)
            != PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }
    // We move the conversion to NTT domain of `h` inside verify_raw()
    

    
    // (Mizzou, 2025) revised
    // Algorithm 21 in "A Note on Hybrid Signature Schemes", Bindel and Britta Hale
    
    /*
     * Divide signature to ECDSA and Falcon signatures.
     */
    uint8_t *sig_ecdsa      = sigbuf + 4;
    size_t sig_ecdsa_len    = sigbuf[3];

    uint8_t *sig_falcon             = sig_ecdsa + sig_ecdsa_len;
    uint8_t *sig_falcon_nonce       = sig_falcon + 1;
    uint8_t *sig_falcon_body        = sig_falcon_nonce + NONCELEN;
    size_t sig_falcon_body_len      = sigbuflen - 4 - sig_ecdsa_len - 1 - NONCELEN;
    printf("1Do I get here?\n");
    fflush(stdout);
    
    /*
     * Decode signature.
     */
    if (sig_falcon_body_len == 0) {
        return -1;
    }
    printf("2Do I get here (sig_falcon_body_len: %d)?\n", sig_falcon_body_len);
    printf("  total_len: %d\n  ecdsa_len: %d\n  falcon_body_len: %d\n  nonce_len: %d\n", sigbuflen, sig_ecdsa_len, sig_falcon_body_len, NONCELEN);
    fflush(stdout);

    v = PQCLEAN_FALCON512_BH_AARCH64_comp_decode(sig, sig_falcon_body, sig_falcon_body_len);
    if (v == 0) {
        return -1;
    }
    printf("3Do I get here?\n");
    fflush(stdout);
    if (v != sig_falcon_body_len) {
        if (sig_falcon_body_len == PQCLEAN_FALCONPADDED512_BH_AARCH64_CRYPTO_BYTES - NONCELEN - 1) {
            while (v < sig_falcon_body_len) {
                if (sig_falcon_body[v++] != 0) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
    printf("4Do I get here?\n");
    fflush(stdout);

    // /*
    //  * Hash nonce + message into a vector.
    //  */
    // // (Mizzou, 2025) revised
    // // Kwon et al. hybrid signature scheme (2024)
    // // Restore the nonce
    // uint8_t *r_ecdsa        = nonce - 1;
    // uint8_t size_r_ecdsa    = 32;
    
    // if (*(r_ecdsa - size_r_ecdsa) & 0x80)
    //     r_ecdsa = r_ecdsa - (2 * size_r_ecdsa) - 2;
    // else
    //     r_ecdsa = r_ecdsa - (2 * size_r_ecdsa) - 1;

    // uint8_t *new_nonce = malloc(NONCELEN);
    // memcpy(new_nonce, r_ecdsa, size_r_ecdsa);
    // memcpy(new_nonce + size_r_ecdsa, nonce, NONCELEN - size_r_ecdsa);

    // inner_shake256_init(&sc);
    // inner_shake256_inject(&sc, new_nonce, NONCELEN);
    // // inner_shake256_inject(&sc, nonce, NONCELEN);
    // inner_shake256_inject(&sc, m, mlen);
    // inner_shake256_flip(&sc);
    // PQCLEAN_FALCON512_BH_AARCH64_hash_to_point_ct(&sc, (uint16_t *) hm, FALCON_LOGN, tmp.b);
    // inner_shake256_ctx_release(&sc);

    // // (Mizzou, 2025) revised
    // free(new_nonce);

    // /*
    //  * Verify signature.
    //  */
    // if (!PQCLEAN_FALCON512_BH_AARCH64_verify_raw(hm, sig, h, (int16_t *) tmp.b)) {
    //     return -1;
    // }
    // return 0;
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, 
    //
    void *ctx_classical, size_t *signature_len_classical) {
    size_t vlen;
    
    vlen = PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_BYTES - NONCELEN - 1;
    if (do_sign(sig, NULL, &vlen, m, mlen, sk, 
        //
        ctx_classical, signature_len_classical) < 0) {
        return -1;
    }
    // sig[0] = 0x30 + FALCON_LOGN;
    
    // (Mizzou, 2025) revised
    *siglen = 1 + NONCELEN + vlen;
    // Original code copied from liboqs
    // *siglen = 1 + NONCELEN + vlen;
    return 0;
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk, 
    // 
    void *ctx_classical) {
    printf("(function) PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_verify.\n");
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    // if (sig[0] != 0x30 + FALCON_LOGN) {
    //     return -1;
    // }
    return do_verify(sig,
                     NULL, siglen, m, mlen, pk, 
                    // 
                    ctx_classical);
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, 
    //
    void *ctx_classical, size_t *signature_len_classical) {
    uint8_t *pm, *sigbuf;
    size_t sigbuflen;

    /*
     * Move the message to its final location; this is a memmove() so
     * it handles overlaps properly.
     */
    memmove(sm + 2 + NONCELEN, m, mlen);
    pm = sm + 2 + NONCELEN;
    sigbuf = pm + 1 + mlen;
    sigbuflen = PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_BYTES - NONCELEN - 3;
    if (do_sign(sm + 2, sigbuf, &sigbuflen, pm, mlen, sk,
        //
        ctx_classical, signature_len_classical) < 0) {
        return -1;
    }
    pm[mlen] = 0x20 + FALCON_LOGN;
    sigbuflen ++;
    sm[0] = (uint8_t)(sigbuflen >> 8);
    sm[1] = (uint8_t)sigbuflen;
    *smlen = mlen + 2 + NONCELEN + sigbuflen;
    return 0;
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk, 
    // 
    void *ctx_classical) {
    printf("(function) PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_open.\n");
    const uint8_t *sigbuf;
    size_t pmlen, sigbuflen;

    if (smlen < 3 + NONCELEN) {
        return -1;
    }
    sigbuflen = ((size_t)sm[0] << 8) | (size_t)sm[1];
    if (sigbuflen < 2 || sigbuflen > (smlen - NONCELEN - 2)) {
        return -1;
    }
    sigbuflen --;
    pmlen = smlen - NONCELEN - 3 - sigbuflen;
    if (sm[2 + NONCELEN + pmlen] != 0x20 + FALCON_LOGN) {
        return -1;
    }
    sigbuf = sm + 2 + NONCELEN + pmlen + 1;

    /*
     * The 2-byte length header and the one-byte signature header
     * have been verified. Nonce is at sm+2, followed by the message
     * itself. Message length is in pmlen. sigbuf/sigbuflen point to
     * the signature value (excluding the header byte).
     */
    if (do_verify(sm + 2, sigbuf, sigbuflen,
                  sm + 2 + NONCELEN, pmlen, pk, 
                // 
                ctx_classical) < 0) {
        return -1;
    }

    /*
     * Signature is correct, we just have to copy/move the message
     * to its final destination. The memmove() properly handles
     * overlaps.
     */
    memmove(m, sm + 2 + NONCELEN, pmlen);
    *mlen = pmlen;
    return 0;
}
