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
do_sign(uint8_t *nonce, uint8_t *sigbuf, size_t *sigbuflen,
        const uint8_t *m, size_t mlen, const uint8_t *sk, 
        //
        void *ctx_classical, size_t *signature_len_classical, const unsigned char *tbs_classical, size_t tbslen_classical) {
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
     * Prepare for ECDSA
     */
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey((EVP_PKEY_CTX *) ctx_classical);
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec_key) return 0;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    BN_CTX *ctx = BN_CTX_new();

    /*
     * Line 1, r_2 <- 0, s <- 0 ((r_2, s) : the signature of ECDSA)
     */
    BIGNUM *r2	= BN_new();
    BIGNUM *s	= BN_new();

    /*
     * Line 2, k <- Z^*_q
     */
    BIGNUM *k	= BN_new();
    BN_rand_range(k, EC_GROUP_get0_order(group));

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
        BN_mod(r2, r2, EC_GROUP_get0_order(group), ctx);

		/*
		 * Line 6, c <- F( (r_2, r_1) || m )
		 */
		/* Original comment
		 * Hash message nonce + message into a vector.
		 */
		inner_shake256_init(&sc);

		int r2_size = BN_num_bytes(r2);
		uint8_t *ec_buf = malloc(r2_size);
		BN_bn2bin(r2, ec_buf);
		inner_shake256_inject(&sc, ec_buf, r2_size);

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
        v = PQCLEAN_FALCON512_AARCH64_comp_encode(sigbuf, *sigbuflen, r.sig);
        if (v != 0) {
            inner_shake256_ctx_release(&sc);
            *sigbuflen = v;
            return 0;
        }

		/*
		 * Line 8, s <- k^-1 (c + (sk_2) r_2) mod q
		 */



        // s = k^(-1) * (hash + d*r) mod n
        BIGNUM *ec_d    = (BIGNUM *)EC_KEY_get0_private_key(ec_key);
        BIGNUM *hash_bn = BN_bin2bn(tbs_classical, tbslen_classical, NULL);
        BN_mod_mul(s, ec_d, r2, EC_GROUP_get0_order(group), ctx);
        BN_mod_add(s, s, hash_bn, EC_GROUP_get0_order(group), ctx);
        BN_mod_inverse(k, k, EC_GROUP_get0_order(group), ctx);
        BN_mod_mul(s, s, k, EC_GROUP_get0_order(group), ctx);

        BN_free(hash_bn);




        // TODO: Length 관련 챙겨야 함






         
		free(ec_buf);
        EC_POINT_free(kp);
	} while (BN_is_zero(r2) || BN_is_zero(s));







    do {
    } while ();

    // 4. ECDSA_SIG 객체 생성 및 값 설정
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r2, s);

    // 5. 메모리 정리 (heeyong: 이거 메모리 정리가 덜 된 거 같은데 파악해서 다 free 해 줘)
    BN_free(k);
    BN_CTX_free(ctx);

    printf("\n\nHEREHERE\n\n");

    
    return sig;






    



    

    

    
    return -1;
}

/*
 * Verify a sigature. The nonce has size NONCELEN bytes. sigbuf[]
 * (of size sigbuflen) contains the signature value, not including the
 * header byte or nonce. Return value is 0 on success, -1 on error.
 */
static int
do_verify(
    const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
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
    
    // (Mizzou, 2025) revised (32: the size of r in ECDSA)
    // new sigbuf and sigbuflen
    sigbuf      -= 32;
    sigbuflen   += 32;

    /*
     * Decode signature.
     */
    if (sigbuflen == 0) {
        return -1;
    }

    v = PQCLEAN_FALCON512_BH_AARCH64_comp_decode(sig, sigbuf, sigbuflen);
    if (v == 0) {
        return -1;
    }
    if (v != sigbuflen) {
        if (sigbuflen == PQCLEAN_FALCONPADDED512_BH_AARCH64_CRYPTO_BYTES - NONCELEN - 1) {
            while (v < sigbuflen) {
                if (sigbuf[v++] != 0) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }

    /*
     * Hash nonce + message into a vector.
     */
    // (Mizzou, 2025) revised
    // Kwon et al. hybrid signature scheme (2024)
    // Restore the nonce
    uint8_t *r_ecdsa        = nonce - 1;
    uint8_t size_r_ecdsa    = 32;
    
    if (*(r_ecdsa - size_r_ecdsa) & 0x80)
        r_ecdsa = r_ecdsa - (2 * size_r_ecdsa) - 2;
    else
        r_ecdsa = r_ecdsa - (2 * size_r_ecdsa) - 1;

    uint8_t *new_nonce = malloc(NONCELEN);
    memcpy(new_nonce, r_ecdsa, size_r_ecdsa);
    memcpy(new_nonce + size_r_ecdsa, nonce, NONCELEN - size_r_ecdsa);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, new_nonce, NONCELEN);
    // inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_BH_AARCH64_hash_to_point_ct(&sc, (uint16_t *) hm, FALCON_LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);

    // (Mizzou, 2025) revised
    free(new_nonce);

    /*
     * Verify signature.
     */
    if (!PQCLEAN_FALCON512_BH_AARCH64_verify_raw(hm, sig, h, (int16_t *) tmp.b)) {
        return -1;
    }
    return 0;
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, 
    //
    void *ctx_classical, size_t *signature_len_classical, const unsigned char *tbs_classical, size_t tbslen_classical) {
    size_t vlen;
    
    vlen = PQCLEAN_FALCON512_BH_AARCH64_CRYPTO_BYTES - NONCELEN - 1;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, &vlen, m, mlen, sk, 
        //
        ctx_classical, signature_len_classical, tbs_classical, tbslen_classical) < 0) {
        return -1;
    }
    sig[0] = 0x30 + FALCON_LOGN;
    
    // (Mizzou, 2025) revised (32: the size of r in ECDSA)
    *siglen = 1 + NONCELEN - 32 + vlen;
    // Original code copied from liboqs
    // *siglen = 1 + NONCELEN + vlen;
    return 0;
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + FALCON_LOGN) {
        return -1;
    }
    return do_verify(sig + 1,
                     sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}

/* see api.h */
int
PQCLEAN_FALCON512_BH_AARCH64_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, 
    //
    void *ctx_classical, size_t *signature_len_classical, const unsigned char *tbs_classical, size_t tbslen_classical) {
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
        ctx_classical, signature_len_classical, tbs_classical, tbslen_classical) < 0) {
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
    const uint8_t *sm, size_t smlen, const uint8_t *pk) {
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
                  sm + 2 + NONCELEN, pmlen, pk) < 0) {
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
