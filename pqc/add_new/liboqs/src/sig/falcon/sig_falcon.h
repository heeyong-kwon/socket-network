// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_FALCON_H
#define OQS_SIG_FALCON_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_falcon_512)
#define OQS_SIG_falcon_512_length_public_key 897
#define OQS_SIG_falcon_512_length_secret_key 1281
#define OQS_SIG_falcon_512_length_signature 752

OQS_SIG *OQS_SIG_falcon_512_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_512_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_1024)
#define OQS_SIG_falcon_1024_length_public_key 1793
#define OQS_SIG_falcon_1024_length_secret_key 2305
#define OQS_SIG_falcon_1024_length_signature 1462

OQS_SIG *OQS_SIG_falcon_1024_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_512)
#define OQS_SIG_falcon_padded_512_length_public_key 897
#define OQS_SIG_falcon_padded_512_length_secret_key 1281
#define OQS_SIG_falcon_padded_512_length_signature 666

OQS_SIG *OQS_SIG_falcon_padded_512_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_1024)
#define OQS_SIG_falcon_padded_1024_length_public_key 1793
#define OQS_SIG_falcon_padded_1024_length_secret_key 2305
#define OQS_SIG_falcon_padded_1024_length_signature 1280

OQS_SIG *OQS_SIG_falcon_padded_1024_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif



#if defined(OQS_ENABLE_SIG_falcon_512_kbl)
#define OQS_SIG_falcon_512_kbl_length_public_key 897
#define OQS_SIG_falcon_512_kbl_length_secret_key 1281
#define OQS_SIG_falcon_512_kbl_length_signature 752

OQS_SIG *OQS_SIG_falcon_512_kbl_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_512_kbl_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_kbl_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_kbl_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_kbl_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_kbl_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_1024_kbl)
#define OQS_SIG_falcon_1024_kbl_length_public_key 1793
#define OQS_SIG_falcon_1024_kbl_length_secret_key 2305
#define OQS_SIG_falcon_1024_kbl_length_signature 1462

OQS_SIG *OQS_SIG_falcon_1024_kbl_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_kbl_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_kbl_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_kbl_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_kbl_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_kbl_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_512_kbl)
#define OQS_SIG_falcon_padded_512_kbl_length_public_key 897
#define OQS_SIG_falcon_padded_512_kbl_length_secret_key 1281
#define OQS_SIG_falcon_padded_512_kbl_length_signature 666

OQS_SIG *OQS_SIG_falcon_padded_512_kbl_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_kbl_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_kbl_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_kbl_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_kbl_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_kbl_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_1024_kbl)
#define OQS_SIG_falcon_padded_1024_kbl_length_public_key 1793
#define OQS_SIG_falcon_padded_1024_kbl_length_secret_key 2305
#define OQS_SIG_falcon_padded_1024_kbl_length_signature 1280

OQS_SIG *OQS_SIG_falcon_padded_1024_kbl_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_kbl_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_kbl_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_kbl_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_kbl_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_kbl_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif



#if defined(OQS_ENABLE_SIG_falcon_512_bh)
#define OQS_SIG_falcon_512_bh_length_public_key 897
#define OQS_SIG_falcon_512_bh_length_secret_key 1281
#define OQS_SIG_falcon_512_bh_length_signature 752

OQS_SIG *OQS_SIG_falcon_512_bh_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_512_bh_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_512_bh_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_512_bh_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key, void *ctx_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_512_bh_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_512_bh_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key, void *ctx_classical);
#endif

#if defined(OQS_ENABLE_SIG_falcon_1024_bh)
#define OQS_SIG_falcon_1024_bh_length_public_key 1793
#define OQS_SIG_falcon_1024_bh_length_secret_key 2305
#define OQS_SIG_falcon_1024_bh_length_signature 1462

OQS_SIG *OQS_SIG_falcon_1024_bh_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_bh_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_bh_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_bh_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key, void *ctx_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_bh_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_1024_bh_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key, void *ctx_classical);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_512_bh)
#define OQS_SIG_falcon_padded_512_bh_length_public_key 897
#define OQS_SIG_falcon_padded_512_bh_length_secret_key 1281
#define OQS_SIG_falcon_padded_512_bh_length_signature 666

OQS_SIG *OQS_SIG_falcon_padded_512_bh_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_bh_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_bh_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_bh_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key, void *ctx_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_bh_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_512_bh_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key, void *ctx_classical);
#endif

#if defined(OQS_ENABLE_SIG_falcon_padded_1024_bh)
#define OQS_SIG_falcon_padded_1024_bh_length_public_key 1793
#define OQS_SIG_falcon_padded_1024_bh_length_secret_key 2305
#define OQS_SIG_falcon_padded_1024_bh_length_signature 1280

OQS_SIG *OQS_SIG_falcon_padded_1024_bh_new(void);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_bh_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_bh_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_bh_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key, void *ctx_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_bh_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key, void *ctx_classical, size_t *signature_len_classical);
OQS_API OQS_STATUS OQS_SIG_falcon_padded_1024_bh_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key, void *ctx_classical);
#endif



#endif
