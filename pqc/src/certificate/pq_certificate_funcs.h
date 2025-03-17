#ifndef PQ_CERTIFICATE_FUNCS_H
#define PQ_CERTIFICATE_FUNCS_H

#include "pq_certificate_params.h"

ASN1_INTEGER *generate_serial_number();
EVP_PKEY *generate_ecdsa_key();
EVP_PKEY *generate_falcon_key();
EVP_PKEY *generate_hybrid_key();
X509 *generate_hybrid_x509_certificate(EVP_PKEY *);
void save_hybrid_key_and_cert(EVP_PKEY *, X509 *);

#endif