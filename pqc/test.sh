#!/bin/bash

#!/bin/bash

# bash add_new.sh

generate_certificates() {
  local ALG=$1
  openssl req -x509 -new -newkey ${ALG} -keyout ${ALG}_CA.key -out ${ALG}_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
  openssl genpkey -algorithm ${ALG} -out ${ALG}_srv.key
  openssl req -new -newkey ${ALG} -keyout ${ALG}_srv.key -out ${ALG}_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
  openssl x509 -req -in ${ALG}_srv.csr -out ${ALG}_srv.crt -CA ${ALG}_CA.crt -CAkey ${ALG}_CA.key -CAcreateserial -days 365
  # rm ${ALG}_*
}

# Hybrid algorithms with KBL
generate_certificates "p256_falcon512_kbl"
generate_certificates "p521_falcon1024_kbl"
generate_certificates "p256_falconpadded512_kbl"
generate_certificates "p521_falconpadded1024_kbl"

# Original hybrid algorithms provided by liboqs
generate_certificates "p256_falcon512"
generate_certificates "p521_falcon1024"
generate_certificates "p256_falconpadded512"
generate_certificates "p521_falconpadded1024"
