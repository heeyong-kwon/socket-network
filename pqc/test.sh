#!/bin/bash

bash add_new.sh

openssl req -x509 -new -newkey p256_falcon512k -keyout p256_falcon512k_CA.key -out p256_falcon512k_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
openssl genpkey -algorithm p256_falcon512k -out p256_falcon512k_srv.key
openssl req -new -newkey p256_falcon512k -keyout p256_falcon512k_srv.key -out p256_falcon512k_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
openssl x509 -req -in p256_falcon512k_srv.csr -out p256_falcon512k_srv.crt -CA p256_falcon512k_CA.crt -CAkey p256_falcon512k_CA.key -CAcreateserial -days 365

# rm p256_falcon512k_*

