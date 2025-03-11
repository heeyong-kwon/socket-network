#!/bin/bash

bash add_new.sh

openssl req -x509 -new -newkey p256_falcon512_kbl -keyout p256_falcon512_kbl_CA.key -out p256_falcon512_kbl_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
openssl genpkey -algorithm p256_falcon512_kbl -out p256_falcon512_kbl_srv.key
openssl req -new -newkey p256_falcon512_kbl -keyout p256_falcon512_kbl_srv.key -out p256_falcon512_kbl_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
openssl x509 -req -in p256_falcon512_kbl_srv.csr -out p256_falcon512_kbl_srv.crt -CA p256_falcon512_kbl_CA.crt -CAkey p256_falcon512_kbl_CA.key -CAcreateserial -days 365

# rm p256_falcon512_kbl_*

